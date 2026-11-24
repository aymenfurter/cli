//go:build darwin && cgo

package proxy

/*
#cgo LDFLAGS: -framework CoreFoundation -framework CFNetwork
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>

typedef struct {
	CFArrayRef result;
	int done;
} gh_pac_ctx;

static void gh_pac_callback(void *client, CFArrayRef proxies, CFErrorRef error) {
	gh_pac_ctx *ctx = (gh_pac_ctx *)client;
	if (error == NULL && proxies != NULL) {
		ctx->result = (CFArrayRef)CFRetain(proxies);
	}
	ctx->done = 1;
	CFRunLoopStop(CFRunLoopGetCurrent());
}

// gh_run_pac runs a PAC file (pacURL) or a PAC script (script) for target.
// It uses a private run loop mode so that it does not run other sources.
static CFArrayRef gh_run_pac(CFURLRef pacURL, CFStringRef script, CFURLRef target, double timeout) {
	gh_pac_ctx ctx = { NULL, 0 };
	CFStreamClientContext sctx = { 0, &ctx, NULL, NULL, NULL };
	CFRunLoopSourceRef src;
	if (pacURL != NULL) {
		src = CFNetworkExecuteProxyAutoConfigurationURL(pacURL, target, gh_pac_callback, &sctx);
	} else {
		src = CFNetworkExecuteProxyAutoConfigurationScript(script, target, gh_pac_callback, &sctx);
	}
	if (src == NULL) {
		return NULL;
	}
	CFStringRef mode = CFSTR("com.github.cli.proxy");
	CFRunLoopAddSource(CFRunLoopGetCurrent(), src, mode);
	CFAbsoluteTime end = CFAbsoluteTimeGetCurrent() + timeout;
	while (!ctx.done) {
		double left = end - CFAbsoluteTimeGetCurrent();
		if (left <= 0) {
			break;
		}
		CFRunLoopRunInMode(mode, left, false);
	}
	CFRunLoopRemoveSource(CFRunLoopGetCurrent(), src, mode);
	CFRunLoopSourceInvalidate(src);
	CFRelease(src);
	return ctx.result;
}

static void gh_append_proxies(CFMutableStringRef out, CFArrayRef proxies, CFURLRef target, double timeout, int depth);

static void gh_append_pac(CFMutableStringRef out, CFURLRef pacURL, CFStringRef script, CFURLRef target, double timeout, int depth) {
	if (depth > 1) {
		return;
	}
	CFArrayRef result = gh_run_pac(pacURL, script, target, timeout);
	if (result != NULL) {
		gh_append_proxies(out, result, target, timeout, depth + 1);
		CFRelease(result);
	}
}

static void gh_append_proxies(CFMutableStringRef out, CFArrayRef proxies, CFURLRef target, double timeout, int depth) {
	CFIndex n = CFArrayGetCount(proxies);
	for (CFIndex i = 0; i < n; i++) {
		CFDictionaryRef p = (CFDictionaryRef)CFArrayGetValueAtIndex(proxies, i);
		if (p == NULL || CFGetTypeID(p) != CFDictionaryGetTypeID()) {
			continue;
		}
		CFStringRef type = (CFStringRef)CFDictionaryGetValue(p, kCFProxyTypeKey);
		if (type == NULL) {
			continue;
		}
		if (CFEqual(type, kCFProxyTypeNone)) {
			CFStringAppend(out, CFSTR("DIRECT\n"));
		} else if (CFEqual(type, kCFProxyTypeAutoConfigurationURL)) {
			CFURLRef pac = (CFURLRef)CFDictionaryGetValue(p, kCFProxyAutoConfigurationURLKey);
			if (pac != NULL && CFGetTypeID(pac) == CFURLGetTypeID()) {
				gh_append_pac(out, pac, NULL, target, timeout, depth);
			}
		} else if (CFEqual(type, kCFProxyTypeAutoConfigurationJavaScript)) {
			CFStringRef js = (CFStringRef)CFDictionaryGetValue(p, kCFProxyAutoConfigurationJavaScriptKey);
			if (js != NULL && CFGetTypeID(js) == CFStringGetTypeID()) {
				gh_append_pac(out, NULL, js, target, timeout, depth);
			}
		} else {
			const char *kind = NULL;
			int port = 0;
			if (CFEqual(type, kCFProxyTypeHTTP) || CFEqual(type, kCFProxyTypeHTTPS)) {
				kind = "PROXY";
				port = 80;
			} else if (CFEqual(type, kCFProxyTypeSOCKS)) {
				kind = "SOCKS";
				port = 1080;
			}
			CFStringRef host = (CFStringRef)CFDictionaryGetValue(p, kCFProxyHostNameKey);
			if (kind == NULL || host == NULL || CFGetTypeID(host) != CFStringGetTypeID()) {
				continue;
			}
			CFNumberRef num = (CFNumberRef)CFDictionaryGetValue(p, kCFProxyPortNumberKey);
			if (num != NULL && CFGetTypeID(num) == CFNumberGetTypeID()) {
				CFNumberGetValue(num, kCFNumberIntType, &port);
			}
			if (CFStringFind(host, CFSTR(":"), 0).location != kCFNotFound) {
				CFStringAppendFormat(out, NULL, CFSTR("%s [%@]:%d\n"), kind, host, port);
			} else {
				CFStringAppendFormat(out, NULL, CFSTR("%s %@:%d\n"), kind, host, port);
			}
		}
	}
}

static int gh_dict_flag(CFDictionaryRef d, CFStringRef key) {
	CFNumberRef v = (CFNumberRef)CFDictionaryGetValue(d, key);
	int flag = 0;
	if (v != NULL && CFGetTypeID(v) == CFNumberGetTypeID()) {
		CFNumberGetValue(v, kCFNumberIntType, &flag);
	}
	return flag;
}

// gh_system_proxies returns the proxy list for url as lines in the PAC result
// format. The caller frees the result. It returns NULL if the system has no
// proxy settings.
static char *gh_system_proxies(const char *url, double timeout) {
	CFDictionaryRef settings = CFNetworkCopySystemProxySettings();
	if (settings == NULL) {
		return NULL;
	}
	CFURLRef target = CFURLCreateWithBytes(NULL, (const UInt8 *)url, strlen(url), kCFStringEncodingUTF8, NULL);
	if (target == NULL) {
		CFRelease(settings);
		return NULL;
	}
	CFMutableStringRef out = CFStringCreateMutable(NULL, 0);

	// CFNetworkCopyProxiesForURL does not do Web Proxy Auto-Discovery, so
	// use the well-known WPAD URL when auto discovery is on.
	if (gh_dict_flag(settings, CFSTR("ProxyAutoDiscoveryEnable"))) {
		CFURLRef wpad = CFURLCreateWithString(NULL, CFSTR("http://wpad/wpad.dat"), NULL);
		if (wpad != NULL) {
			gh_append_pac(out, wpad, NULL, target, timeout, 0);
			CFRelease(wpad);
		}
	}
	if (CFStringGetLength(out) == 0) {
		CFArrayRef proxies = CFNetworkCopyProxiesForURL(target, settings);
		if (proxies != NULL) {
			gh_append_proxies(out, proxies, target, timeout, 0);
			CFRelease(proxies);
		}
	}

	CFIndex size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(out), kCFStringEncodingUTF8) + 1;
	char *buf = malloc(size);
	if (buf != NULL && !CFStringGetCString(out, buf, size, kCFStringEncodingUTF8)) {
		free(buf);
		buf = NULL;
	}
	CFRelease(out);
	CFRelease(target);
	CFRelease(settings);
	return buf;
}
*/
import "C"

import (
	"net/url"
	"strings"
	"unsafe"
)

const pacTimeoutSeconds = 10

func systemProxies(u *url.URL) ([]string, error) {
	cu := C.CString(u.String())
	defer C.free(unsafe.Pointer(cu))
	res := C.gh_system_proxies(cu, C.double(pacTimeoutSeconds))
	if res == nil {
		return nil, nil
	}
	defer C.free(unsafe.Pointer(res))
	return strings.Split(strings.TrimSpace(C.GoString(res)), "\n"), nil
}
