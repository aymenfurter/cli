//go:build windows

package proxy

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	winhttp                                   = windows.NewLazySystemDLL("winhttp.dll")
	procWinHttpOpen                           = winhttp.NewProc("WinHttpOpen")
	procWinHttpCloseHandle                    = winhttp.NewProc("WinHttpCloseHandle")
	procWinHttpGetProxyForUrl                 = winhttp.NewProc("WinHttpGetProxyForUrl")
	procWinHttpGetIEProxyConfigForCurrentUser = winhttp.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	procWinHttpGetDefaultProxyConfiguration   = winhttp.NewProc("WinHttpGetDefaultProxyConfiguration")
	procGlobalFree                            = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")
)

const (
	winhttpAccessTypeNoProxy    = 1
	winhttpAccessTypeNamedProxy = 3
	winhttpAutoproxyAutoDetect  = 0x1
	winhttpAutoproxyConfigURL   = 0x2
	winhttpAutoDetectTypeDHCP   = 0x1
	winhttpAutoDetectTypeDNSA   = 0x2
	// winhttpAutoproxyRunInprocess runs the PAC download and script in this
	// process instead of in the WinHTTP AutoProxy service.
	winhttpAutoproxyRunInprocess = 0x00010000

	errWinhttpLoginFailure = windows.Errno(12015)

	wpadURL = "http://wpad/wpad.dat"
)

type winhttpCurrentUserIEProxyConfig struct {
	autoDetect    int32
	autoConfigURL *uint16
	proxy         *uint16
	proxyBypass   *uint16
}

type winhttpAutoproxyOptions struct {
	flags                 uint32
	autoDetectFlags       uint32
	autoConfigURL         *uint16
	reserved1             uintptr
	reserved2             uint32
	autoLogonIfChallenged int32
}

type winhttpProxyInfo struct {
	accessType  uint32
	proxy       *uint16
	proxyBypass *uint16
}

func takeString(p *uint16) string {
	if p == nil {
		return ""
	}
	s := windows.UTF16PtrToString(p)
	_, _, _ = procGlobalFree.Call(uintptr(unsafe.Pointer(p)))
	return s
}

func systemProxies(u *url.URL) ([]string, error) {
	var ie winhttpCurrentUserIEProxyConfig
	r, _, _ := procWinHttpGetIEProxyConfigForCurrentUser.Call(uintptr(unsafe.Pointer(&ie)))
	if r != 0 {
		autoDetect := ie.autoDetect != 0
		pacURL := takeString(ie.autoConfigURL)
		manual := takeString(ie.proxy)
		bypass := takeString(ie.proxyBypass)

		if autoDetect || pacURL != "" {
			if res, ok := autoProxy(u, autoDetect, pacURL); ok {
				return res, nil
			}
		}
		if manual != "" {
			if bypassed(u.Hostname(), bypass) {
				return []string{"DIRECT"}, nil
			}
			return proxyListEntries(manual, u.Scheme), nil
		}
	}

	// The machine-wide WinHTTP setting (netsh winhttp set proxy).
	var info winhttpProxyInfo
	r, _, _ = procWinHttpGetDefaultProxyConfiguration.Call(uintptr(unsafe.Pointer(&info)))
	if r != 0 {
		p := takeString(info.proxy)
		b := takeString(info.proxyBypass)
		if info.accessType == winhttpAccessTypeNamedProxy && p != "" {
			if bypassed(u.Hostname(), b) {
				return []string{"DIRECT"}, nil
			}
			return proxyListEntries(p, u.Scheme), nil
		}
	}
	return nil, nil
}

func autoProxy(u *url.URL, autoDetect bool, pacURL string) ([]string, bool) {
	agent, _ := windows.UTF16PtrFromString("GitHub CLI")
	session, _, _ := procWinHttpOpen.Call(uintptr(unsafe.Pointer(agent)), winhttpAccessTypeNoProxy, 0, 0, 0)
	if session == 0 {
		return nil, false
	}
	defer procWinHttpCloseHandle.Call(session)

	target, err := windows.UTF16PtrFromString(u.String())
	if err != nil {
		return nil, false
	}
	var opts []winhttpAutoproxyOptions
	if autoDetect {
		opts = append(opts, winhttpAutoproxyOptions{
			flags:           winhttpAutoproxyAutoDetect,
			autoDetectFlags: winhttpAutoDetectTypeDHCP | winhttpAutoDetectTypeDNSA,
		})
	}
	if pacURL != "" {
		p, err := windows.UTF16PtrFromString(pacURL)
		if err == nil {
			opts = append(opts, winhttpAutoproxyOptions{flags: winhttpAutoproxyConfigURL, autoConfigURL: p})
		}
	}
	if autoDetect {
		// WinHTTP DNS discovery uses only the primary DNS suffix of the
		// computer, so it does not work on most computers that are not in a
		// domain. Browsers also try the unqualified "wpad" host, which the
		// DNS suffix search list completes. This runs in the process because
		// the AutoProxy service can keep an earlier failure.
		p, _ := windows.UTF16PtrFromString(wpadURL)
		opts = append(opts, winhttpAutoproxyOptions{flags: winhttpAutoproxyConfigURL | winhttpAutoproxyRunInprocess, autoConfigURL: p})
	}
	for _, o := range opts {
		info, err := proxyForURL(session, target, o)
		if err != nil {
			continue
		}
		p := takeString(info.proxy)
		_ = takeString(info.proxyBypass)
		if info.accessType != winhttpAccessTypeNamedProxy || p == "" {
			return []string{"DIRECT"}, true
		}
		return proxyListEntries(p, u.Scheme), true
	}
	return nil, false
}

// proxyForURL calls WinHttpGetProxyForUrl. It tries again with the
// credentials of the current user only if the PAC server asks for them.
func proxyForURL(session uintptr, target *uint16, o winhttpAutoproxyOptions) (winhttpProxyInfo, error) {
	var info winhttpProxyInfo
	for _, logon := range []int32{0, 1} {
		o.autoLogonIfChallenged = logon
		r, _, err := procWinHttpGetProxyForUrl.Call(session, uintptr(unsafe.Pointer(target)), uintptr(unsafe.Pointer(&o)), uintptr(unsafe.Pointer(&info)))
		if r != 0 {
			return info, nil
		}
		if !errors.Is(err, errWinhttpLoginFailure) {
			return info, err
		}
	}
	return info, errWinhttpLoginFailure
}

// proxyListEntries converts a WinHTTP proxy string, for example
// "proxy:8080" or "http=a:80;https=b:443", to PAC result entries.
func proxyListEntries(list, scheme string) []string {
	var generic, matching, socks []string
	for _, item := range strings.FieldsFunc(list, func(r rune) bool { return r == ';' || r == ' ' || r == '\t' }) {
		kind := ""
		if i := strings.Index(item, "="); i >= 0 {
			kind, item = strings.ToLower(item[:i]), item[i+1:]
		}
		kind2 := "PROXY"
		if p, err := url.Parse(item); err == nil && p.Host != "" {
			if strings.HasPrefix(p.Scheme, "socks") {
				kind2 = "SOCKS"
			}
			item = p.Host
		}
		if _, _, err := net.SplitHostPort(item); err != nil {
			item = net.JoinHostPort(strings.Trim(item, "[]"), "80")
		}
		switch kind {
		case "":
			generic = append(generic, kind2+" "+item)
		case scheme:
			matching = append(matching, kind2+" "+item)
		case "socks":
			socks = append(socks, "SOCKS "+item)
		}
	}
	if len(matching) > 0 {
		return matching
	}
	if len(generic) > 0 {
		return generic
	}
	return socks
}

// bypassed reports if host matches the WinHTTP bypass list.
func bypassed(host, list string) bool {
	host = strings.ToLower(host)
	for _, item := range strings.FieldsFunc(list, func(r rune) bool { return r == ';' || r == ' ' || r == '\t' }) {
		item = strings.ToLower(item)
		if item == "<local>" {
			if !strings.Contains(host, ".") {
				return true
			}
			continue
		}
		pattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(item), `\*`, ".*") + "$"
		if ok, _ := regexp.MatchString(pattern, host); ok {
			return true
		}
	}
	return false
}
