//go:build windows

package proxy

import (
	"net/url"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestProxyListEntries(t *testing.T) {
	tests := []struct {
		list   string
		scheme string
		want   []string
	}{
		{"proxy:8080", "https", []string{"PROXY proxy:8080"}},
		{"proxy", "https", []string{"PROXY proxy:80"}},
		{"http://proxy:8080", "https", []string{"PROXY proxy:8080"}},
		{"http=a:80;https=b:443", "https", []string{"PROXY b:443"}},
		{"http=a:80;https=b:443", "http", []string{"PROXY a:80"}},
		{"http=a:80", "https", nil},
		{"a:1 b:2", "https", []string{"PROXY a:1", "PROXY b:2"}},
		{"socks=s:1080", "https", []string{"SOCKS s:1080"}},
		{"socks5://s:1080", "https", []string{"SOCKS s:1080"}},
		{"[::1]:3128", "https", []string{"PROXY [::1]:3128"}},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, proxyListEntries(tt.list, tt.scheme), tt.list)
	}
}

func TestBypassed(t *testing.T) {
	list := "<local>;*.corp.example;10.*"
	assert.True(t, bypassed("intranet", list))
	assert.True(t, bypassed("git.corp.example", list))
	assert.True(t, bypassed("GIT.CORP.EXAMPLE", list))
	assert.True(t, bypassed("10.1.2.3", list))
	assert.False(t, bypassed("api.github.com", list))
	assert.False(t, bypassed("corp.example.com", list))
	assert.False(t, bypassed("api.github.com", ""))
}

// TestSystemProxies calls WinHTTP with the settings of the machine. The
// result depends on the machine, so the test checks only that the entries
// can be parsed.
func TestSystemProxies(t *testing.T) {
	entries, err := systemProxies(&url.URL{Scheme: "https", Host: "api.github.com"})
	assert.NoError(t, err)
	t.Logf("system proxy entries: %q", entries)
	for _, p := range ParseEntries(entries) {
		if p != nil {
			assert.NotEmpty(t, p.Host)
		}
	}
}

// TestSystemProxiesWPAD needs a machine with "Automatically detect
// settings" on and a wpad.dat server for the "wpad" host. The fork CI sets
// this up, and first asks the AutoProxy service while "wpad" does not
// resolve, so that the service keeps a failed discovery.
// GH_TEST_WPAD_PROXY is the proxy that the wpad.dat file returns.
func TestSystemProxiesWPAD(t *testing.T) {
	want := os.Getenv("GH_TEST_WPAD_PROXY")
	if want == "" {
		t.Skip("GH_TEST_WPAD_PROXY is not set")
	}
	u := &url.URL{Scheme: "https", Host: "api.github.com"}

	agent, _ := windows.UTF16PtrFromString("GitHub CLI test")
	session, _, _ := procWinHttpOpen.Call(uintptr(unsafe.Pointer(agent)), winhttpAccessTypeNoProxy, 0, 0, 0)
	require.NotZero(t, session)
	defer procWinHttpCloseHandle.Call(session)
	target, _ := windows.UTF16PtrFromString(u.String())
	info, err := proxyForURL(session, target, winhttpAutoproxyOptions{
		flags:           winhttpAutoproxyAutoDetect,
		autoDetectFlags: winhttpAutoDetectTypeDHCP | winhttpAutoDetectTypeDNSA,
	})
	t.Logf("AutoProxy service only: proxy=%q err=%v", takeString(info.proxy), err)

	entries, err := systemProxies(u)
	require.NoError(t, err)
	assert.Equal(t, []string{"PROXY " + want}, entries)
}
