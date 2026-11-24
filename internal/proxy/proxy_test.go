package proxy

import (
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestResolver(env map[string]string, system func(*url.URL) ([]string, error), probe func(string) bool) *Resolver {
	return &Resolver{
		Getenv: func(k string) string { return env[k] },
		System: system,
		Probe:  probe,
		Now:    time.Now,
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}

func TestProxyForURL(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]string
		system []string
		err    error
		down   []string
		target string
		want   string
	}{
		{
			name:   "environment wins over system",
			env:    map[string]string{"HTTPS_PROXY": "http://env:3128"},
			system: []string{"PROXY sys:8080"},
			target: "https://api.github.com/",
			want:   "http://env:3128",
		},
		{
			name:   "lowercase environment wins over system",
			env:    map[string]string{"https_proxy": "http://env:3128"},
			system: []string{"PROXY sys:8080"},
			target: "https://api.github.com/",
			want:   "http://env:3128",
		},
		{
			name:   "all_proxy wins over system",
			env:    map[string]string{"ALL_PROXY": "socks5://env:1080"},
			system: []string{"PROXY sys:8080"},
			target: "https://api.github.com/",
			want:   "socks5://env:1080",
		},
		{
			name:   "system proxy",
			system: []string{"PROXY sys:8080"},
			target: "https://api.github.com/",
			want:   "http://sys:8080",
		},
		{
			name:   "system direct",
			system: []string{"DIRECT"},
			target: "https://api.github.com/",
		},
		{
			name:   "no system settings",
			target: "https://api.github.com/",
		},
		{
			name:   "system error gives direct",
			err:    errors.New("boom"),
			target: "https://api.github.com/",
		},
		{
			name:   "NO_PROXY excludes system proxy",
			env:    map[string]string{"NO_PROXY": ".github.com"},
			system: []string{"PROXY sys:8080"},
			target: "https://api.github.com/",
		},
		{
			name:   "localhost is never sent to the system proxy",
			system: []string{"PROXY sys:8080"},
			target: "http://127.0.0.1:9000/",
		},
		{
			name:   "first proxy is down",
			system: []string{"PROXY a:8080; PROXY b:8080"},
			down:   []string{"a:8080"},
			target: "https://api.github.com/",
			want:   "http://b:8080",
		},
		{
			name:   "all proxies down then direct",
			system: []string{"PROXY a:8080", "PROXY b:8080", "DIRECT"},
			down:   []string{"a:8080", "b:8080"},
			target: "https://api.github.com/",
		},
		{
			name:   "all proxies down gives the first proxy",
			system: []string{"PROXY a:8080; PROXY b:8080"},
			down:   []string{"a:8080", "b:8080"},
			target: "https://api.github.com/",
			want:   "http://a:8080",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestResolver(tt.env, func(*url.URL) ([]string, error) {
				return tt.system, tt.err
			}, func(hostport string) bool {
				return !slices.Contains(tt.down, hostport)
			})
			got, err := r.ProxyForURL(mustURL(t, tt.target))
			require.NoError(t, err)
			if tt.want == "" {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.want, got.String())
			}
		})
	}
}

func TestProxyForURLCachesResults(t *testing.T) {
	systemCalls, probeCalls := 0, 0
	r := newTestResolver(nil, func(*url.URL) ([]string, error) {
		systemCalls++
		return []string{"PROXY a:8080; PROXY b:8080"}, nil
	}, func(hostport string) bool {
		probeCalls++
		return hostport == "b:8080"
	})
	for _, path := range []string{"/a", "/b", "/c"} {
		got, err := r.ProxyForURL(mustURL(t, "https://api.github.com"+path))
		require.NoError(t, err)
		assert.Equal(t, "http://b:8080", got.String())
	}
	_, err := r.ProxyForURL(mustURL(t, "https://uploads.github.com/"))
	require.NoError(t, err)
	assert.Equal(t, 2, systemCalls)
	assert.Equal(t, 2, probeCalls)
}

func TestParseEntries(t *testing.T) {
	got := ParseEntries([]string{
		"PROXY a:8080; proxy a:8080;HTTPS b:443",
		"SOCKS c:1080",
		"DIRECT",
		"DIRECT",
		"PROXY no-port",
		"UNKNOWN d:1",
		"",
		"PROXY [::1]:3128",
	})
	var s []string
	for _, u := range got {
		if u == nil {
			s = append(s, "DIRECT")
		} else {
			s = append(s, u.String())
		}
	}
	assert.Equal(t, []string{"http://a:8080", "https://b:443", "socks5://c:1080", "DIRECT", "http://[::1]:3128"}, s)
}
