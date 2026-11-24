// Package proxy finds the proxy for gh HTTP requests.
//
// When HTTPS_PROXY, HTTP_PROXY or ALL_PROXY is set, gh uses only the
// environment, as before. When none is set, gh also reads the proxy settings
// of the operating system: the manual proxy, the proxy auto-configuration
// (PAC) file and Web Proxy Auto-Discovery (WPAD) on macOS and Windows. NO_PROXY
// applies to all proxies.
package proxy

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"
)

const (
	resultTTL    = 5 * time.Minute
	probeTimeout = 3 * time.Second
)

// Resolver selects the proxy for a request.
type Resolver struct {
	// Getenv reads environment variables.
	Getenv func(string) string
	// System returns the operating system proxy list for a URL, in the
	// PAC result format, for example "PROXY host:port" or "DIRECT".
	System func(*url.URL) ([]string, error)
	// Probe tells if a proxy accepts TCP connections.
	Probe func(hostport string) bool
	// Now returns the current time.
	Now func() time.Time

	mu       sync.Mutex
	results  map[string]cachedResult
	probes   map[string]cachedProbe
	envProxy func(*url.URL) (*url.URL, error)
	noProxy  func(*url.URL) (*url.URL, error)
	initOnce sync.Once
}

type cachedResult struct {
	proxy   *url.URL
	expires time.Time
}

type cachedProbe struct {
	ok      bool
	expires time.Time
}

// NewResolver returns a Resolver that uses the process environment and the
// operating system settings.
func NewResolver() *Resolver {
	return &Resolver{
		Getenv: os.Getenv,
		System: systemProxies,
		Probe:  probeTCP,
		Now:    time.Now,
	}
}

func (r *Resolver) init() {
	r.initOnce.Do(func() {
		env := &httpproxy.Config{
			HTTPProxy:  r.getenvAny("HTTP_PROXY", "http_proxy"),
			HTTPSProxy: r.getenvAny("HTTPS_PROXY", "https_proxy"),
			NoProxy:    r.getenvAny("NO_PROXY", "no_proxy"),
		}
		if all := r.getenvAny("ALL_PROXY", "all_proxy"); all != "" {
			if env.HTTPProxy == "" {
				env.HTTPProxy = all
			}
			if env.HTTPSProxy == "" {
				env.HTTPSProxy = all
			}
		}
		if env.HTTPProxy != "" || env.HTTPSProxy != "" {
			r.envProxy = env.ProxyFunc()
		}
		// This config has a proxy for all requests, so a nil result means that
		// NO_PROXY (or the built-in localhost rule) excludes the URL.
		r.noProxy = (&httpproxy.Config{
			HTTPProxy:  "http://no-proxy-check.invalid",
			HTTPSProxy: "http://no-proxy-check.invalid",
			NoProxy:    env.NoProxy,
		}).ProxyFunc()
		r.results = map[string]cachedResult{}
		r.probes = map[string]cachedProbe{}
	})
}

func (r *Resolver) getenvAny(names ...string) string {
	for _, n := range names {
		if v := r.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// Proxy has the signature of http.Transport.Proxy.
func (r *Resolver) Proxy(req *http.Request) (*url.URL, error) {
	return r.ProxyForURL(req.URL)
}

// ProxyForURL returns the proxy for u, or nil for a direct connection.
func (r *Resolver) ProxyForURL(u *url.URL) (*url.URL, error) {
	r.init()
	if r.envProxy != nil {
		return r.envProxy(u)
	}
	if p, err := r.noProxy(u); err != nil || p == nil {
		return nil, err
	}
	if r.System == nil {
		return nil, nil
	}

	key := u.Scheme + "://" + u.Host
	now := r.Now()
	r.mu.Lock()
	if c, ok := r.results[key]; ok && now.Before(c.expires) {
		r.mu.Unlock()
		return c.proxy, nil
	}
	r.mu.Unlock()

	entries, err := r.System(u)
	if err != nil {
		// Do not stop the request: try a direct connection as before.
		return nil, nil
	}
	p := r.choose(ParseEntries(entries))

	r.mu.Lock()
	r.results[key] = cachedResult{proxy: p, expires: now.Add(resultTTL)}
	r.mu.Unlock()
	return p, nil
}

// choose returns the first candidate that is DIRECT or that accepts TCP
// connections. If no proxy accepts connections, it returns the first
// candidate so that the error message names a proxy.
func (r *Resolver) choose(candidates []*url.URL) *url.URL {
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) == 1 || r.Probe == nil {
		return candidates[0]
	}
	for _, c := range candidates {
		if c == nil || r.reachable(c.Host) {
			return c
		}
	}
	return candidates[0]
}

func (r *Resolver) reachable(hostport string) bool {
	now := r.Now()
	r.mu.Lock()
	if c, ok := r.probes[hostport]; ok && now.Before(c.expires) {
		r.mu.Unlock()
		return c.ok
	}
	r.mu.Unlock()
	ok := r.Probe(hostport)
	r.mu.Lock()
	r.probes[hostport] = cachedProbe{ok: ok, expires: now.Add(resultTTL)}
	r.mu.Unlock()
	return ok
}

func probeTCP(hostport string) bool {
	c, err := net.DialTimeout("tcp", hostport, probeTimeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// ParseEntries converts PAC result entries to proxy URLs. A nil URL means a
// direct connection. Each entry can contain more than one item separated by
// ";", for example "PROXY a:8080; DIRECT". Unknown items are ignored.
func ParseEntries(entries []string) []*url.URL {
	var out []*url.URL
	seen := map[string]bool{}
	for _, e := range entries {
		for _, item := range strings.Split(e, ";") {
			fields := strings.Fields(item)
			if len(fields) == 0 {
				continue
			}
			var scheme string
			switch strings.ToUpper(fields[0]) {
			case "DIRECT":
				if !seen["DIRECT"] {
					seen["DIRECT"] = true
					out = append(out, nil)
				}
				continue
			case "PROXY", "HTTP":
				scheme = "http"
			case "HTTPS":
				scheme = "https"
			case "SOCKS", "SOCKS5":
				scheme = "socks5"
			default:
				continue
			}
			if len(fields) < 2 {
				continue
			}
			hostport := fields[1]
			if _, port, err := net.SplitHostPort(hostport); err != nil || port == "" {
				continue
			}
			u := &url.URL{Scheme: scheme, Host: hostport}
			if !seen[u.String()] {
				seen[u.String()] = true
				out = append(out, u)
			}
		}
	}
	return out
}
