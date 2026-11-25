package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Install makes http.DefaultTransport use the operating system proxy
// settings and proxy authentication (Negotiate, NTLM and Basic). Call it
// once at startup, before HTTP clients are made.
func Install() {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return
	}
	http.DefaultTransport = NewTransport(base, NewResolver())
}

// Transport sends requests through the proxy that a Resolver selects.
//
// Requests use a clone of the base transport first, so a proxy that does
// not ask for authentication works exactly as with net/http. When a proxy
// answers CONNECT with 407 Proxy Authentication Required, the request is
// sent again through a tunnel that does the authentication, and later
// https requests through that proxy use the tunnel at once.
type Transport struct {
	resolver *Resolver
	direct   *http.Transport
	tunneled *http.Transport
	tunnel   *tunnel

	mu          sync.Mutex
	authProxies map[string]bool
}

// NewTransport returns a Transport that uses clones of base.
func NewTransport(base *http.Transport, r *Resolver) *Transport {
	return newTransport(base, r, &gitCredentials{})
}

func newTransport(base *http.Transport, r *Resolver, creds credentialStore) *Transport {
	t := &Transport{resolver: r, authProxies: map[string]bool{}}
	t.direct = base.Clone()
	t.direct.Proxy = r.Proxy
	t.direct.OnProxyConnectResponse = t.onConnectResponse

	t.tunnel = &tunnel{
		dialer:    &net.Dialer{Timeout: dialTimeout, KeepAlive: dialTimeout},
		tlsConfig: base.TLSClientConfig,
		schemes:   authSchemes(creds),
	}
	t.tunneled = base.Clone()
	t.tunneled.Proxy = nil
	t.tunneled.OnProxyConnectResponse = nil
	t.tunneled.GetProxyConnectHeader = nil
	t.tunneled.DialContext = t.dialTunnel
	return t
}

const dialTimeout = 30 * time.Second

// authRequiredError is the error for a CONNECT request that got 407.
type authRequiredError struct {
	proxy string
}

func (e *authRequiredError) Error() string {
	return fmt.Sprintf("proxy %s requires authentication", e.proxy)
}

func (t *Transport) onConnectResponse(_ context.Context, proxyURL *url.URL, _ *http.Request, res *http.Response) error {
	if res.StatusCode != http.StatusProxyAuthRequired {
		return nil
	}
	t.mu.Lock()
	t.authProxies[proxyURL.Host] = true
	t.mu.Unlock()
	return &authRequiredError{proxy: proxyURL.Host}
}

func (t *Transport) needsAuth(proxyURL *url.URL) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.authProxies[proxyURL.Host]
}

// tunnelProxy returns the proxy for a https request when the proxy needs
// a tunnel that gh makes, or nil.
func (t *Transport) tunnelProxy(u *url.URL) *url.URL {
	if u.Scheme != "https" {
		return nil
	}
	p, err := t.resolver.ProxyForURL(u)
	if err != nil || p == nil || (p.Scheme != "http" && p.Scheme != "https") {
		return nil
	}
	return p
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if p := t.tunnelProxy(req.URL); p != nil && t.needsAuth(p) {
		return t.tunneled.RoundTrip(req)
	}
	res, err := t.direct.RoundTrip(req)
	var authErr *authRequiredError
	if err == nil || !errors.As(err, &authErr) || t.tunnelProxy(req.URL) == nil {
		return res, err
	}
	retry := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, err
		}
		body, berr := req.GetBody()
		if berr != nil {
			return nil, err
		}
		retry.Body = body
	}
	return t.tunneled.RoundTrip(retry)
}

// CloseIdleConnections closes the idle connections of both transports.
func (t *Transport) CloseIdleConnections() {
	t.direct.CloseIdleConnections()
	t.tunneled.CloseIdleConnections()
}

func (t *Transport) dialTunnel(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	u := &url.URL{Scheme: "https", Host: addr}
	if port == "443" {
		u.Host = host
	}
	if p := t.tunnelProxy(u); p != nil {
		return t.tunnel.Dial(ctx, p, addr)
	}
	return t.tunnel.dialer.DialContext(ctx, network, addr)
}
