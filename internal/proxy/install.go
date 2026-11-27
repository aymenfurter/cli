package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	p := t.tunnelProxy(req.URL)
	if p == nil {
		return t.direct.RoundTrip(req)
	}
	if t.needsAuth(p) {
		return t.tunneled.RoundTrip(req)
	}
	first := req
	var body *heldBody
	if req.Body != nil && req.Body != http.NoBody {
		body = &heldBody{ReadCloser: req.Body}
		first = req.Clone(req.Context())
		first.Body = body
	}
	res, err := t.direct.RoundTrip(first)
	var authErr *authRequiredError
	retry := err != nil && errors.As(err, &authErr)
	if body != nil {
		body.finish(retry)
	}
	if !retry {
		return res, err
	}
	// The proxy rejected the CONNECT request before the transport sent
	// any of the body, so the original body is still unread.
	return t.tunneled.RoundTrip(req)
}

// heldBody delays a Close from the transport until the first round trip
// is complete. A failed CONNECT makes the transport close the request
// body, but gh must send that body again through the auth tunnel.
type heldBody struct {
	io.ReadCloser

	mu       sync.Mutex
	finished bool
	closed   bool
}

func (b *heldBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.finished {
		b.closed = true
		return nil
	}
	return b.ReadCloser.Close()
}

// finish ends the hold. If keep is false, it does a Close that it delayed.
func (b *heldBody) finish(keep bool) {
	b.mu.Lock()
	b.finished = true
	closed := b.closed
	b.mu.Unlock()
	if closed && !keep {
		_ = b.ReadCloser.Close()
	}
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
