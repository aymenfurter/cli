package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// errNegotiateRetry tells the retry transport that the proxy asks for
// Negotiate authentication and that a new request can authenticate.
var errNegotiateRetry = errors.New("proxy asks for Negotiate authentication")

// negotiateFunc returns a SPNEGO token for the HTTP service on host.
type negotiateFunc func(host string) ([]byte, error)

// negotiator adds Negotiate (Kerberos) authentication to proxy CONNECT
// requests. It sends a token only to proxies that asked for one.
type negotiator struct {
	token negotiateFunc

	mu      sync.Mutex
	proxies map[string]bool
}

func newNegotiator(token negotiateFunc) *negotiator {
	return &negotiator{token: token, proxies: map[string]bool{}}
}

func (n *negotiator) wanted(proxyHost string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.proxies[proxyHost]
}

// ConnectHeader has the signature of http.Transport.GetProxyConnectHeader.
func (n *negotiator) ConnectHeader(_ context.Context, proxyURL *url.URL, _ string) (http.Header, error) {
	if proxyURL == nil || !n.wanted(proxyURL.Host) {
		return nil, nil
	}
	tok, err := n.token(proxyURL.Hostname())
	if err != nil {
		return nil, fmt.Errorf("cannot get a Kerberos ticket for proxy %s: %w", proxyURL.Host, err)
	}
	h := http.Header{}
	h.Set("Proxy-Authorization", "Negotiate "+encodeToken(tok))
	return h, nil
}

// ConnectResponse has the signature of http.Transport.OnProxyConnectResponse.
func (n *negotiator) ConnectResponse(_ context.Context, proxyURL *url.URL, req *http.Request, res *http.Response) error {
	if proxyURL == nil || res.StatusCode != http.StatusProxyAuthRequired {
		return nil
	}
	if req.Header.Get("Proxy-Authorization") != "" || !offersNegotiate(res.Header) {
		return nil
	}
	n.mu.Lock()
	n.proxies[proxyURL.Host] = true
	n.mu.Unlock()
	return errNegotiateRetry
}

func offersNegotiate(h http.Header) bool {
	for _, v := range h.Values("Proxy-Authenticate") {
		for _, challenge := range strings.Split(v, ",") {
			f := strings.Fields(challenge)
			if len(f) > 0 && strings.EqualFold(f[0], "Negotiate") {
				return true
			}
		}
	}
	return false
}

// retryTransport sends a request again when the first proxy CONNECT asked
// for Negotiate authentication.
type retryTransport struct {
	base http.RoundTripper
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.base.RoundTrip(req)
	if err == nil || !errors.Is(err, errNegotiateRetry) {
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
	return t.base.RoundTrip(retry)
}

func (t *retryTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func encodeToken(tok []byte) string {
	return base64.StdEncoding.EncodeToString(tok)
}
