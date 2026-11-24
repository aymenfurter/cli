package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connectProxy is a CONNECT proxy that asks for the given authentication
// scheme and accepts the request when Proxy-Authorization equals accept.
type connectProxy struct {
	challenge string
	accept    string

	mu    sync.Mutex
	auths []string
}

func (p *connectProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.auths = append(p.auths, r.Header.Get("Proxy-Authorization"))
	p.mu.Unlock()
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Proxy-Authorization") != p.accept {
		w.Header().Set("Proxy-Authenticate", p.challenge)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	upstream, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
	conn, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	go func() {
		_, _ = io.Copy(upstream, buf)
		upstream.Close()
	}()
	_, _ = io.Copy(conn, upstream)
	conn.Close()
}

func (p *connectProxy) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.auths...)
}

func newNegotiateClient(t *testing.T, proxyURL string, origin *httptest.Server, token negotiateFunc) *http.Client {
	t.Helper()
	pu, err := url.Parse(proxyURL)
	require.NoError(t, err)
	tr := origin.Client().Transport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(pu)
	n := newNegotiator(token)
	tr.GetProxyConnectHeader = n.ConnectHeader
	tr.OnProxyConnectResponse = n.ConnectResponse
	return &http.Client{Transport: &retryTransport{base: tr}}
}

func TestNegotiateProxy(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte("ok " + string(body)))
	}))
	defer origin.Close()

	p := &connectProxy{challenge: "Negotiate", accept: "Negotiate dG9rZW4="}
	ps := httptest.NewServer(p)
	defer ps.Close()

	var hosts []string
	client := newNegotiateClient(t, ps.URL, origin, func(host string) ([]byte, error) {
		hosts = append(hosts, host)
		return []byte("token"), nil
	})

	res, err := client.Post(origin.URL, "text/plain", strings.NewReader("body"))
	require.NoError(t, err)
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	assert.Equal(t, "ok body", string(b))
	assert.Equal(t, []string{"", "Negotiate dG9rZW4="}, p.seen())
	assert.Equal(t, []string{"127.0.0.1"}, hosts)

	// The proxy is now known, so a new connection authenticates at once.
	client.CloseIdleConnections()
	res, err = client.Get(origin.URL)
	require.NoError(t, err)
	res.Body.Close()
	assert.Equal(t, []string{"", "Negotiate dG9rZW4=", "Negotiate dG9rZW4="}, p.seen())
}

func TestNegotiateProxyRejectsToken(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer origin.Close()
	p := &connectProxy{challenge: "Negotiate", accept: "never"}
	ps := httptest.NewServer(p)
	defer ps.Close()

	client := newNegotiateClient(t, ps.URL, origin, func(string) ([]byte, error) { return []byte("token"), nil })
	_, err := client.Get(origin.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Proxy Authentication Required")
	assert.Len(t, p.seen(), 2)
}

func TestNegotiateProxyIgnoresBasic(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer origin.Close()
	p := &connectProxy{challenge: `Basic realm="proxy"`, accept: "never"}
	ps := httptest.NewServer(p)
	defer ps.Close()

	called := false
	client := newNegotiateClient(t, ps.URL, origin, func(string) ([]byte, error) {
		called = true
		return []byte("token"), nil
	})
	_, err := client.Get(origin.URL)
	require.Error(t, err)
	assert.False(t, called)
	assert.Len(t, p.seen(), 1)
}

func TestNegotiateProxyTokenError(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer origin.Close()
	p := &connectProxy{challenge: "Negotiate", accept: "never"}
	ps := httptest.NewServer(p)
	defer ps.Close()

	client := newNegotiateClient(t, ps.URL, origin, func(string) ([]byte, error) {
		return nil, assert.AnError
	})
	_, err := client.Get(origin.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot get a Kerberos ticket for proxy")
}

func TestOffersNegotiate(t *testing.T) {
	h := http.Header{}
	h.Add("Proxy-Authenticate", `Basic realm="x"`)
	assert.False(t, offersNegotiate(h))
	h.Add("Proxy-Authenticate", "NTLM, negotiate")
	assert.True(t, offersNegotiate(h))
}
