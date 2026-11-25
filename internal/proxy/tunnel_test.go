package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
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

// proxyReply is the answer of a fake proxy to one CONNECT request.
type proxyReply struct {
	ok        bool
	challenge []string
	close     bool
}

// fakeProxy is a CONNECT proxy. For each request it calls auth with the
// connection number and the Proxy-Authorization header. On success it
// connects the client to origin, whatever the CONNECT target is.
type fakeProxy struct {
	origin string
	auth   func(conn int, authz string) proxyReply

	ln    net.Listener
	mu    sync.Mutex
	log   []string
	conns int
}

func startFakeProxy(t *testing.T, origin string, tlsConfig *tls.Config, auth func(conn int, authz string) proxyReply) *fakeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	if tlsConfig != nil {
		ln = tls.NewListener(ln, tlsConfig)
	}
	p := &fakeProxy{origin: origin, auth: auth, ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.conns++
			n := p.conns
			p.mu.Unlock()
			go p.serve(c, n)
		}
	}()
	return p
}

func (p *fakeProxy) serve(c net.Conn, n int) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		authz := req.Header.Get("Proxy-Authorization")
		p.mu.Lock()
		p.log = append(p.log, fmt.Sprintf("%d %s %s %s", n, req.Method, req.Host, authz))
		p.mu.Unlock()
		reply := p.auth(n, authz)
		if req.Method == http.MethodConnect && reply.ok {
			up, err := net.Dial("tcp", p.origin)
			if err != nil {
				return
			}
			fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
			go func() { _, _ = io.Copy(up, br); up.Close() }()
			_, _ = io.Copy(c, up)
			return
		}
		var b strings.Builder
		b.WriteString("HTTP/1.1 407 Proxy Authentication Required\r\n")
		for _, ch := range reply.challenge {
			fmt.Fprintf(&b, "Proxy-Authenticate: %s\r\n", ch)
		}
		if reply.close {
			b.WriteString("Connection: close\r\n")
		}
		b.WriteString("Content-Length: 6\r\n\r\ndenied")
		fmt.Fprint(c, b.String())
		if reply.close {
			return
		}
	}
}

func (p *fakeProxy) url() string {
	return "http://" + p.ln.Addr().String()
}

func (p *fakeProxy) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.log...)
}

// fakeCredentials is a credentialStore that records the calls.
type fakeCredentials struct {
	cred *credential
	mu   sync.Mutex
	log  []string
}

func (f *fakeCredentials) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, s)
}

func (f *fakeCredentials) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func (f *fakeCredentials) fill(_ context.Context, u *url.URL) (*credential, error) {
	f.record("fill " + proxyHostPort(u))
	if f.cred == nil {
		return nil, errNoCredential
	}
	c := *f.cred
	return &c, nil
}

func (f *fakeCredentials) approve(_ context.Context, u *url.URL, c *credential) {
	f.record("approve " + c.username)
}

func (f *fakeCredentials) reject(_ context.Context, u *url.URL, c *credential) {
	f.record("reject " + c.username)
}

// fakeHandshake returns the tokens in order and checks the challenges.
type fakeHandshake struct {
	t          *testing.T
	tokens     []string
	challenges []string
	result     *authResult
}

func (h *fakeHandshake) step(challenge []byte) ([]byte, error) {
	if challenge != nil {
		require.NotEmpty(h.t, h.challenges)
		assert.Equal(h.t, h.challenges[0], string(challenge))
		h.challenges = h.challenges[1:]
	}
	require.NotEmpty(h.t, h.tokens)
	tok := h.tokens[0]
	h.tokens = h.tokens[1:]
	return []byte(tok), nil
}

func (h *fakeHandshake) finish(_ context.Context, r authResult) {
	if h.result != nil {
		*h.result = r
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

type testSetup struct {
	origin *httptest.Server
	client *http.Client
	tr     *Transport
}

// newSetup makes an origin server for https://example.com and a client
// whose transport uses proxyURL.
func newSetup(t *testing.T, proxyURL func(origin string) string, creds credentialStore, schemes []scheme) *testSetup {
	t.Helper()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "ok %s", body)
	}))
	t.Cleanup(origin.Close)
	env := map[string]string{"HTTPS_PROXY": proxyURL(origin.Listener.Addr().String())}
	r := newTestResolver(env, nil, nil)
	base := origin.Client().Transport.(*http.Transport)
	tr := newTransport(base, r, creds)
	if schemes != nil {
		tr.tunnel.schemes = schemes
	}
	return &testSetup{origin: origin, client: &http.Client{Transport: tr}, tr: tr}
}

func (s *testSetup) post(t *testing.T, body string) (string, error) {
	t.Helper()
	res, err := s.client.Post("https://example.com/", "text/plain", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return string(b), err
}

func TestTransportProxyWithoutAuthentication(t *testing.T) {
	var p *fakeProxy
	s := newSetup(t, func(origin string) string {
		p = startFakeProxy(t, origin, nil, func(int, string) proxyReply { return proxyReply{ok: true} })
		return p.url()
	}, &fakeCredentials{}, nil)

	got, err := s.post(t, "hello")
	require.NoError(t, err)
	assert.Equal(t, "ok hello", got)
	assert.Equal(t, []string{"1 CONNECT example.com:443 "}, p.seen())
	assert.Empty(t, s.tr.authProxies)
}

func TestTransportBasicFromCredentialStore(t *testing.T) {
	want := "Basic " + b64("monalisa:s3cret")
	var p *fakeProxy
	creds := &fakeCredentials{cred: &credential{username: "monalisa", password: "s3cret", fromGit: true}}
	s := newSetup(t, func(origin string) string {
		p = startFakeProxy(t, origin, nil, func(_ int, authz string) proxyReply {
			return proxyReply{ok: authz == want, challenge: []string{`Basic realm="corp"`}}
		})
		return p.url()
	}, creds, nil)

	got, err := s.post(t, "first")
	require.NoError(t, err)
	assert.Equal(t, "ok first", got)

	// The proxy is now known to need authentication, so the next request
	// uses the tunnel at once.
	s.client.CloseIdleConnections()
	got, err = s.post(t, "second")
	require.NoError(t, err)
	assert.Equal(t, "ok second", got)

	assert.Equal(t, []string{
		"1 CONNECT example.com:443 ",
		"2 CONNECT example.com:443 ",
		"2 CONNECT example.com:443 " + want,
		"3 CONNECT example.com:443 ",
		"3 CONNECT example.com:443 " + want,
	}, p.seen())
	host := strings.TrimPrefix(p.url(), "http://")
	assert.Equal(t, []string{"fill " + host, "approve monalisa", "fill " + host, "approve monalisa"}, creds.calls())
}

func TestTransportBasicRejected(t *testing.T) {
	creds := &fakeCredentials{cred: &credential{username: "monalisa", password: "wrong", fromGit: true}}
	s := newSetup(t, func(origin string) string {
		return startFakeProxy(t, origin, nil, func(int, string) proxyReply {
			return proxyReply{challenge: []string{`Basic realm="corp"`}}
		}).url()
	}, creds, nil)

	_, err := s.post(t, "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Basic: the proxy rejected the credentials")
	assert.Equal(t, "reject monalisa", creds.calls()[len(creds.calls())-1])
}

func TestTransportNoCredentials(t *testing.T) {
	s := newSetup(t, func(origin string) string {
		return startFakeProxy(t, origin, nil, func(int, string) proxyReply {
			return proxyReply{challenge: []string{`Basic realm="corp"`}}
		}).url()
	}, &fakeCredentials{}, nil)

	_, err := s.post(t, "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no proxy credentials found")
}

func TestTransportBasicReconnectsAfterClose(t *testing.T) {
	want := "Basic " + b64("u:p")
	var p *fakeProxy
	s := newSetup(t, func(origin string) string {
		p = startFakeProxy(t, origin, nil, func(_ int, authz string) proxyReply {
			return proxyReply{ok: authz == want, challenge: []string{"Basic"}, close: true}
		})
		return p.url()
	}, &fakeCredentials{cred: &credential{username: "u", password: "p"}}, nil)

	got, err := s.post(t, "x")
	require.NoError(t, err)
	assert.Equal(t, "ok x", got)
	assert.Equal(t, []string{
		"1 CONNECT example.com:443 ",
		"2 CONNECT example.com:443 ",
		"3 CONNECT example.com:443 " + want,
	}, p.seen())
}

func TestTransportProxyURLUserInfo(t *testing.T) {
	want := "Basic " + b64("env-user:env-pass")
	var p *fakeProxy
	creds := &fakeCredentials{}
	s := newSetup(t, func(origin string) string {
		p = startFakeProxy(t, origin, nil, func(_ int, authz string) proxyReply {
			return proxyReply{ok: authz == want, challenge: []string{"Basic"}}
		})
		return "http://env-user:env-pass@" + p.ln.Addr().String()
	}, creds, nil)

	got, err := s.post(t, "x")
	require.NoError(t, err)
	assert.Equal(t, "ok x", got)
	assert.Equal(t, []string{"1 CONNECT example.com:443 " + want}, p.seen())
	assert.Empty(t, creds.calls())
}

func TestTransportHTTPSProxy(t *testing.T) {
	want := "Basic " + b64("u:p")
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer certServer.Close()
	var p *fakeProxy
	s := newSetup(t, func(origin string) string {
		p = startFakeProxy(t, origin, certServer.TLS, func(_ int, authz string) proxyReply {
			return proxyReply{ok: authz == want, challenge: []string{"Basic"}}
		})
		return "https://" + p.ln.Addr().String()
	}, &fakeCredentials{cred: &credential{username: "u", password: "p"}}, nil)
	s.tr.tunnel.tlsConfig = certServer.Client().Transport.(*http.Transport).TLSClientConfig
	s.tr.direct.TLSClientConfig = s.tr.tunnel.tlsConfig

	got, err := s.post(t, "x")
	require.NoError(t, err)
	assert.Equal(t, "ok x", got)
	assert.Len(t, p.seen(), 3)
}

// ntlmChallenge returns an NTLM CHALLENGE message (MS-NLMP 2.2.1.2).
func ntlmChallenge() []byte {
	const flags = 0x00000001 | 0x00000200 | 0x00080000 | 0x00800000 | 0x02000000 // UNICODE, NTLM, ESS, TARGET_INFO, VERSION
	target := []byte{'C', 0, 'O', 0, 'R', 0, 'P', 0}
	info := []byte{0, 0, 0, 0} // MsvAvEOL
	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	_ = binary.Write(&b, binary.LittleEndian, uint32(2))
	_ = binary.Write(&b, binary.LittleEndian, [2]uint16{uint16(len(target)), uint16(len(target))})
	_ = binary.Write(&b, binary.LittleEndian, uint32(56))
	_ = binary.Write(&b, binary.LittleEndian, uint32(flags))
	b.WriteString("01234567") // server challenge
	b.Write(make([]byte, 8))  // reserved
	_ = binary.Write(&b, binary.LittleEndian, [2]uint16{uint16(len(info)), uint16(len(info))})
	_ = binary.Write(&b, binary.LittleEndian, uint32(56+len(target)))
	b.Write([]byte{10, 0, 0x61, 0x4a, 0, 0, 0, 15}) // version
	b.Write(target)
	b.Write(info)
	return b.Bytes()
}

// ntlmUser returns DOMAIN\user from an NTLM AUTHENTICATE message.
func ntlmUser(t *testing.T, msg []byte) string {
	t.Helper()
	require.GreaterOrEqual(t, len(msg), 64)
	require.Equal(t, "NTLMSSP\x00\x03\x00\x00\x00", string(msg[:12]))
	field := func(off int) string {
		l := binary.LittleEndian.Uint16(msg[off:])
		o := binary.LittleEndian.Uint32(msg[off+4:])
		var s []rune
		for i := o; i+1 < o+uint32(l); i += 2 {
			s = append(s, rune(binary.LittleEndian.Uint16(msg[i:])))
		}
		return string(s)
	}
	return field(28) + `\` + field(36)
}

func TestTransportNTLMWithCredentials(t *testing.T) {
	challenge := ntlmChallenge()
	var user string
	var p *fakeProxy
	creds := &fakeCredentials{cred: &credential{username: `CORP\monalisa`, password: "s3cret", fromGit: true}}
	schemes := []scheme{{name: "NTLM", start: func(ctx context.Context, u *url.URL) (handshake, error) {
		return newCredentialHandshake(ctx, creds, u, &ntlmHandshake{})
	}}}
	s := newSetup(t, func(origin string) string {
		p = startFakeProxy(t, origin, nil, func(_ int, authz string) proxyReply {
			tok, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(authz, "NTLM "))
			switch {
			case bytes.HasPrefix(tok, []byte("NTLMSSP\x00\x01\x00\x00\x00")):
				return proxyReply{challenge: []string{"NTLM " + base64.StdEncoding.EncodeToString(challenge)}}
			case bytes.HasPrefix(tok, []byte("NTLMSSP\x00\x03\x00\x00\x00")):
				user = ntlmUser(t, tok)
				return proxyReply{ok: true}
			}
			return proxyReply{challenge: []string{"NTLM", `Basic realm="corp"`}}
		})
		return p.url()
	}, creds, schemes)

	got, err := s.post(t, "x")
	require.NoError(t, err)
	assert.Equal(t, "ok x", got)
	assert.Equal(t, `CORP\monalisa`, user)
	seen := p.seen()
	require.Len(t, seen, 4)
	// The NTLM handshake stays on one connection.
	for _, l := range seen[1:] {
		assert.True(t, strings.HasPrefix(l, "2 "), l)
	}
	assert.Equal(t, "approve "+`CORP\monalisa`, creds.calls()[len(creds.calls())-1])
}

func TestTransportNegotiateMultiStep(t *testing.T) {
	var result authResult = -1
	var p *fakeProxy
	schemes := []scheme{{name: "Negotiate", start: func(context.Context, *url.URL) (handshake, error) {
		return &fakeHandshake{t: t, tokens: []string{"t1", "t2"}, challenges: []string{"c1"}, result: &result}, nil
	}}}
	s := newSetup(t, func(origin string) string {
		p = startFakeProxy(t, origin, nil, func(_ int, authz string) proxyReply {
			switch authz {
			case "Negotiate " + b64("t1"):
				return proxyReply{challenge: []string{"Negotiate " + b64("c1")}}
			case "Negotiate " + b64("t2"):
				return proxyReply{ok: true}
			}
			return proxyReply{challenge: []string{"Negotiate"}}
		})
		return p.url()
	}, &fakeCredentials{}, schemes)

	got, err := s.post(t, "x")
	require.NoError(t, err)
	assert.Equal(t, "ok x", got)
	assert.Equal(t, accepted, result)
	assert.Equal(t, []string{
		"1 CONNECT example.com:443 ",
		"2 CONNECT example.com:443 ",
		"2 CONNECT example.com:443 Negotiate " + b64("t1"),
		"2 CONNECT example.com:443 Negotiate " + b64("t2"),
	}, p.seen())
}

func TestTransportFallsBackFromNegotiate(t *testing.T) {
	want := "Basic " + b64("u:p")
	var negResult authResult = -1
	creds := &fakeCredentials{cred: &credential{username: "u", password: "p", fromGit: true}}
	tests := []struct {
		name   string
		start  func(context.Context, *url.URL) (handshake, error)
		reason string
	}{
		{
			name:   "no Kerberos ticket",
			start:  func(context.Context, *url.URL) (handshake, error) { return nil, fmt.Errorf("no ticket") },
			reason: "Negotiate: no ticket",
		},
		{
			name: "token rejected",
			start: func(context.Context, *url.URL) (handshake, error) {
				return &fakeHandshake{t: t, tokens: []string{"t1"}, result: &negResult}, nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schemes := append([]scheme{{name: "Negotiate", start: tt.start}}, authSchemes(creds)[len(authSchemes(creds))-1])
			s := newSetup(t, func(origin string) string {
				return startFakeProxy(t, origin, nil, func(_ int, authz string) proxyReply {
					return proxyReply{ok: authz == want, challenge: []string{"Negotiate", `Basic realm="corp"`}}
				}).url()
			}, creds, schemes)
			got, err := s.post(t, "x")
			require.NoError(t, err)
			assert.Equal(t, "ok x", got)
		})
	}
	assert.Equal(t, rejected, negResult)
}

func TestTransportUnsupportedScheme(t *testing.T) {
	s := newSetup(t, func(origin string) string {
		return startFakeProxy(t, origin, nil, func(int, string) proxyReply {
			return proxyReply{challenge: []string{`Digest realm="corp", nonce="abc"`}}
		}).url()
	}, &fakeCredentials{}, nil)

	_, err := s.post(t, "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support")
	assert.Contains(t, err.Error(), "Digest")
}

func TestChallenges(t *testing.T) {
	h := http.Header{}
	h.Add("Proxy-Authenticate", `Basic realm="a, b", charset="UTF-8"`)
	h.Add("Proxy-Authenticate", "NTLM, Negotiate")
	h.Add("Proxy-Authenticate", "Negotiate YWJjZA==")
	assert.Equal(t, map[string]string{
		"basic":     "",
		"ntlm":      "",
		"negotiate": "YWJjZA==",
	}, challenges(h))
}
