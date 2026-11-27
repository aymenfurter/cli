package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// maxAuthRounds limits the CONNECT requests for one tunnel. NTLM needs
// two, and a fallback from Negotiate to NTLM to Basic needs some more.
const maxAuthRounds = 8

// tunnel opens CONNECT tunnels through a proxy that asks for
// authentication. Unlike the CONNECT code in net/http, it keeps the proxy
// connection open between the 407 responses, which NTLM and multi-step
// Negotiate need.
type tunnel struct {
	dialer    *net.Dialer
	tlsConfig *tls.Config
	schemes   []scheme
}

// errProxyAuth is the error for a proxy that rejected all the
// authentication that gh can do.
type errProxyAuth struct {
	proxy   string
	reasons []string
}

func (e *errProxyAuth) Error() string {
	msg := "proxy authentication failed for " + e.proxy
	if len(e.reasons) > 0 {
		msg += ": " + strings.Join(e.reasons, "; ")
	}
	return msg
}

// proxyConn is a connection to the proxy and its read buffer.
type proxyConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *proxyConn) Read(p []byte) (int, error) {
	return c.br.Read(p)
}

func (t *tunnel) dialProxy(ctx context.Context, proxyURL *url.URL) (*proxyConn, error) {
	conn, err := t.dialer.DialContext(ctx, "tcp", proxyHostPort(proxyURL))
	if err != nil {
		return nil, err
	}
	if proxyURL.Scheme == "https" {
		cfg := &tls.Config{}
		if t.tlsConfig != nil {
			cfg = t.tlsConfig.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = proxyURL.Hostname()
		}
		cfg.NextProtos = nil
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tc
	}
	return &proxyConn{Conn: conn, br: bufio.NewReader(conn)}, nil
}

// connect sends one CONNECT request and reads the response headers.
func connect(ctx context.Context, conn *proxyConn, addr, auth string) (*http.Response, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: http.Header{},
	}
	if auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	req = req.WithContext(ctx)

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	if err := req.Write(conn); err != nil {
		return nil, ctxErr(ctx, err)
	}
	res, err := http.ReadResponse(conn.br, req)
	if err != nil {
		return nil, ctxErr(ctx, err)
	}
	return res, nil
}

func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Dial opens a tunnel to addr through the proxy.
func (t *tunnel) Dial(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	var (
		conn    *proxyConn
		cur     *scheme
		hs      handshake
		auth    string
		tried   = map[*scheme]bool{}
		reasons []string
	)
	closeConn := func() {
		if conn != nil {
			conn.Close()
			conn = nil
		}
	}
	defer func() {
		if hs != nil {
			hs.finish(ctx, aborted)
		}
	}()
	// begin starts a handshake with s and sets the first token.
	begin := func(s *scheme) bool {
		tried[s] = true
		h, err := s.start(ctx, proxyURL)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("%s: %v", s.name, err))
			return false
		}
		tok, err := h.step(nil)
		if err != nil {
			h.finish(ctx, aborted)
			reasons = append(reasons, fmt.Sprintf("%s: %v", s.name, err))
			return false
		}
		cur, hs, auth = s, h, authorization(s.name, tok)
		return true
	}

	// A password in the proxy URL is sent at once, as net/http does.
	if _, ok := proxyURL.User.Password(); ok {
		if s := t.scheme("basic"); s != nil {
			begin(s)
		}
	}

	for range maxAuthRounds {
		if conn == nil {
			var err error
			if conn, err = t.dialProxy(ctx, proxyURL); err != nil {
				return nil, err
			}
		}
		res, err := connect(ctx, conn, addr, auth)
		if err != nil {
			closeConn()
			return nil, err
		}
		if res.StatusCode == http.StatusOK {
			if hs != nil {
				hs.finish(ctx, accepted)
				hs = nil
			}
			return conn, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
		res.Body.Close()
		if res.StatusCode != http.StatusProxyAuthRequired {
			closeConn()
			return nil, fmt.Errorf("proxy %s refused CONNECT to %s: %s", proxyURL.Host, addr, res.Status)
		}
		if res.Close {
			closeConn()
		}

		offered := challenges(res.Header)
		auth = ""
		if hs != nil {
			// A token in the challenge continues the handshake on the same
			// connection. A challenge without a token rejects it.
			if next, err := continueHandshake(hs, offered[strings.ToLower(cur.name)], conn != nil); err != nil {
				reasons = append(reasons, fmt.Sprintf("%s: %v", cur.name, err))
			} else {
				auth = authorization(cur.name, next)
				continue
			}
			hs.finish(ctx, rejected)
			hs = nil
		}

		for i := range t.schemes {
			s := &t.schemes[i]
			if _, ok := offered[strings.ToLower(s.name)]; ok && !tried[s] && begin(s) {
				break
			}
		}
		if hs == nil {
			closeConn()
			if len(reasons) == 0 {
				reasons = append(reasons, "the proxy asks for an authentication scheme that gh does not support: "+strings.Join(res.Header.Values("Proxy-Authenticate"), ", "))
			}
			return nil, &errProxyAuth{proxy: proxyURL.Host, reasons: reasons}
		}
	}
	closeConn()
	return nil, &errProxyAuth{proxy: proxyURL.Host, reasons: append(reasons, "too many authentication steps")}
}

var errCredentialsRejected = errors.New("the proxy rejected the credentials")

// continueHandshake returns the next token for a challenge token, or an
// error when the proxy rejected the handshake.
func continueHandshake(hs handshake, challenge string, connOpen bool) ([]byte, error) {
	if challenge == "" || !connOpen {
		return nil, errCredentialsRejected
	}
	in, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		return nil, err
	}
	return hs.step(in)
}

// scheme returns the scheme with the lowercase name key, or nil.
func (t *tunnel) scheme(key string) *scheme {
	for i := range t.schemes {
		if strings.ToLower(t.schemes[i].name) == key {
			return &t.schemes[i]
		}
	}
	return nil
}
