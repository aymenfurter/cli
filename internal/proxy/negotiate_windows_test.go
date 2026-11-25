//go:build windows

package proxy

import (
	"encoding/base64"
	"strings"
	"sync"
	"testing"

	"github.com/alexbrainman/sspi/negotiate"
	"github.com/alexbrainman/sspi/ntlm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTransportSSPINTLM does a real NTLM handshake: the client uses the
// credentials of the signed-in Windows user, and the fake proxy checks them
// with the SSPI server functions.
func TestTransportSSPINTLM(t *testing.T) {
	serverCred, err := ntlm.AcquireServerCredentials()
	require.NoError(t, err)
	defer serverCred.Release()

	var mu sync.Mutex
	contexts := map[int]*ntlm.ServerContext{}
	var p *fakeProxy
	s := newSetup(t, func(origin string) string {
		p = startFakeProxy(t, origin, nil, func(conn int, authz string) proxyReply {
			mu.Lock()
			defer mu.Unlock()
			deny := proxyReply{challenge: []string{"NTLM"}}
			tok, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authz, "NTLM "))
			if err != nil || !strings.HasPrefix(authz, "NTLM ") {
				return deny
			}
			sc := contexts[conn]
			if sc == nil {
				sc, challenge, err := ntlm.NewServerContext(serverCred, tok)
				if err != nil {
					t.Errorf("NTLM negotiate message: %v", err)
					return deny
				}
				contexts[conn] = sc
				return proxyReply{challenge: []string{"NTLM " + base64.StdEncoding.EncodeToString(challenge)}}
			}
			defer sc.Release()
			if err := sc.Update(tok); err != nil {
				t.Errorf("NTLM authenticate message: %v", err)
				return deny
			}
			return proxyReply{ok: true}
		})
		return p.url()
	}, &fakeCredentials{}, nil)

	got, err := s.post(t, "x")
	require.NoError(t, err)
	assert.Equal(t, "ok x", got)
	assert.Len(t, p.seen(), 4)
}

// TestTransportSSPINegotiate does a real Negotiate handshake. Without a
// domain, SPNEGO uses NTLM, so the handshake has several steps on one
// connection.
func TestTransportSSPINegotiate(t *testing.T) {
	serverCred, err := negotiate.AcquireServerCredentials("")
	require.NoError(t, err)
	defer serverCred.Release()

	var mu sync.Mutex
	contexts := map[int]*negotiate.ServerContext{}
	var p *fakeProxy
	s := newSetup(t, func(origin string) string {
		p = startFakeProxy(t, origin, nil, func(conn int, authz string) proxyReply {
			mu.Lock()
			defer mu.Unlock()
			deny := proxyReply{challenge: []string{"Negotiate"}}
			tok, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authz, "Negotiate "))
			if err != nil || !strings.HasPrefix(authz, "Negotiate ") {
				return deny
			}
			var done bool
			var out []byte
			if sc := contexts[conn]; sc == nil {
				sc, done, out, err = negotiate.NewServerContext(serverCred, tok)
				contexts[conn] = sc
			} else {
				done, out, err = sc.Update(tok)
			}
			if err != nil {
				t.Errorf("Negotiate token: %v", err)
				return deny
			}
			if done {
				return proxyReply{ok: true}
			}
			return proxyReply{challenge: []string{"Negotiate " + base64.StdEncoding.EncodeToString(out)}}
		})
		return p.url()
	}, &fakeCredentials{}, nil)

	got, err := s.post(t, "x")
	require.NoError(t, err)
	assert.Equal(t, "ok x", got)
	t.Logf("proxy log: %q", p.seen())
	assert.GreaterOrEqual(t, len(p.seen()), 3)
}
