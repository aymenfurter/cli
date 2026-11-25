package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/go-ntlmssp"
)

// handshake makes the Proxy-Authorization tokens for one authentication
// scheme on one proxy connection.
type handshake interface {
	// step returns the next token. challenge is nil for the first token,
	// and is the token from the proxy challenge after that.
	step(challenge []byte) ([]byte, error)
	// finish releases resources and records the result.
	finish(ctx context.Context, result authResult)
}

// authResult is the result of a handshake.
type authResult int

const (
	// aborted means that the handshake stopped for a different reason, for
	// example a network error. The credentials can be correct.
	aborted authResult = iota
	accepted
	rejected
)

// scheme is a proxy authentication scheme.
type scheme struct {
	// name is the scheme name in Proxy-Authenticate, for example "NTLM".
	name string
	// start begins a handshake for the proxy.
	start func(ctx context.Context, proxyURL *url.URL) (handshake, error)
}

// authSchemes returns the supported schemes, the most secure first.
func authSchemes(creds credentialStore) []scheme {
	var schemes []scheme
	if newNegotiate != nil {
		schemes = append(schemes, scheme{name: "Negotiate", start: func(_ context.Context, proxyURL *url.URL) (handshake, error) {
			return newNegotiate(proxyURL.Hostname())
		}})
	}
	schemes = append(schemes, scheme{name: "NTLM", start: func(ctx context.Context, proxyURL *url.URL) (handshake, error) {
		if newPlatformNTLM != nil && proxyURL.User == nil {
			return newPlatformNTLM()
		}
		return newCredentialHandshake(ctx, creds, proxyURL, &ntlmHandshake{})
	}})
	schemes = append(schemes, scheme{name: "Basic", start: func(ctx context.Context, proxyURL *url.URL) (handshake, error) {
		return newCredentialHandshake(ctx, creds, proxyURL, &basicHandshake{})
	}})
	return schemes
}

// challenges returns the tokens of the Proxy-Authenticate challenges by
// lowercase scheme name. A scheme without a token, or with parameters such
// as realm="x", has an empty value.
func challenges(h http.Header) map[string]string {
	m := map[string]string{}
	for _, v := range h.Values("Proxy-Authenticate") {
		for _, part := range splitOutsideQuotes(v) {
			name, rest, _ := strings.Cut(strings.TrimSpace(part), " ")
			if name == "" || strings.Contains(name, "=") {
				// An auth-param of the previous challenge.
				continue
			}
			name = strings.ToLower(name)
			token := strings.TrimSpace(rest)
			if (strings.Contains(token, "=") && !strings.HasSuffix(token, "=")) || strings.Contains(token, "\"") {
				token = ""
			}
			if old, ok := m[name]; !ok || old == "" {
				m[name] = token
			}
		}
	}
	return m
}

func splitOutsideQuotes(s string) []string {
	var parts []string
	quoted, start := false, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			quoted = !quoted
		case ',':
			if !quoted {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, s[start:])
}

func authorization(name string, token []byte) string {
	return name + " " + base64.StdEncoding.EncodeToString(token)
}

// credentialMechanism is a handshake that uses a user name and password.
type credentialMechanism interface {
	step(c *credential, challenge []byte) ([]byte, error)
}

type credentialHandshake struct {
	creds    credentialStore
	proxyURL *url.URL
	cred     *credential
	mech     credentialMechanism
	sent     bool
}

func newCredentialHandshake(ctx context.Context, creds credentialStore, proxyURL *url.URL, mech credentialMechanism) (handshake, error) {
	c, err := creds.fill(ctx, proxyURL)
	if err != nil {
		return nil, err
	}
	return &credentialHandshake{creds: creds, proxyURL: proxyURL, cred: c, mech: mech}, nil
}

func (h *credentialHandshake) step(challenge []byte) ([]byte, error) {
	h.sent = true
	return h.mech.step(h.cred, challenge)
}

func (h *credentialHandshake) finish(ctx context.Context, result authResult) {
	if !h.sent {
		return
	}
	switch result {
	case accepted:
		h.creds.approve(ctx, h.proxyURL, h.cred)
	case rejected:
		h.creds.reject(ctx, h.proxyURL, h.cred)
	}
}

type basicHandshake struct{}

func (basicHandshake) step(c *credential, challenge []byte) ([]byte, error) {
	if challenge != nil {
		return nil, errors.New("basic authentication has one step only")
	}
	return []byte(c.username + ":" + c.password), nil
}

// ntlmHandshake is NTLMv2 with a user name and password. The user name can
// have the form DOMAIN\user or user@domain.
type ntlmHandshake struct{}

func (ntlmHandshake) step(c *credential, challenge []byte) ([]byte, error) {
	if challenge == nil {
		return ntlmssp.NewNegotiateMessage("", "")
	}
	msg, err := ntlmssp.NewAuthenticateMessage(challenge, c.username, c.password, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot make NTLM response: %w", err)
	}
	return msg, nil
}
