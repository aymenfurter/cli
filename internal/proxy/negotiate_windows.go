//go:build windows

package proxy

import (
	"context"
	"errors"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/alexbrainman/sspi/ntlm"
)

// newNegotiate uses the Kerberos or NTLM credentials of the signed-in
// Windows user through SSPI.
var newNegotiate = func(host string) (handshake, error) {
	cred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}
	return &sspiNegotiate{cred: cred, target: "HTTP/" + host}, nil
}

// newPlatformNTLM uses the NTLM credentials of the signed-in Windows user
// through SSPI.
var newPlatformNTLM = func() (handshake, error) {
	cred, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}
	return &sspiNTLM{cred: cred}, nil
}

type sspiNegotiate struct {
	cred   *sspi.Credentials
	target string
	ctx    *negotiate.ClientContext
}

func (h *sspiNegotiate) step(challenge []byte) ([]byte, error) {
	if h.ctx == nil {
		if challenge != nil {
			return nil, errors.New("unexpected Negotiate challenge")
		}
		ctx, tok, err := negotiate.NewClientContext(h.cred, h.target)
		if err != nil {
			return nil, err
		}
		h.ctx = ctx
		return tok, nil
	}
	_, tok, err := h.ctx.Update(challenge)
	return tok, err
}

func (h *sspiNegotiate) finish(context.Context, authResult) {
	if h.ctx != nil {
		_ = h.ctx.Release()
	}
	_ = h.cred.Release()
}

type sspiNTLM struct {
	cred *sspi.Credentials
	ctx  *ntlm.ClientContext
}

func (h *sspiNTLM) step(challenge []byte) ([]byte, error) {
	if h.ctx == nil {
		if challenge != nil {
			return nil, errors.New("unexpected NTLM challenge")
		}
		ctx, tok, err := ntlm.NewClientContext(h.cred)
		if err != nil {
			return nil, err
		}
		h.ctx = ctx
		return tok, nil
	}
	return h.ctx.Update(challenge)
}

func (h *sspiNTLM) finish(context.Context, authResult) {
	if h.ctx != nil {
		_ = h.ctx.Release()
	}
	_ = h.cred.Release()
}
