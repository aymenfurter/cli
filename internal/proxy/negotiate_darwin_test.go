//go:build darwin && cgo

package proxy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGSSNegotiateWithoutTicket calls the GSS framework. A proxy name that
// does not exist has no Kerberos ticket, so the first step must fail with
// an error and not crash.
func TestGSSNegotiateWithoutTicket(t *testing.T) {
	h, err := newNegotiate("proxy.gh-cli-test.invalid")
	require.NoError(t, err)
	_, err = h.step(nil)
	require.Error(t, err)
	h.finish(context.Background(), aborted)
}
