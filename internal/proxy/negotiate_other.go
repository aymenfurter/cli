//go:build !windows && !(darwin && cgo)

package proxy

// newNegotiate is nil because this platform has no Negotiate support.
var newNegotiate func(host string) (handshake, error)

// newPlatformNTLM is nil because NTLM on this platform needs a user name
// and password.
var newPlatformNTLM func() (handshake, error)
