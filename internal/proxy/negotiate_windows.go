//go:build windows

package proxy

import (
	"github.com/alexbrainman/sspi/negotiate"
)

var negotiateToken negotiateFunc = sspiToken

// sspiToken uses the credentials of the signed-in Windows user.
func sspiToken(host string) ([]byte, error) {
	cred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}
	defer cred.Release()
	ctx, token, err := negotiate.NewClientContext(cred, "HTTP/"+host)
	if err != nil {
		return nil, err
	}
	defer ctx.Release()
	return token, nil
}
