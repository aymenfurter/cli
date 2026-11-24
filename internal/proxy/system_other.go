//go:build !windows && !(darwin && cgo)

package proxy

import "net/url"

// systemProxies returns no proxies. On this platform gh reads only the
// environment.
func systemProxies(*url.URL) ([]string, error) {
	return nil, nil
}
