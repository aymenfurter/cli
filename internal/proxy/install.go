package proxy

import "net/http"

// Install makes http.DefaultTransport use the operating system proxy
// settings and Negotiate proxy authentication. Call it once at startup,
// before HTTP clients are made.
func Install() {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return
	}
	t := base.Clone()
	t.Proxy = NewResolver().Proxy
	if negotiateToken == nil {
		http.DefaultTransport = t
		return
	}
	n := newNegotiator(negotiateToken)
	t.GetProxyConnectHeader = n.ConnectHeader
	t.OnProxyConnectResponse = n.ConnectResponse
	http.DefaultTransport = &retryTransport{base: t}
}
