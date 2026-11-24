//go:build !windows && !(darwin && cgo)

package proxy

// negotiateToken is nil because this platform has no Negotiate support.
var negotiateToken negotiateFunc
