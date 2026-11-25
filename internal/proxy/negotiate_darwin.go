//go:build darwin && cgo

package proxy

/*
#cgo LDFLAGS: -framework GSS
#include <stdlib.h>
#include <string.h>
#include <GSS/GSS.h>

static char *gh_gss_message(OM_uint32 status, int type) {
	OM_uint32 minor, ctx = 0;
	gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
	gss_display_status(&minor, status, type, GSS_C_NO_OID, &ctx, &msg);
	char *s = malloc(msg.length + 1);
	if (s != NULL) {
		memcpy(s, msg.value, msg.length);
		s[msg.length] = 0;
	}
	gss_release_buffer(&minor, &msg);
	return s;
}

// gh_gss_name imports the service name spn ("HTTP@host"). On failure it
// returns 1 and sets *err (free with free).
static int gh_gss_name(const char *spn, gss_name_t *name, char **err) {
	OM_uint32 major, minor;
	gss_buffer_desc nb = { strlen(spn), (void *)spn };
	major = gss_import_name(&minor, &nb, GSS_C_NT_HOSTBASED_SERVICE, name);
	if (GSS_ERROR(major)) {
		*err = gh_gss_message(major, GSS_C_GSS_CODE);
		return 1;
	}
	return 0;
}

// gh_gss_step makes the next SPNEGO token. in is NULL for the first token.
// On success it returns 0 and sets *out (free with free, can be NULL). On
// failure it returns 1 and sets *err (free with free).
static int gh_gss_step(gss_name_t name, gss_ctx_id_t *ctx, void *in, size_t inlen, void **out, size_t *outlen, char **err) {
	OM_uint32 major, minor;
	gss_buffer_desc input = { inlen, in };
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, ctx, name, GSS_SPNEGO_MECHANISM,
		0, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, in == NULL ? GSS_C_NO_BUFFER : &input,
		NULL, &token, NULL, NULL);
	int rc = 0;
	*out = NULL;
	*outlen = 0;
	if (GSS_ERROR(major)) {
		*err = gh_gss_message(minor != 0 ? minor : major, minor != 0 ? GSS_C_MECH_CODE : GSS_C_GSS_CODE);
		rc = 1;
	} else if (token.length > 0) {
		*out = malloc(token.length);
		if (*out == NULL) {
			rc = 1;
		} else {
			memcpy(*out, token.value, token.length);
			*outlen = token.length;
		}
	}
	gss_release_buffer(&minor, &token);
	return rc;
}

static void gh_gss_release(gss_name_t name, gss_ctx_id_t ctx) {
	OM_uint32 minor;
	if (ctx != GSS_C_NO_CONTEXT) {
		gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);
	}
	if (name != GSS_C_NO_NAME) {
		gss_release_name(&minor, &name);
	}
}
*/
import "C"

import (
	"context"
	"errors"
	"unsafe"
)

// newNegotiate uses the Kerberos tickets of the signed-in macOS user through
// the GSS framework.
var newNegotiate = func(host string) (handshake, error) {
	spn := C.CString("HTTP@" + host)
	defer C.free(unsafe.Pointer(spn))
	h := &gssNegotiate{}
	var cerr *C.char
	if C.gh_gss_name(spn, &h.name, &cerr) != 0 { //nolint:gocritic // false positive from cgo-generated code
		return nil, gssError(cerr)
	}
	return h, nil
}

// newPlatformNTLM is nil because macOS has no NTLM single sign-on for HTTP
// proxies. NTLM uses a user name and password instead.
var newPlatformNTLM func() (handshake, error)

type gssNegotiate struct {
	name C.gss_name_t
	ctx  C.gss_ctx_id_t
}

func (h *gssNegotiate) step(challenge []byte) ([]byte, error) {
	var in unsafe.Pointer
	if challenge != nil {
		in = C.CBytes(challenge)
		defer C.free(in)
	}
	var out unsafe.Pointer
	var outlen C.size_t
	var cerr *C.char
	if C.gh_gss_step(h.name, &h.ctx, in, C.size_t(len(challenge)), &out, &outlen, &cerr) != 0 { //nolint:gocritic // false positive from cgo-generated code
		return nil, gssError(cerr)
	}
	if out == nil {
		if challenge == nil {
			return nil, errors.New("GSS-API returned no token")
		}
		return nil, nil
	}
	defer C.free(out)
	return C.GoBytes(out, C.int(outlen)), nil
}

func (h *gssNegotiate) finish(context.Context, authResult) {
	C.gh_gss_release(h.name, h.ctx)
	h.name, h.ctx = nil, nil
}

func gssError(cerr *C.char) error {
	if cerr == nil {
		return errors.New("GSS-API error")
	}
	defer C.free(unsafe.Pointer(cerr))
	return errors.New(C.GoString(cerr))
}
