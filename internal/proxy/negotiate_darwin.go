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

// gh_spnego_token makes the first SPNEGO token for the service spn
// ("HTTP@host"). On success it returns 0 and sets *out (free with free).
// On failure it returns 1 and sets *err (free with free).
static int gh_spnego_token(const char *spn, void **out, size_t *outlen, char **err) {
	OM_uint32 major, minor;
	gss_buffer_desc nb = { strlen(spn), (void *)spn };
	gss_name_t name = GSS_C_NO_NAME;
	major = gss_import_name(&minor, &nb, GSS_C_NT_HOSTBASED_SERVICE, &name);
	if (GSS_ERROR(major)) {
		*err = gh_gss_message(major, GSS_C_GSS_CODE);
		return 1;
	}
	gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &ctx, name, GSS_SPNEGO_MECHANISM,
		0, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, NULL, &token, NULL, NULL);
	int rc = 0;
	if (GSS_ERROR(major) || token.length == 0) {
		*err = gh_gss_message(minor != 0 ? minor : major, minor != 0 ? GSS_C_MECH_CODE : GSS_C_GSS_CODE);
		rc = 1;
	} else {
		*out = malloc(token.length);
		if (*out == NULL) {
			rc = 1;
		} else {
			memcpy(*out, token.value, token.length);
			*outlen = token.length;
		}
	}
	gss_release_buffer(&minor, &token);
	if (ctx != GSS_C_NO_CONTEXT) {
		gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);
	}
	gss_release_name(&minor, &name);
	return rc;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

var negotiateToken negotiateFunc = gssToken

func gssToken(host string) ([]byte, error) {
	spn := C.CString("HTTP@" + host)
	defer C.free(unsafe.Pointer(spn))
	var out unsafe.Pointer
	var outlen C.size_t
	var cerr *C.char
	if C.gh_spnego_token(spn, &out, &outlen, &cerr) != 0 {
		msg := "GSS-API error"
		if cerr != nil {
			msg = C.GoString(cerr)
			C.free(unsafe.Pointer(cerr))
		}
		return nil, errors.New(msg)
	}
	defer C.free(out)
	return C.GoBytes(out, C.int(outlen)), nil
}
