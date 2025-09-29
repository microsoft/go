package ossl

/*
#include <stdlib.h> // for calloc and free
#include <string.h> // for strdup
#include "zossl.h"

// OpenSSL only allows a maximum of 16 errors to be stored in the error queue.
#define ERR_NUM_MAX  16

// ossl_err_state is a custom structure to hold the error state
// of OpenSSL.
typedef struct ossl_err_state_st {
	unsigned long code[ERR_NUM_MAX];
	int line[ERR_NUM_MAX];
	char *file[ERR_NUM_MAX];
} ossl_err_state;

// mkcgo_err_clear clears the error queue in OpenSSL.
void mkcgo_err_clear() {
	// Clear the error queue.
	_mkcgo_ERR_clear_error();
}

// mkcgo_err_retrieve retrieves the error state from OpenSSL.
// It returns a pointer to a mkcgo_err_state structure
// that contains the error codes, lines, and file names.
// The caller is responsible for freeing the memory
// by calling mkcgo_err_free.
mkcgo_err_state mkcgo_err_retrieve() {
	ossl_err_state *errs = (ossl_err_state *)calloc(1, sizeof(ossl_err_state));
	if (errs == NULL) return NULL;

	// Retrieve the errors from OpenSSL.
	for (int i = 0; i < ERR_NUM_MAX; i++) {
		const char *file;
		if (_mkcgo_available_OPENSSL_version_major() == 1) { // Only available in OpenSSL 3.
			// OpenSSL 3 error handling
			errs->code[i] = _mkcgo_ERR_get_error_all(&file, &errs->line[i], NULL, NULL, NULL);
		} else {
			// OpenSSL 1 error handling
			errs->code[i] = _mkcgo_ERR_get_error_line(&file, &errs->line[i]);
		}
		if (errs->code[i] == 0) {
			break;
		}
		if (file != NULL) {
			// Copy the file name as the pointer we just retrieved will be freed by OpenSSL
			// when the error queue is cleared.
			errs->file[i] = strdup(file);
		}
	}
	return errs;
}

// mkcgo_err_free frees the memory allocated for the mkcgo_err_state structure.
void mkcgo_err_free(mkcgo_err_state errs) {
	if (errs == NULL) return;

	ossl_err_state *oerrs = (ossl_err_state *)errs;
	for (int i = 0; i < ERR_NUM_MAX; i++) {
		if (oerrs->file[i] != NULL) {
			free((void *)oerrs->file[i]);
		}
	}
	free(errs);
}
*/
import "C"
import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"unsafe"
)

// newMkcgoErr creates a new error from the given mkcgo_err_state
// and frees the state. If errst is nil, it returns nil.
func newMkcgoErr(msg string, errst C.mkcgo_err_state) error {
	if errst == nil {
		return nil
	}
	defer C.mkcgo_err_free(errst)
	oerrst := (*C.ossl_err_state)(unsafe.Pointer(errst))
	var b strings.Builder
	b.WriteString(msg)
	b.WriteString("\nopenssl error(s):")
	for i := range C.ERR_NUM_MAX {
		e := uint64(oerrst.code[i])
		if e == 0 {
			break
		}
		b.WriteByte('\n')
		var buf [256]byte
		ERR_error_string_n(e, unsafe.SliceData(buf[:]), len(buf))
		if termIdx := bytes.IndexByte(buf[:], 0); termIdx != -1 {
			b.Write(buf[:termIdx])
		} else {
			b.Write(buf[:])
		}
		if oerrst.file[i] == nil {
			// info not available
			continue
		}
		b.WriteString("\n\t")
		b.Write(cstrBytes(oerrst.file[i]))
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(int(oerrst.line[i])))
	}
	return errors.New(b.String())
}

// cstrBytes returns a byte slice containing the contents of the C string
// pointed to by p. The slice does not include the terminating null byte.
func cstrBytes(p *C.char) []byte {
	if p == nil {
		return nil
	}
	end := unsafe.Pointer(p)
	for *(*byte)(end) != 0 {
		end = unsafe.Add(end, 1)
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(p)), uintptr(end)-uintptr(unsafe.Pointer(p)))
}
