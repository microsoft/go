package ossl

/*
#include "zossl.h"
// go_hash_sum copies ctx into ctx2 and calls EVP_DigestFinal_ex using ctx2.
// This is necessary because Go hash.Hash mandates that Sum has no effect
// on the underlying stream. In particular it is OK to Sum, then Write more,
// then Sum again, and the second Sum acts as if the first didn't happen.
// It is written in C because Sum() tend to be in the hot path,
// and doing one cgo call instead of two is a significant performance win.
static inline int
go_hash_sum(const _EVP_MD_CTX_PTR ctx, _EVP_MD_CTX_PTR ctx2, unsigned char *out, mkcgo_err_state *_err_state)
{
	if (_mkcgo_EVP_MD_CTX_copy(ctx2, ctx, _err_state) != 1)
		return -1;
	if (_mkcgo_EVP_DigestFinal_ex(ctx2, out, NULL, _err_state) <= 0)
		return -2;
	return 1;
}
*/
import "C"
import (
	"unsafe"
)

func HashSum(ctx1, ctx2 EVP_MD_CTX_PTR, out []byte) error {
	var errst C.mkcgo_err_state
	if code := C.go_hash_sum(ctx1, ctx2, (*C.uchar)(unsafe.SliceData(out)), mkcgoNoEscape(&errst)); code != 1 {
		msg := "go_hash_sum"
		switch code {
		case -1:
			msg = "EVP_MD_CTX_copy"
		case -2:
			msg = "EVP_DigestFinal_ex"
		}
		return newMkcgoErr(msg, errst)
	}
	return nil
}
