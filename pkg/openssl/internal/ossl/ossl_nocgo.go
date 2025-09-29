//go:build !cgo

package ossl

import "unsafe"

// HashSum copies ctx1 into ctx2 and calls EVP_DigestFinal_ex using ctx2.
// This is necessary because Go hash.Hash mandates that Sum has no effect
// on the underlying stream. In particular it is OK to Sum, then Write more,
// then Sum again, and the second Sum acts as if the first didn't happen.
func HashSum(ctx1, ctx2 EVP_MD_CTX_PTR, out []byte) error {
	// Clear any existing errors
	ERR_clear_error()

	// Copy ctx1 to ctx2 using EVP_MD_CTX_copy_ex
	code, err := EVP_MD_CTX_copy_ex(ctx2, ctx1)
	if err != nil {
		return err
	}
	if code != 1 {
		return newMkcgoErr("EVP_MD_CTX_copy_ex", nil)
	}

	// Finalize the hash using ctx2
	code, err = EVP_DigestFinal_ex(ctx2, (*byte)(unsafe.SliceData(out)), nil)
	if err != nil {
		return err
	}
	if code <= 0 {
		return newMkcgoErr("EVP_DigestFinal_ex", nil)
	}

	return nil
}
