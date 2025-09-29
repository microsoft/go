//go:build !cmd_go_bootstrap

package openssl

import (
	"crypto"
	"errors"
	"hash"
	"sync"
	"unsafe"

	"github.com/microsoft/go/pkg/openssl/internal/ossl"
)

func SupportsTLS1PRF() bool {
	switch vMajor {
	case 1:
		return vMinor >= 1
	case 3:
		_, err := fetchTLS1PRF3()
		return err == nil
	default:
		panic(errUnsupportedVersion())
	}
}

// TLS1PRF implements the TLS 1.0/1.1 pseudo-random function if h is nil,
// else it implements the TLS 1.2 pseudo-random function.
// The pseudo-random number will be written to result and will be of length len(result).
func TLS1PRF(result, secret, label, seed []byte, fh func() hash.Hash) error {
	var md ossl.EVP_MD_PTR
	if fh == nil {
		// TLS 1.0/1.1 PRF doesn't allow to specify the hash function,
		// it always uses MD5SHA1. If h is nil, then assume
		// that the caller wants to use TLS 1.0/1.1 PRF.
		// OpenSSL detects this case by checking if the hash
		// function is MD5SHA1.
		md = loadHash(crypto.MD5SHA1).md
	} else {
		h, err := hashFuncHash(fh)
		if err != nil {
			return err
		}
		md = hashToMD(h)
	}
	if md == nil {
		return errors.New("unsupported hash function")
	}

	switch vMajor {
	case 1:
		return tls1PRF1(result, secret, label, seed, md)
	case 3:
		return tls1PRF3(result, secret, label, seed, md)
	default:
		return errUnsupportedVersion()
	}
}

// tls1PRF1 implements TLS1PRF for OpenSSL 1 using the EVP_PKEY API.
func tls1PRF1(result, secret, label, seed []byte, md ossl.EVP_MD_PTR) error {
	checkMajorVersion(1)

	ctx, err := ossl.EVP_PKEY_CTX_new_id(ossl.EVP_PKEY_TLS1_PRF, nil)
	if err != nil {
		return err
	}
	defer func() {
		ossl.EVP_PKEY_CTX_free(ctx)
	}()

	if _, err := ossl.EVP_PKEY_derive_init(ctx); err != nil {
		return err
	}
	if _, err := ossl.EVP_PKEY_CTX_ctrl(ctx, -1,
		ossl.EVP_PKEY_OP_DERIVE,
		ossl.EVP_PKEY_CTRL_TLS_MD,
		0, unsafe.Pointer(md)); err != nil {
		return err
	}
	if _, err := ossl.EVP_PKEY_CTX_ctrl(ctx, -1,
		ossl.EVP_PKEY_OP_DERIVE,
		ossl.EVP_PKEY_CTRL_TLS_SECRET,
		int32(len(secret)), unsafe.Pointer(base(secret))); err != nil {
		return err
	}
	if _, err := ossl.EVP_PKEY_CTX_ctrl(ctx, -1,
		ossl.EVP_PKEY_OP_DERIVE,
		ossl.EVP_PKEY_CTRL_TLS_SEED,
		int32(len(label)), unsafe.Pointer(base(label))); err != nil {
		return err
	}
	if _, err := ossl.EVP_PKEY_CTX_ctrl(ctx, -1,
		ossl.EVP_PKEY_OP_DERIVE,
		ossl.EVP_PKEY_CTRL_TLS_SEED,
		int32(len(seed)), unsafe.Pointer(base(seed))); err != nil {
		return err
	}
	outLen := len(result)
	if _, err := ossl.EVP_PKEY_derive(ctx, base(result), &outLen); err != nil {
		return err
	}
	// The Go standard library expects TLS1PRF to return the requested number of bytes,
	// fail if it doesn't. While there is no known situation where this will happen,
	// EVP_PKEY_derive handles multiple algorithms and there could be a subtle mismatch
	// after more code changes in the future.
	if outLen != len(result) {
		return errors.New("tls1-prf: derived less bytes than requested")
	}
	return nil
}

// fetchTLS1PRF3 fetches the TLS1-PRF KDF algorithm.
// It is safe to call this function concurrently.
// The returned EVP_KDF_PTR shouldn't be freed.
var fetchTLS1PRF3 = sync.OnceValues(func() (ossl.EVP_KDF_PTR, error) {
	checkMajorVersion(3)

	kdf, err := ossl.EVP_KDF_fetch(nil, _OSSL_KDF_NAME_TLS1_PRF.ptr(), nil)
	if err != nil {
		return nil, err
	}
	return kdf, nil
})

// tls1PRF3 implements TLS1PRF for OpenSSL 3 using the EVP_KDF API.
func tls1PRF3(result, secret, label, seed []byte, md ossl.EVP_MD_PTR) error {
	checkMajorVersion(3)

	kdf, err := fetchTLS1PRF3()
	if err != nil {
		return err
	}
	ctx, err := ossl.EVP_KDF_CTX_new(kdf)
	if err != nil {
		return err
	}
	defer ossl.EVP_KDF_CTX_free(ctx)

	bld, err := newParamBuilder()
	if err != nil {
		return err
	}
	bld.addUTF8String(_OSSL_KDF_PARAM_DIGEST, ossl.EVP_MD_get0_name(md), 0)
	bld.addOctetString(_OSSL_KDF_PARAM_SECRET, secret)
	bld.addOctetString(_OSSL_KDF_PARAM_SEED, label)
	bld.addOctetString(_OSSL_KDF_PARAM_SEED, seed)
	params, err := bld.build()
	if err != nil {
		return err
	}
	defer ossl.OSSL_PARAM_free(params)

	if _, err := ossl.EVP_KDF_derive(ctx, base(result), len(result), params); err != nil {
		return err
	}
	return nil
}
