//go:build !cmd_go_bootstrap

package openssl

import (
	"errors"
	"hash"
	"io"
	"runtime"
	"sync"
	"unsafe"

	"github.com/microsoft/go/pkg/openssl/internal/ossl"
)

// SupprtHKDF reports whether the current OpenSSL version supports HKDF.
func SupportsHKDF() bool {
	switch vMajor {
	case 1:
		return versionAtOrAbove(1, 1, 1)
	case 3:
		_, err := fetchHKDF3()
		return err == nil
	default:
		panic(errUnsupportedVersion())
	}
}

// SupprtsTLS13KDF reports whether the current OpenSSL version supports TLS13-KDF.
func SupportsTLS13KDF() bool {
	switch vMajor {
	case 1:
		return false
	case 3:
		// TLS13-KDF is available in OpenSSL 3.0.0 and later.
		_, err := fetchTLS13_KDF()
		return err == nil
	default:
		panic(errUnsupportedVersion())
	}
}

func newHKDFCtx1(md ossl.EVP_MD_PTR, mode int32, secret, salt, pseudorandomKey, info []byte) (ctx ossl.EVP_PKEY_CTX_PTR, err error) {
	checkMajorVersion(1)

	ctx, err = ossl.EVP_PKEY_CTX_new_id(ossl.EVP_PKEY_HKDF, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			ossl.EVP_PKEY_CTX_free(ctx)
		}
	}()

	if _, err := ossl.EVP_PKEY_derive_init(ctx); err != nil {
		return ctx, err
	}

	ctrlSlice := func(ctrl int32, data []byte) bool {
		if err != nil {
			return false
		}
		if len(data) == 0 {
			return true // No data to set.
		}
		_, err = ossl.EVP_PKEY_CTX_ctrl(ctx, -1, ossl.EVP_PKEY_OP_DERIVE, ctrl, int32(len(data)), unsafe.Pointer(base(data)))
		return err == nil
	}

	if _, err := ossl.EVP_PKEY_CTX_ctrl(ctx, -1, ossl.EVP_PKEY_OP_DERIVE, ossl.EVP_PKEY_CTRL_HKDF_MODE, mode, nil); err != nil {
		return ctx, err
	}
	if _, err := ossl.EVP_PKEY_CTX_ctrl(ctx, -1, ossl.EVP_PKEY_OP_DERIVE, ossl.EVP_PKEY_CTRL_HKDF_MD, 0, unsafe.Pointer(md)); err != nil {
		return ctx, err
	}
	if ctrlSlice(ossl.EVP_PKEY_CTRL_HKDF_KEY, secret) &&
		ctrlSlice(ossl.EVP_PKEY_CTRL_HKDF_SALT, salt) &&
		ctrlSlice(ossl.EVP_PKEY_CTRL_HKDF_KEY, pseudorandomKey) &&
		ctrlSlice(ossl.EVP_PKEY_CTRL_HKDF_INFO, info) {
		return ctx, err
	}
	return ctx, nil
}

type hkdf1 struct {
	ctx ossl.EVP_PKEY_CTX_PTR

	hashLen int
	buf     []byte
}

func (c *hkdf1) finalize() {
	if c.ctx != nil {
		ossl.EVP_PKEY_CTX_free(c.ctx)
	}
}

func (c *hkdf1) Read(p []byte) (int, error) {
	defer runtime.KeepAlive(c)

	// EVP_PKEY_derive doesn't support incremental output, each call
	// derives the key from scratch and returns the requested bytes.
	// To implement io.Reader, we need to ask for len(c.buf) + len(p)
	// bytes and copy the last derived len(p) bytes to p.
	// We use c.buf to know how many bytes we've already derived and
	// to avoid allocating the whole output buffer on each call.
	prevLen := len(c.buf)
	needLen := len(p)
	remains := 255*c.hashLen - prevLen
	// Check whether enough data can be generated.
	if remains < needLen {
		return 0, errors.New("hkdf: entropy limit reached")
	}
	c.buf = append(c.buf, make([]byte, needLen)...)
	outLen := prevLen + needLen
	if _, err := ossl.EVP_PKEY_derive(c.ctx, base(c.buf), &outLen); err != nil {
		return 0, err
	}
	n := copy(p, c.buf[prevLen:outLen])
	return n, nil
}

// hkdfAllZerosSalt is a preallocated buffer of zeros used in ExtractHKDF().
// The size should be kept as large as the output length of any hash algorithm
// used with HKDF.
var hkdfAllZerosSalt [64]byte

// ExtractHDKF implements the HDKF extract step.
// If salt is nil, then this function replaces it internally with a buffer of
// zeros whose length equals the output length of the specified hash algorithm.
func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	if !SupportsHKDF() {
		return nil, errUnsupportedVersion()
	}

	md, err := hashFuncToMD(h)
	if err != nil {
		return nil, err
	}

	// If calling code specifies nil salt, replace it with a buffer of hashLen
	// zeros, as specified in RFC 5896 and as OpenSSL EVP_KDF-HKDF documentation
	// instructs. Take a slice of a preallocated buffer to avoid allocating new
	// buffer per call, but fall back to allocating a buffer if preallocated
	// buffer is not large enough.
	if salt == nil {
		hlen := h().Size()
		if hlen > len(hkdfAllZerosSalt) {
			salt = make([]byte, hlen)
		} else {
			salt = hkdfAllZerosSalt[:hlen]
		}
	}

	switch vMajor {
	case 1:
		ctx, err := newHKDFCtx1(md, ossl.EVP_KDF_HKDF_MODE_EXTRACT_ONLY, secret, salt, nil, nil)
		if err != nil {
			return nil, err
		}
		defer ossl.EVP_PKEY_CTX_free(ctx)
		var keylen int
		if _, err := ossl.EVP_PKEY_derive(ctx, nil, &keylen); err != nil {
			return nil, err
		}
		out := make([]byte, keylen)
		if _, err := ossl.EVP_PKEY_derive(ctx, base(out), &keylen); err != nil {
			return nil, err
		}
		return out[:keylen], nil
	case 3:
		ctx, err := newHKDFCtx3(md, ossl.EVP_KDF_HKDF_MODE_EXTRACT_ONLY, secret, salt, nil, nil)
		if err != nil {
			return nil, err
		}
		defer ossl.EVP_KDF_CTX_free(ctx)
		size, err := ossl.EVP_KDF_CTX_get_kdf_size(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]byte, size)
		if _, err := ossl.EVP_KDF_derive(ctx, base(out), len(out), nil); err != nil {
			return nil, err
		}
		return out, nil
	default:
		panic(errUnsupportedVersion())
	}
}

// ExpandHKDFOneShot derives a key from the given hash, key, and optional context info.
func ExpandHKDFOneShot(h func() hash.Hash, pseudorandomKey, info []byte, keyLength int) ([]byte, error) {
	if !SupportsHKDF() {
		return nil, errUnsupportedVersion()
	}

	md, err := hashFuncToMD(h)
	if err != nil {
		return nil, err
	}

	out := make([]byte, keyLength)
	switch vMajor {
	case 1:
		ctx, err := newHKDFCtx1(md, ossl.EVP_KDF_HKDF_MODE_EXPAND_ONLY, nil, nil, pseudorandomKey, info)
		if err != nil {
			return nil, err
		}
		defer ossl.EVP_PKEY_CTX_free(ctx)
		keylen := keyLength
		if _, err := ossl.EVP_PKEY_derive(ctx, base(out), &keylen); err != nil {
			return nil, err
		}
	case 3:
		ctx, err := newHKDFCtx3(md, ossl.EVP_KDF_HKDF_MODE_EXPAND_ONLY, nil, nil, pseudorandomKey, info)
		if err != nil {
			return nil, err
		}
		defer ossl.EVP_KDF_CTX_free(ctx)
		if _, err := ossl.EVP_KDF_derive(ctx, base(out), keyLength, nil); err != nil {
			return nil, err
		}
	default:
		panic(errUnsupportedVersion())
	}
	return out, nil
}

// ExpandTLS13KDF derives a key from the given hash, key, label and context. It will use
// "TLS13-KDF" algorithm to do so.
func ExpandTLS13KDF(h func() hash.Hash, pseudorandomKey, label, context []byte, keyLength int) ([]byte, error) {
	if !SupportsTLS13KDF() {
		return nil, errUnsupportedVersion()
	}

	md, err := hashFuncToMD(h)
	if err != nil {
		return nil, err
	}

	out := make([]byte, keyLength)

	ctx, err := newTLS13KDFExpandCtx3(md, label, context, pseudorandomKey)
	if err != nil {
		return nil, err
	}
	defer ossl.EVP_KDF_CTX_free(ctx)
	if _, err := ossl.EVP_KDF_derive(ctx, base(out), keyLength, nil); err != nil {
		return nil, err
	}
	return out, nil
}

func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte) (io.Reader, error) {
	if !SupportsHKDF() {
		return nil, errUnsupportedVersion()
	}

	md, err := hashFuncToMD(h)
	if err != nil {
		return nil, err
	}

	size := int(ossl.EVP_MD_get_size(md))

	switch vMajor {
	case 1:
		ctx, err := newHKDFCtx1(md, ossl.EVP_KDF_HKDF_MODE_EXPAND_ONLY, nil, nil, pseudorandomKey, info)
		if err != nil {
			return nil, err
		}
		c := &hkdf1{ctx: ctx, hashLen: size}
		runtime.SetFinalizer(c, (*hkdf1).finalize)
		return c, nil
	case 3:
		ctx, err := newHKDFCtx3(md, ossl.EVP_KDF_HKDF_MODE_EXPAND_ONLY, nil, nil, pseudorandomKey, info)
		if err != nil {
			return nil, err
		}
		c := &hkdf3{ctx: ctx, hashLen: size}
		runtime.SetFinalizer(c, (*hkdf3).finalize)
		return c, nil
	default:
		panic(errUnsupportedVersion())
	}
}

type hkdf3 struct {
	ctx ossl.EVP_KDF_CTX_PTR

	hashLen int
	buf     []byte
}

func (c *hkdf3) finalize() {
	if c.ctx != nil {
		ossl.EVP_KDF_CTX_free(c.ctx)
	}
}

// fetchTLS13_KDF fetches the TLS13-KDF algorithm.
// It is safe to call this function concurrently.
// The returned EVP_KDF_PTR shouldn't be freed.
var fetchTLS13_KDF = sync.OnceValues(func() (ossl.EVP_KDF_PTR, error) {
	checkMajorVersion(3)

	kdf, err := ossl.EVP_KDF_fetch(nil, _OSSL_KDF_NAME_TLS13_KDF.ptr(), nil)
	if err != nil {
		return nil, err
	}
	return kdf, nil
})

// newTLS13KDFExpandCtx3 fetches the "TLS13-KDF" for TLS 1.3 handshakes.
func newTLS13KDFExpandCtx3(md ossl.EVP_MD_PTR, label, context, pseudorandomKey []byte) (_ ossl.EVP_KDF_CTX_PTR, err error) {
	checkMajorVersion(3)

	kdf, err := fetchTLS13_KDF()
	if err != nil {
		return nil, err
	}

	ctx, err := ossl.EVP_KDF_CTX_new(kdf)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			ossl.EVP_KDF_CTX_free(ctx)
		}
	}()

	bld, err := newParamBuilder()
	if err != nil {
		return ctx, err
	}
	bld.addUTF8String(_OSSL_KDF_PARAM_DIGEST, ossl.EVP_MD_get0_name(md), 0)
	bld.addInt32(_OSSL_KDF_PARAM_MODE, int32(ossl.EVP_KDF_HKDF_MODE_EXPAND_ONLY))
	bld.addOctetString(_OSSL_KDF_PARAM_PREFIX, []byte("tls13 "))
	bld.addOctetString(_OSSL_KDF_PARAM_LABEL, label)
	bld.addOctetString(_OSSL_KDF_PARAM_DATA, context)
	if len(pseudorandomKey) > 0 {
		bld.addOctetString(_OSSL_KDF_PARAM_KEY, pseudorandomKey)
	}

	params, err := bld.build()
	if err != nil {
		return ctx, err
	}
	defer ossl.OSSL_PARAM_free(params)

	if _, err := ossl.EVP_KDF_CTX_set_params(ctx, params); err != nil {
		return ctx, err
	}
	return ctx, nil
}

// fetchHKDF3 fetches the HKDF algorithm.
// It is safe to call this function concurrently.
// The returned EVP_KDF_PTR shouldn't be freed.
var fetchHKDF3 = sync.OnceValues(func() (ossl.EVP_KDF_PTR, error) {
	checkMajorVersion(3)

	kdf, err := ossl.EVP_KDF_fetch(nil, _OSSL_KDF_NAME_HKDF.ptr(), nil)
	if err != nil {
		return nil, err
	}
	return kdf, nil
})

// newHKDFCtx3 implements HKDF for OpenSSL 3 using the EVP_KDF API.
func newHKDFCtx3(md ossl.EVP_MD_PTR, mode int32, secret, salt, pseudorandomKey, info []byte) (_ ossl.EVP_KDF_CTX_PTR, err error) {
	checkMajorVersion(3)

	kdf, err := fetchHKDF3()
	if err != nil {
		return nil, err
	}
	ctx, err := ossl.EVP_KDF_CTX_new(kdf)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			ossl.EVP_KDF_CTX_free(ctx)
		}
	}()

	bld, err := newParamBuilder()
	if err != nil {
		return ctx, err
	}
	bld.addUTF8String(_OSSL_KDF_PARAM_DIGEST, ossl.EVP_MD_get0_name(md), 0)
	bld.addInt32(_OSSL_KDF_PARAM_MODE, int32(mode))
	if len(secret) > 0 {
		bld.addOctetString(_OSSL_KDF_PARAM_KEY, secret)
	}
	if len(salt) > 0 {
		bld.addOctetString(_OSSL_KDF_PARAM_SALT, salt)
	}
	if len(pseudorandomKey) > 0 {
		bld.addOctetString(_OSSL_KDF_PARAM_KEY, pseudorandomKey)
	}
	if len(info) > 0 {
		bld.addOctetString(_OSSL_KDF_PARAM_INFO, info)
	}
	params, err := bld.build()
	if err != nil {
		return ctx, err
	}
	defer ossl.OSSL_PARAM_free(params)

	if _, err := ossl.EVP_KDF_CTX_set_params(ctx, params); err != nil {
		return ctx, err
	}
	return ctx, nil
}

func (c *hkdf3) Read(p []byte) (int, error) {
	defer runtime.KeepAlive(c)

	// EVP_KDF_derive doesn't support incremental output, each call
	// derives the key from scratch and returns the requested bytes.
	// To implement io.Reader, we need to ask for len(c.buf) + len(p)
	// bytes and copy the last derived len(p) bytes to p.
	// We use c.buf to know how many bytes we've already derived and
	// to avoid allocating the whole output buffer on each call.
	prevLen := len(c.buf)
	needLen := len(p)
	remains := 255*c.hashLen - prevLen
	// Check whether enough data can be generated.
	if remains < needLen {
		return 0, errors.New("hkdf: entropy limit reached")
	}
	c.buf = append(c.buf, make([]byte, needLen)...)
	outLen := prevLen + needLen
	if _, err := ossl.EVP_KDF_derive(c.ctx, base(c.buf), outLen, nil); err != nil {
		return 0, err
	}
	n := copy(p, c.buf[prevLen:outLen])
	return n, nil
}
