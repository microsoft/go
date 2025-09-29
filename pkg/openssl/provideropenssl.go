//go:build !cmd_go_bootstrap

package openssl

import (
	"crypto"
	"errors"
	"unsafe"

	"github.com/microsoft/go/pkg/openssl/internal/ossl"
)

// This file contains code specific to the built-in OpenSSL providers.

// _OSSL_MD5_CTX layout is taken from
// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/include/openssl/md5.h#L33.
type _OSSL_MD5_CTX struct {
	h      [4]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

func (d *_OSSL_MD5_CTX) UnmarshalBinary(b []byte) error {
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

func (d *_OSSL_MD5_CTX) AppendBinary(buf []byte) ([]byte, error) {
	buf = appendUint32(buf, d.h[0])
	buf = appendUint32(buf, d.h[1])
	buf = appendUint32(buf, d.h[2])
	buf = appendUint32(buf, d.h[3])
	buf = append(buf, d.x[:d.nx]...)
	buf = append(buf, make([]byte, len(d.x)-int(d.nx))...)
	buf = appendUint64(buf, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return buf, nil
}

// _OSSL_SHA_CTX layout is taken from
// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/include/openssl/sha.h#L34.
type _OSSL_SHA_CTX struct {
	h      [5]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

func (d *_OSSL_SHA_CTX) UnmarshalBinary(b []byte) error {
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

func (d *_OSSL_SHA_CTX) AppendBinary(buf []byte) ([]byte, error) {
	buf = appendUint32(buf, d.h[0])
	buf = appendUint32(buf, d.h[1])
	buf = appendUint32(buf, d.h[2])
	buf = appendUint32(buf, d.h[3])
	buf = appendUint32(buf, d.h[4])
	buf = append(buf, d.x[:d.nx]...)
	buf = append(buf, make([]byte, len(d.x)-int(d.nx))...)
	buf = appendUint64(buf, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return buf, nil
}

// _OSSL_SHA256_CTX layout is taken from
// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/include/openssl/sha.h#L51.
type _OSSL_SHA256_CTX struct {
	h      [8]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

func (d *_OSSL_SHA256_CTX) UnmarshalBinary(b []byte) error {
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b, d.h[5] = consumeUint32(b)
	b, d.h[6] = consumeUint32(b)
	b, d.h[7] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

func (d *_OSSL_SHA256_CTX) AppendBinary(buf []byte) ([]byte, error) {
	buf = appendUint32(buf, d.h[0])
	buf = appendUint32(buf, d.h[1])
	buf = appendUint32(buf, d.h[2])
	buf = appendUint32(buf, d.h[3])
	buf = appendUint32(buf, d.h[4])
	buf = appendUint32(buf, d.h[5])
	buf = appendUint32(buf, d.h[6])
	buf = appendUint32(buf, d.h[7])
	buf = append(buf, d.x[:d.nx]...)
	buf = append(buf, make([]byte, len(d.x)-int(d.nx))...)
	buf = appendUint64(buf, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return buf, nil
}

// _OSSL_SHA512_CTX layout is taken from
// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/include/openssl/sha.h#L95.
type _OSSL_SHA512_CTX struct {
	h      [8]uint64
	nl, nh uint64
	x      [128]byte
	nx     uint32
}

func (d *_OSSL_SHA512_CTX) UnmarshalBinary(b []byte) error {
	b, d.h[0] = consumeUint64(b)
	b, d.h[1] = consumeUint64(b)
	b, d.h[2] = consumeUint64(b)
	b, d.h[3] = consumeUint64(b)
	b, d.h[4] = consumeUint64(b)
	b, d.h[5] = consumeUint64(b)
	b, d.h[6] = consumeUint64(b)
	b, d.h[7] = consumeUint64(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = n << 3
	d.nh = n >> 61
	d.nx = uint32(n) % 128
	return nil
}

func (d *_OSSL_SHA512_CTX) AppendBinary(buf []byte) ([]byte, error) {
	buf = appendUint64(buf, d.h[0])
	buf = appendUint64(buf, d.h[1])
	buf = appendUint64(buf, d.h[2])
	buf = appendUint64(buf, d.h[3])
	buf = appendUint64(buf, d.h[4])
	buf = appendUint64(buf, d.h[5])
	buf = appendUint64(buf, d.h[6])
	buf = appendUint64(buf, d.h[7])
	buf = append(buf, d.x[:d.nx]...)
	buf = append(buf, make([]byte, len(d.x)-int(d.nx))...)
	buf = appendUint64(buf, d.nl>>3|d.nh<<61)
	return buf, nil
}

func getOSSLDigetsContext(ctx ossl.EVP_MD_CTX_PTR) unsafe.Pointer {
	switch vMajor {
	case 1:
		// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/crypto/evp/evp_local.h#L12.
		type mdCtx struct {
			_       [2]unsafe.Pointer
			_       uint32
			md_data unsafe.Pointer
		}
		return (*mdCtx)(unsafe.Pointer(ctx)).md_data
	case 3:
		// The EVP_MD_CTX memory layout has changed in OpenSSL 3
		// and the property holding the internal structure is no longer md_data but algctx.
		// https://github.com/openssl/openssl/blob/5675a5aaf6a2e489022bcfc18330dae9263e598e/crypto/evp/evp_local.h#L16.
		type mdCtx struct {
			_      [3]unsafe.Pointer
			_      uint32
			_      [3]unsafe.Pointer
			algctx unsafe.Pointer
		}
		return (*mdCtx)(unsafe.Pointer(ctx)).algctx
	default:
		panic(errUnsupportedVersion())
	}
}

var errHashStateInvalid = errors.New("openssl: can't retrieve hash state")

func osslHashAppendBinary(ctx ossl.EVP_MD_CTX_PTR, ch crypto.Hash, magic string, buf []byte) ([]byte, error) {
	algctx := getOSSLDigetsContext(ctx)
	if algctx == nil {
		return nil, errHashStateInvalid
	}
	buf = append(buf, magic...)
	switch ch {
	case crypto.MD5:
		d := (*_OSSL_MD5_CTX)(unsafe.Pointer(algctx))
		return d.AppendBinary(buf)
	case crypto.SHA1:
		d := (*_OSSL_SHA_CTX)(unsafe.Pointer(algctx))
		return d.AppendBinary(buf)
	case crypto.SHA224, crypto.SHA256:
		d := (*_OSSL_SHA256_CTX)(unsafe.Pointer(algctx))
		return d.AppendBinary(buf)
	case crypto.SHA384, crypto.SHA512_224, crypto.SHA512_256, crypto.SHA512:
		d := (*_OSSL_SHA512_CTX)(unsafe.Pointer(algctx))
		return d.AppendBinary(buf)
	default:
		panic("unsupported hash " + ch.String())
	}
}

func osslHashUnmarshalBinary(ctx ossl.EVP_MD_CTX_PTR, ch crypto.Hash, magic string, b []byte) error {
	algctx := getOSSLDigetsContext(ctx)
	if algctx == nil {
		return errHashStateInvalid
	}
	b = b[len(magic):]
	switch ch {
	case crypto.MD5:
		d := (*_OSSL_MD5_CTX)(unsafe.Pointer(algctx))
		return d.UnmarshalBinary(b)
	case crypto.SHA1:
		d := (*_OSSL_SHA_CTX)(unsafe.Pointer(algctx))
		return d.UnmarshalBinary(b)
	case crypto.SHA224, crypto.SHA256:
		d := (*_OSSL_SHA256_CTX)(unsafe.Pointer(algctx))
		return d.UnmarshalBinary(b)
	case crypto.SHA384, crypto.SHA512_224, crypto.SHA512_256, crypto.SHA512:
		d := (*_OSSL_SHA512_CTX)(unsafe.Pointer(algctx))
		return d.UnmarshalBinary(b)
	default:
		panic("unsupported hash " + ch.String())
	}
}
