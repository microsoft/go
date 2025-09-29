//go:build !cmd_go_bootstrap

package openssl

import (
	"crypto"
	"errors"
	"runtime"
	"unsafe"

	"github.com/microsoft/go/pkg/openssl/internal/ossl"
)

// This file contains code specific to the SymCrypt provider.

const (
	_SCOSSL_DIGEST_PARAM_STATE              cString = "state\x00"
	_SCOSSL_DIGEST_PARAM_RECOMPUTE_CHECKSUM cString = "recompute_checksum\x00"
)

const (
	_SYMCRYPT_BLOB_MAGIC = 0x636D7973 // "cysm" in little-endian

	_SymCryptBlobTypeHashState       = 0x100
	_SymCryptBlobTypeMd2State        = _SymCryptBlobTypeHashState + 1
	_SymCryptBlobTypeMd4State        = _SymCryptBlobTypeHashState + 2
	_SymCryptBlobTypeMd5State        = _SymCryptBlobTypeHashState + 3
	_SymCryptBlobTypeSha1State       = _SymCryptBlobTypeHashState + 4
	_SymCryptBlobTypeSha256State     = _SymCryptBlobTypeHashState + 5
	_SymCryptBlobTypeSha384State     = _SymCryptBlobTypeHashState + 6
	_SymCryptBlobTypeSha512State     = _SymCryptBlobTypeHashState + 7
	_SymCryptBlobTypeSha3_256State   = _SymCryptBlobTypeHashState + 8
	_SymCryptBlobTypeSha3_384State   = _SymCryptBlobTypeHashState + 9
	_SymCryptBlobTypeSha3_512State   = _SymCryptBlobTypeHashState + 10
	_SymCryptBlobTypeSha224State     = _SymCryptBlobTypeHashState + 11
	_SymCryptBlobTypeSha512_224State = _SymCryptBlobTypeHashState + 12
	_SymCryptBlobTypeSha512_256State = _SymCryptBlobTypeHashState + 13
	_SymCryptBlobTypeSha3_224State   = _SymCryptBlobTypeHashState + 14

	_SYMCRYPT_MD5_STATE_EXPORT_SIZE    = uint32(unsafe.Sizeof(_SYMCRYPT_MD5_STATE_EXPORT_BLOB{}))
	_SYMCRYPT_SHA1_STATE_EXPORT_SIZE   = uint32(unsafe.Sizeof(_SYMCRYPT_SHA1_STATE_EXPORT_BLOB{}))
	_SYMCRYPT_SHA256_STATE_EXPORT_SIZE = uint32(unsafe.Sizeof(_SYMCRYPT_SHA256_STATE_EXPORT_BLOB{}))
	_SYMCRYPT_SHA512_STATE_EXPORT_SIZE = uint32(unsafe.Sizeof(_SYMCRYPT_SHA512_STATE_EXPORT_BLOB{}))
)

type _SYMCRYPT_BLOB_HEADER struct {
	magic uint32
	size  uint32
	_type uint32
}

type _SYMCRYPT_BLOB_TRAILER struct {
	checksum [8]uint8
}

// _UINT64 is a 64-bit unsigned integer, stored in native endianess.
// It is used to represent a SymCrypt UINT64 type without making the
// parent struct 8-byte aligned, given that the Windows ABI makes
// the struct 4-byte aligned.
type _UINT64 [2]uint32

func newUINT64(v uint64) _UINT64 {
	var u _UINT64
	if isBigEndian {
		u[0], u[1] = uint32(v>>32), uint32(v)
	} else {
		u[0], u[1] = uint32(v), uint32(v>>32)
	}
	return u
}

func (u *_UINT64) uint64() uint64 {
	if isBigEndian {
		return uint64(u[0])<<32 | (uint64(u[1]))
	}
	return uint64(u[0]) | (uint64(u[1]) << 32)
}

// symCryptAppendBinary appends the binary representation of a SymCrypt state
// to the given destination slice.
func symCryptAppendBinary(dst, chain, buffer []byte, blength _UINT64) []byte {
	length := blength.uint64()
	var nx uint64
	if len(buffer) <= 64 {
		nx = length & 0x3f
	} else {
		nx = length & 0x7f
	}
	dst = append(dst, chain...)
	dst = append(dst, buffer[:nx]...)
	dst = append(dst, make([]byte, len(buffer)-int(nx))...)
	dst = appendUint64(dst, length)
	return dst
}

// symCryptUnmarshalBinary unmarshals the binary representation of a SymCrypt state
// from the given source slice. It returns the length of the data.
func symCryptUnmarshalBinary(d []byte, chain, buffer []byte) _UINT64 {
	copy(chain[:], d)
	d = d[len(chain):]
	copy(buffer[:], d)
	d = d[len(buffer):]
	_, length := consumeUint64(d)
	return newUINT64(length)
}

// swapEndianessUint32 swaps the endianness of the given byte slice
// in place. It assumes the slice is a backup of a 32-bit integer array.
func swapEndianessUint32(d []uint8) {
	for i := 0; i < len(d); i += 4 {
		d[i], d[i+3] = d[i+3], d[i]
		d[i+1], d[i+2] = d[i+2], d[i+1]
	}

}

type _SYMCRYPT_MD5_STATE_EXPORT_BLOB struct {
	header _SYMCRYPT_BLOB_HEADER
	chain  [16]uint8 // little endian
	length _UINT64   // native endian
	buffer [64]uint8
	_      [8]uint8 // reserved
	_      _SYMCRYPT_BLOB_TRAILER
}

func (b *_SYMCRYPT_MD5_STATE_EXPORT_BLOB) appendBinary(d []byte) ([]byte, error) {
	// b.chain is little endian, but Go expects big endian,
	// we need to swap the bytes.
	swapEndianessUint32(b.chain[:])
	return symCryptAppendBinary(d, b.chain[:], b.buffer[:], b.length), nil
}

func (b *_SYMCRYPT_MD5_STATE_EXPORT_BLOB) unmarshalBinary(d []byte) {
	b.length = symCryptUnmarshalBinary(d, b.chain[:], b.buffer[:])
	swapEndianessUint32(b.chain[:])
}

type _SYMCRYPT_SHA1_STATE_EXPORT_BLOB struct {
	header _SYMCRYPT_BLOB_HEADER
	chain  [20]uint8 // big endian
	length _UINT64   // native endian
	buffer [64]uint8
	_      [8]uint8 // reserved
	_      _SYMCRYPT_BLOB_TRAILER
}

func (b *_SYMCRYPT_SHA1_STATE_EXPORT_BLOB) appendBinary(d []byte) ([]byte, error) {
	return symCryptAppendBinary(d, b.chain[:], b.buffer[:], b.length), nil
}

func (b *_SYMCRYPT_SHA1_STATE_EXPORT_BLOB) unmarshalBinary(d []byte) {
	b.length = symCryptUnmarshalBinary(d, b.chain[:], b.buffer[:])
}

type _SYMCRYPT_SHA256_STATE_EXPORT_BLOB struct {
	header _SYMCRYPT_BLOB_HEADER
	chain  [32]uint8 // big endian
	length _UINT64   // native endian
	buffer [64]uint8
	_      [8]uint8 // reserved
	_      _SYMCRYPT_BLOB_TRAILER
}

func (b *_SYMCRYPT_SHA256_STATE_EXPORT_BLOB) appendBinary(d []byte) ([]byte, error) {
	return symCryptAppendBinary(d, b.chain[:], b.buffer[:], b.length), nil
}

func (b *_SYMCRYPT_SHA256_STATE_EXPORT_BLOB) unmarshalBinary(d []byte) {
	b.length = symCryptUnmarshalBinary(d, b.chain[:], b.buffer[:])
}

type _SYMCRYPT_SHA512_STATE_EXPORT_BLOB struct {
	header  _SYMCRYPT_BLOB_HEADER
	chain   [64]uint8 // big endian
	lengthL _UINT64   // native endian
	lengthH _UINT64   // native endian
	buffer  [128]uint8
	_       [8]uint8 // reserved
	_       _SYMCRYPT_BLOB_TRAILER
}

func (b *_SYMCRYPT_SHA512_STATE_EXPORT_BLOB) appendBinary(d []byte) ([]byte, error) {
	if b.lengthH.uint64() != 0 {
		return nil, errors.New("exporting state with more than 2^63-1 bytes of data is not supported")
	}
	return symCryptAppendBinary(d, b.chain[:], b.buffer[:], b.lengthL), nil
}

func (b *_SYMCRYPT_SHA512_STATE_EXPORT_BLOB) unmarshalBinary(d []byte) {
	b.lengthL = symCryptUnmarshalBinary(d, b.chain[:], b.buffer[:])
}

func symCryptHashAppendBinary(ctx ossl.EVP_MD_CTX_PTR, ch crypto.Hash, magic string, buf []byte) ([]byte, error) {
	size, typ := symCryptHashStateInfo(ch)
	state := make([]byte, size, _SYMCRYPT_SHA512_STATE_EXPORT_SIZE) // 512 is the largest size
	var pinner runtime.Pinner
	pinner.Pin(&state[0])
	defer pinner.Unpin()
	params := [2]ossl.OSSL_PARAM{
		ossl.OSSL_PARAM_construct_octet_string(_SCOSSL_DIGEST_PARAM_STATE.ptr(), unsafe.Pointer(&state[0]), len(state)),
		ossl.OSSL_PARAM_construct_end(),
	}
	if _, err := ossl.EVP_MD_CTX_get_params(ctx, (ossl.OSSL_PARAM_PTR)(unsafe.Pointer(&params[0]))); err != nil {
		return nil, err
	}
	if !ossl.OSSL_PARAM_modified(&params[0]) {
		return nil, errors.New("EVP_MD_CTX_get_params did not retrieve the state")
	}

	header := (*_SYMCRYPT_BLOB_HEADER)(unsafe.Pointer(&state[0]))
	if header.magic != _SYMCRYPT_BLOB_MAGIC {
		return nil, errors.New("invalid blob magic")
	}
	if header.size != size {
		return nil, errors.New("invalid blob size")
	}
	if header._type != typ {
		return nil, errors.New("invalid blob type")
	}

	buf = append(buf, magic...)
	switch ch {
	case crypto.MD5:
		blob := (*_SYMCRYPT_MD5_STATE_EXPORT_BLOB)(unsafe.Pointer(&state[0]))
		return blob.appendBinary(buf)
	case crypto.SHA1:
		blob := (*_SYMCRYPT_SHA1_STATE_EXPORT_BLOB)(unsafe.Pointer(&state[0]))
		return blob.appendBinary(buf)
	case crypto.SHA224, crypto.SHA256:
		blob := (*_SYMCRYPT_SHA256_STATE_EXPORT_BLOB)(unsafe.Pointer(&state[0]))
		return blob.appendBinary(buf)
	case crypto.SHA384, crypto.SHA512_224, crypto.SHA512_256, crypto.SHA512:
		blob := (*_SYMCRYPT_SHA512_STATE_EXPORT_BLOB)(unsafe.Pointer(&state[0]))
		return blob.appendBinary(buf)
	default:
		panic("unsupported hash " + ch.String())
	}
}

func symCryptHashUnmarshalBinary(ctx ossl.EVP_MD_CTX_PTR, ch crypto.Hash, magic string, b []byte) error {
	size, typ := symCryptHashStateInfo(ch)
	hdr := _SYMCRYPT_BLOB_HEADER{
		magic: _SYMCRYPT_BLOB_MAGIC,
		size:  size,
		_type: typ,
	}
	var blobPtr unsafe.Pointer
	b = b[len(magic):]
	switch ch {
	case crypto.MD5:
		var blob _SYMCRYPT_MD5_STATE_EXPORT_BLOB
		blobPtr = unsafe.Pointer(&blob)
		blob.header = hdr
		blob.unmarshalBinary(b)
	case crypto.SHA1:
		var blob _SYMCRYPT_SHA1_STATE_EXPORT_BLOB
		blobPtr = unsafe.Pointer(&blob)
		blob.header = hdr
		blob.unmarshalBinary(b)
	case crypto.SHA224, crypto.SHA256:
		var blob _SYMCRYPT_SHA256_STATE_EXPORT_BLOB
		blobPtr = unsafe.Pointer(&blob)
		blob.header = hdr
		blob.unmarshalBinary(b)
	case crypto.SHA384, crypto.SHA512_224, crypto.SHA512_256, crypto.SHA512:
		var blob _SYMCRYPT_SHA512_STATE_EXPORT_BLOB
		blobPtr = unsafe.Pointer(&blob)
		blob.header = hdr
		blob.unmarshalBinary(b)
	default:
		panic("unsupported hash " + ch.String())
	}
	var checksum int32 = 1
	var pinner runtime.Pinner
	pinner.Pin(blobPtr)
	pinner.Pin(&checksum)
	defer pinner.Unpin()
	params := [3]ossl.OSSL_PARAM{
		ossl.OSSL_PARAM_construct_octet_string(_SCOSSL_DIGEST_PARAM_STATE.ptr(), blobPtr, int(hdr.size)),
		ossl.OSSL_PARAM_construct_int32(_SCOSSL_DIGEST_PARAM_RECOMPUTE_CHECKSUM.ptr(), &checksum),
		ossl.OSSL_PARAM_construct_end(),
	}
	_, err := ossl.EVP_MD_CTX_set_params(ctx, (ossl.OSSL_PARAM_PTR)(unsafe.Pointer(&params[0])))
	return err
}

func symCryptHashStateInfo(ch crypto.Hash) (size, typ uint32) {
	switch ch {
	case crypto.MD5:
		return _SYMCRYPT_MD5_STATE_EXPORT_SIZE, _SymCryptBlobTypeMd5State
	case crypto.SHA1:
		return _SYMCRYPT_SHA1_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha1State
	case crypto.SHA224:
		return _SYMCRYPT_SHA256_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha224State
	case crypto.SHA256:
		return _SYMCRYPT_SHA256_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha256State
	case crypto.SHA384:
		return _SYMCRYPT_SHA512_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha384State
	case crypto.SHA512_224:
		return _SYMCRYPT_SHA512_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha512_224State
	case crypto.SHA512_256:
		return _SYMCRYPT_SHA512_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha512_256State
	case crypto.SHA512:
		return _SYMCRYPT_SHA512_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha512State
	default:
		panic("unsupported hash " + ch.String())
	}
}

// isSymCryptHashStateSerializable checks if the SymCrypt hash state is serializable.
func isSymCryptHashStateSerializable(md ossl.EVP_MD_PTR) bool {
	ctx, err := ossl.EVP_MD_CTX_new()
	if err != nil {
		return false
	}
	defer ossl.EVP_MD_CTX_free(ctx)
	if _, err := ossl.EVP_DigestInit_ex(ctx, md, nil); err != nil {
		return false
	}
	params, err := ossl.EVP_MD_CTX_gettable_params(ctx)
	if err != nil {
		return false
	}
	if _, err = ossl.OSSL_PARAM_locate_const(params, _SCOSSL_DIGEST_PARAM_STATE.ptr()); err != nil {
		return false
	}
	params, err = ossl.EVP_MD_CTX_settable_params(ctx)
	if err != nil {
		return false
	}
	if _, err = ossl.OSSL_PARAM_locate_const(params, _SCOSSL_DIGEST_PARAM_STATE.ptr()); err != nil {
		return false
	}
	if _, err = ossl.OSSL_PARAM_locate_const(params, _SCOSSL_DIGEST_PARAM_RECOMPUTE_CHECKSUM.ptr()); err != nil {
		return false
	}
	return true
}
