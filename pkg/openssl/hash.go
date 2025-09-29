//go:build !cmd_go_bootstrap

package openssl

import (
	"crypto"
	"errors"
	"hash"
	"runtime"
	"strconv"
	"sync"
	"unsafe"

	"github.com/microsoft/go/pkg/openssl/internal/ossl"
)

const (
	magicMD5     = "md5\x01"
	magic1       = "sha\x01"
	magic224     = "sha\x02"
	magic256     = "sha\x03"
	magic384     = "sha\x04"
	magic512_224 = "sha\x05"
	magic512_256 = "sha\x06"
	magic512     = "sha\x07"

	marshaledSizeMD5 = len(magicMD5) + 4*4 + 64 + 8  // from crypto/md5
	marshaledSize1   = len(magic1) + 5*4 + 64 + 8    // from crypto/sha1
	marshaledSize256 = len(magic256) + 8*4 + 64 + 8  // from crypto/sha256
	marshaledSize512 = len(magic512) + 8*8 + 128 + 8 // from crypto/sha512
)

// maxHashSize is the size of SHA52 and SHA3_512, the largest hashes we support.
const maxHashSize = 64

func hashOneShot(ch crypto.Hash, p []byte, sum []byte) bool {
	_, err := ossl.EVP_Digest(pbaseNeverEmpty(p), len(p), base(sum), nil, loadHash(ch).md, nil)
	return err == nil
}

func MD4(p []byte) (sum [16]byte) {
	if !hashOneShot(crypto.MD4, p, sum[:]) {
		panic("openssl: MD4 failed")
	}
	return
}

func MD5(p []byte) (sum [16]byte) {
	if !hashOneShot(crypto.MD5, p, sum[:]) {
		panic("openssl: MD5 failed")
	}
	return
}

func SHA1(p []byte) (sum [20]byte) {
	if !hashOneShot(crypto.SHA1, p, sum[:]) {
		panic("openssl: SHA1 failed")
	}
	return
}

func SHA224(p []byte) (sum [28]byte) {
	if !hashOneShot(crypto.SHA224, p, sum[:]) {
		panic("openssl: SHA224 failed")
	}
	return
}

func SHA256(p []byte) (sum [32]byte) {
	if !hashOneShot(crypto.SHA256, p, sum[:]) {
		panic("openssl: SHA256 failed")
	}
	return
}

func SHA384(p []byte) (sum [48]byte) {
	if !hashOneShot(crypto.SHA384, p, sum[:]) {
		panic("openssl: SHA384 failed")
	}
	return
}

func SHA512(p []byte) (sum [64]byte) {
	if !hashOneShot(crypto.SHA512, p, sum[:]) {
		panic("openssl: SHA512 failed")
	}
	return
}

func SHA512_224(p []byte) (sum [28]byte) {
	if !hashOneShot(crypto.SHA512_224, p, sum[:]) {
		panic("openssl: SHA512 failed")
	}
	return
}

func SHA512_256(p []byte) (sum [32]byte) {
	if !hashOneShot(crypto.SHA512_256, p, sum[:]) {
		panic("openssl: SHA512_256 failed")
	}
	return
}

// cacheHashSupported is a cache of crypto.Hash support.
var cacheHashSupported sync.Map

// SupportsHash reports whether the current OpenSSL version supports the given hash.
func SupportsHash(h crypto.Hash) bool {
	if v, ok := cacheHashSupported.Load(h); ok {
		return v.(bool)
	}
	alg := loadHash(h)
	if alg == nil {
		cacheHashSupported.Store(h, false)
		return false
	}
	// EVP_MD objects can be non-nil even when they can't be used
	// in a EVP_MD_CTX, e.g. MD5 in FIPS mode. We need to prove
	// if they can be used by passing them to a EVP_MD_CTX.
	var supported bool
	if ctx, _ := ossl.EVP_MD_CTX_new(); ctx != nil {
		_, err := ossl.EVP_DigestInit_ex(ctx, alg.md, nil)
		supported = err == nil
		ossl.EVP_MD_CTX_free(ctx)
	}
	cacheHashSupported.Store(h, supported)
	return supported
}

func SHA3_224(p []byte) (sum [28]byte) {
	if !hashOneShot(crypto.SHA3_224, p, sum[:]) {
		panic("openssl: SHA3_224 failed")
	}
	return
}

func SHA3_256(p []byte) (sum [32]byte) {
	if !hashOneShot(crypto.SHA3_256, p, sum[:]) {
		panic("openssl: SHA3_256 failed")
	}
	return
}

func SHA3_384(p []byte) (sum [48]byte) {
	if !hashOneShot(crypto.SHA3_384, p, sum[:]) {
		panic("openssl: SHA3_384 failed")
	}
	return
}

func SHA3_512(p []byte) (sum [64]byte) {
	if !hashOneShot(crypto.SHA3_512, p, sum[:]) {
		panic("openssl: SHA3_512 failed")
	}
	return
}

// NewMD4 returns a new MD4 hash.
// The returned hash doesn't implement encoding.BinaryMarshaler and
// encoding.BinaryUnmarshaler.
func NewMD4() hash.Hash {
	return newEvpHash(crypto.MD4)
}

// NewMD5 returns a new MD5 hash.
func NewMD5() hash.Hash {
	return newEvpHash(crypto.MD5)
}

// NewSHA1 returns a new SHA1 hash.
func NewSHA1() hash.Hash {
	return newEvpHash(crypto.SHA1)
}

// NewSHA224 returns a new SHA224 hash.
func NewSHA224() hash.Hash {
	return newEvpHash(crypto.SHA224)
}

// NewSHA256 returns a new SHA256 hash.
func NewSHA256() hash.Hash {
	return newEvpHash(crypto.SHA256)
}

// NewSHA384 returns a new SHA384 hash.
func NewSHA384() hash.Hash {
	return newEvpHash(crypto.SHA384)
}

// NewSHA512 returns a new SHA512 hash.
func NewSHA512() hash.Hash {
	return newEvpHash(crypto.SHA512)
}

// NewSHA512_224 returns a new SHA512_224 hash.
func NewSHA512_224() hash.Hash {
	return newEvpHash(crypto.SHA512_224)
}

// NewSHA512_256 returns a new SHA512_256 hash.
func NewSHA512_256() hash.Hash {
	return newEvpHash(crypto.SHA512_256)
}

// NewSHA3_224 returns a new SHA3-224 hash.
func NewSHA3_224() hash.Hash {
	return newEvpHash(crypto.SHA3_224)
}

// NewSHA3_256 returns a new SHA3-256 hash.
func NewSHA3_256() hash.Hash {
	return newEvpHash(crypto.SHA3_256)
}

// NewSHA3_384 returns a new SHA3-384 hash.
func NewSHA3_384() hash.Hash {
	return newEvpHash(crypto.SHA3_384)
}

// NewSHA3_512 returns a new SHA3-512 hash.
func NewSHA3_512() hash.Hash {
	return newEvpHash(crypto.SHA3_512)
}

var _ hash.Hash = (*evpHash)(nil)
var _ HashCloner = (*evpHash)(nil)

// evpHash implements generic hash methods.
type evpHash struct {
	alg *hashAlgorithm
	ctx ossl.EVP_MD_CTX_PTR
	// ctx2 is used in evpHash.sum to avoid changing
	// the state of ctx. Having it here allows reusing the
	// same allocated object multiple times.
	ctx2 ossl.EVP_MD_CTX_PTR
	out  [maxHashSize]byte
}

func newEvpHash(ch crypto.Hash) *evpHash {
	alg := loadHash(ch)
	if alg == nil {
		panic("openssl: unsupported hash function: " + strconv.Itoa(int(ch)))
	}
	h := &evpHash{alg: alg}
	// Don't call init() yet, it would be wasteful
	// if the caller only wants to know the hash type. This
	// is a common pattern in this package, as some functions
	// accept a `func() hash.Hash` parameter and call it just
	// to know the hash type.
	return h
}

func (h *evpHash) finalize() {
	if h.ctx != nil {
		ossl.EVP_MD_CTX_free(h.ctx)
	}
	if h.ctx2 != nil {
		ossl.EVP_MD_CTX_free(h.ctx2)
	}
}

func (h *evpHash) init() {
	if h.ctx != nil {
		return
	}
	var err error
	h.ctx, err = ossl.EVP_MD_CTX_new()
	if err != nil {
		panic(err)
	}
	if _, err := ossl.EVP_DigestInit_ex(h.ctx, h.alg.md, nil); err != nil {
		ossl.EVP_MD_CTX_free(h.ctx)
		panic(err)
	}
	h.ctx2, err = ossl.EVP_MD_CTX_new()
	if err != nil {
		ossl.EVP_MD_CTX_free(h.ctx)
		panic(err)
	}
	runtime.SetFinalizer(h, (*evpHash).finalize)
}

func (h *evpHash) Reset() {
	if h.ctx == nil {
		// The hash is not initialized yet, no need to reset.
		return
	}
	// There is no need to reset h.ctx2 because it is always reset after
	// use in evpHash.sum.
	if _, err := ossl.EVP_DigestInit_ex(h.ctx, nil, nil); err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
}

func (h *evpHash) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	h.init()
	if _, err := ossl.EVP_DigestUpdate(h.ctx, pbase(p), len(p)); err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h *evpHash) WriteString(s string) (int, error) {
	if len(s) == 0 {
		return 0, nil
	}
	h.init()
	if _, err := ossl.EVP_DigestUpdate(h.ctx, unsafe.Pointer(unsafe.StringData(s)), len(s)); err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
	return len(s), nil
}

func (h *evpHash) WriteByte(c byte) error {
	h.init()
	if _, err := ossl.EVP_DigestUpdate(h.ctx, unsafe.Pointer(&c), 1); err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
	return nil
}

func (h *evpHash) Size() int {
	return h.alg.size
}

func (h *evpHash) BlockSize() int {
	return h.alg.blockSize
}

func (h *evpHash) Sum(in []byte) []byte {
	h.init()
	tmp := h.out[:h.Size()] // Create slice view
	clear(tmp)
	if err := ossl.HashSum(h.ctx, h.ctx2, tmp); err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
	return append(in, tmp...)
}

// Clone returns a new evpHash object that is a deep clone of itself.
// The duplicate object contains all state and data contained in the
// original object at the point of duplication.
func (h *evpHash) Clone() (HashCloner, error) {
	h2 := &evpHash{alg: h.alg}
	if h.ctx != nil {
		var err error
		h2.ctx, err = ossl.EVP_MD_CTX_new()
		if err != nil {
			panic(err)
		}
		if _, err := ossl.EVP_MD_CTX_copy_ex(h2.ctx, h.ctx); err != nil {
			ossl.EVP_MD_CTX_free(h2.ctx)
			panic(err)
		}
		h2.ctx2, err = ossl.EVP_MD_CTX_new()
		if err != nil {
			ossl.EVP_MD_CTX_free(h2.ctx)
			panic(err)
		}
		runtime.SetFinalizer(h2, (*evpHash).finalize)
	}
	runtime.KeepAlive(h)
	return h2, nil
}

type errMarshallUnsupported struct{}

func (e errMarshallUnsupported) Error() string {
	return "cryptokit: hash state is not marshallable"
}

func (e errMarshallUnsupported) Unwrap() error {
	return errors.ErrUnsupported
}

func (d *evpHash) MarshalBinary() ([]byte, error) {
	if !d.alg.marshallable {
		return nil, errMarshallUnsupported{}
	}
	buf := make([]byte, 0, d.alg.marshalledSize)
	return d.AppendBinary(buf)
}

func (d *evpHash) AppendBinary(buf []byte) ([]byte, error) {
	defer runtime.KeepAlive(d)
	if !d.alg.marshallable {
		return nil, errMarshallUnsupported{}
	}
	d.init()
	switch d.alg.provider {
	case providerOSSLDefault, providerOSSLFIPS:
		return osslHashAppendBinary(d.ctx, d.alg.ch, d.alg.magic, buf)
	case providerSymCrypt:
		return symCryptHashAppendBinary(d.ctx, d.alg.ch, d.alg.magic, buf)
	default:
		panic("openssl: unknown hash provider" + strconv.Itoa(int(d.alg.provider)))
	}
}

func (d *evpHash) UnmarshalBinary(b []byte) error {
	defer runtime.KeepAlive(d)
	d.init()
	if !d.alg.marshallable {
		return errMarshallUnsupported{}
	}
	if len(b) < len(d.alg.magic) || string(b[:len(d.alg.magic)]) != d.alg.magic {
		return errors.New("openssl: invalid hash state identifier")
	}
	if len(b) != d.alg.marshalledSize {
		return errors.New("openssl: invalid hash state size")
	}
	switch d.alg.provider {
	case providerOSSLDefault, providerOSSLFIPS:
		return osslHashUnmarshalBinary(d.ctx, d.alg.ch, d.alg.magic, b)
	case providerSymCrypt:
		return symCryptHashUnmarshalBinary(d.ctx, d.alg.ch, d.alg.magic, b)
	default:
		panic("openssl: unknown hash provider" + strconv.Itoa(int(d.alg.provider)))
	}
}

// appendUint64 appends x into b as a big endian byte sequence.
func appendUint64(b []byte, x uint64) []byte {
	return append(b,
		byte(x>>56),
		byte(x>>48),
		byte(x>>40),
		byte(x>>32),
		byte(x>>24),
		byte(x>>16),
		byte(x>>8),
		byte(x),
	)
}

// appendUint32 appends x into b as a big endian byte sequence.
func appendUint32(b []byte, x uint32) []byte {
	return append(b, byte(x>>24), byte(x>>16), byte(x>>8), byte(x))
}

// consumeUint64 reads a big endian uint64 number from b.
func consumeUint64(b []byte) ([]byte, uint64) {
	_ = b[7]
	x := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	return b[8:], x
}

// consumeUint32 reads a big endian uint32 number from b.
func consumeUint32(b []byte) ([]byte, uint32) {
	_ = b[3]
	x := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return b[4:], x
}
