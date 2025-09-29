//go:build !cmd_go_bootstrap

// Package openssl provides access to OpenSSL cryptographic functions.
package openssl

import (
	"errors"
	"math/bits"
	"strconv"
	"sync"
	"unsafe"

	"github.com/microsoft/go/pkg/openssl/internal/ossl"
)

var (
	// vMajor and vMinor hold the major/minor OpenSSL version.
	// It is only populated if Init has been called.
	vMajor, vMinor, vPatch uint
)

var (
	initOnce sync.Once
	initErr  error
)

var isBigEndian bool

// CheckVersion checks if the OpenSSL version can be loaded
// and if the FIPS mode is enabled.
// This function can be called before Init.
// All OpenSSL functions used in here should be tagged with "init_1" or "init_3" in shims.h.
func CheckVersion(version string) (exists, fips bool) {
	close, err := initForCheckVersion(version)
	if err != nil {
		return false, false
	}
	defer close()
	return true, FIPS()
}

// Init loads and initializes OpenSSL from the shared library at path.
// It must be called before any other OpenSSL call, except CheckVersion.
//
// Only the first call to Init is effective.
// Subsequent calls will return the same error result as the one from the first call.
//
// The file is passed to dlopen() verbatim to load the OpenSSL shared library.
// For example, `file=libcrypto.so.1.1.1k-fips` makes Init look for the shared
// library libcrypto.so.1.1.1k-fips.
func Init(file string) error {
	initOnce.Do(func() {
		buf := [2]byte{}
		*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

		switch buf {
		case [2]byte{0xCD, 0xAB}:
			isBigEndian = false
		case [2]byte{0xAB, 0xCD}:
			isBigEndian = true
		default:
			panic("Could not determine native endianness.")
		}
		initErr = opensslInit(file)
	})
	return initErr
}

func utoa(n uint) string {
	return strconv.FormatUint(uint64(n), 10)
}

func errUnsupportedVersion() error {
	return errors.New("openssl: OpenSSL version: " + utoa(vMajor) + "." + utoa(vMinor) + "." + utoa(vPatch))
}

// checkMajorVersion panics if the current major version is not expected.
func checkMajorVersion(expected uint) {
	if vMajor != expected {
		panic("openssl: incorrect major version (" + strconv.Itoa(int(vMajor)) + "), expected " + strconv.Itoa(int(expected)))
	}
}

type fail string

func (e fail) Error() string { return "openssl: " + string(e) + " failed" }

// FIPS returns true if OpenSSL is running in FIPS mode and there is
// a provider available that supports FIPS. It returns false otherwise.
// All OpenSSL functions used in here should be tagged with "init_1" or "init_3" in shims.h.
func FIPS() bool {
	switch vMajor {
	case 1:
		return ossl.FIPS_mode() == 1
	case 3:
		// Check if the default properties contain `fips=1`.
		if ossl.EVP_default_properties_is_fips_enabled(nil) != 1 {
			// Note that it is still possible that the provider used by default is FIPS-compliant,
			// but that wouldn't be a system or user requirement.
			return false
		}
		// Check if the SHA-256 algorithm is available. If it is, then we can be sure that there is a provider available that matches
		// the `fips=1` query. Most notably, this works for the common case of using the built-in FIPS provider.
		//
		// Note that this approach has a small chance of false negative if the FIPS provider doesn't provide the SHA-256 algorithm,
		// but that is highly unlikely because SHA-256 is one of the most common algorithms and fundamental to many cryptographic operations.
		// It also has a small chance of false positive if the FIPS provider implements the SHA-256 algorithm but not the other algorithms
		// used by the caller application, but that is also unlikely because the FIPS provider should provide all common algorithms.
		return proveSHA256("")
	default:
		panic(errUnsupportedVersion())
	}
}

// FIPSCapable returns true if the provider used by default matches the `fips=yes` query.
// It is useful for checking whether OpenSSL is capable of running in FIPS mode regardless
// of whether FIPS mode is explicitly enabled. For example, Azure Linux 3 doesn't set the
// `fips=yes` query in the default properties, but sets the default provider to be SCOSSL,
// which is FIPS-capable.
//
// Considerations:
//   - Multiple calls to FIPSCapable can return different values if [SetFIPS] is called in between.
//   - Can return true even if [FIPS] returns false, because [FIPS] also checks whether
//     the default properties contain `fips=yes`.
//   - When using OpenSSL 3, will always return true if [FIPS] returns true.
//   - When using OpenSSL 1, Will always return the same value as [FIPS].
//   - OpenSSL 3 doesn't provide a way to know if a provider is FIPS-capable. This function uses
//     some heuristics that should be treated as an implementation detail that may change in the future.
func FIPSCapable() bool {
	if FIPS() {
		return true
	}
	if vMajor == 3 {
		// Load the provider with and without the `fips=yes` query.
		// If the providers are the same, then the default provider is FIPS-capable.
		provFIPS := sha256Provider(_ProviderNameFips)
		if provFIPS == nil {
			return false
		}
		provDefault := sha256Provider("")
		return provFIPS == provDefault
	}
	return false
}

// SetFIPS enables or disables FIPS mode.
//
// For OpenSSL 3, if there is no provider available that supports FIPS mode,
// SetFIPS will try to load a built-in provider that supports FIPS mode.
func SetFIPS(enable bool) error {
	if FIPS() == enable {
		// Already in the desired state.
		return nil
	}
	var mode int32
	if enable {
		mode = int32(1)
	} else {
		mode = int32(0)
	}
	switch vMajor {
	case 1:
		if _, err := ossl.FIPS_mode_set(mode); err != nil {
			return err
		}
		return nil
	case 3:
		var shaProps, provName cString
		if enable {
			shaProps = _PropFIPSYes
			provName = _ProviderNameFips
		} else {
			shaProps = _PropFIPSNo
			provName = _ProviderNameDefault
		}
		if !proveSHA256(shaProps) {
			// There is no provider available that supports the desired FIPS mode.
			// Try to load the built-in provider associated with the given mode.
			if p, _ := ossl.OSSL_PROVIDER_try_load(nil, provName.ptr(), 1); p == nil {
				// The built-in provider was not loaded successfully, we can't enable FIPS mode.
				ossl.ERR_clear_error()
				return errors.New("openssl: FIPS mode not supported by any provider")
			}
		}
		_, err := ossl.EVP_default_properties_enable_fips(nil, mode)
		return err
	default:
		panic(errUnsupportedVersion())
	}
}

// sha256Provider returns the provider for the SHA-256 algorithm
// using the given properties.
func sha256Provider(props cString) ossl.OSSL_PROVIDER_PTR {
	md, _ := ossl.EVP_MD_fetch(nil, _DigestNameSHA2_256.ptr(), props.ptr())
	if md == nil {
		ossl.ERR_clear_error()
		return nil
	}
	defer ossl.EVP_MD_free(md)
	return ossl.EVP_MD_get0_provider(md)
}

// proveSHA256 checks if the SHA-256 algorithm is available
// using the given properties.
func proveSHA256(props cString) bool {
	return sha256Provider(props) != nil
}

var zero byte

// baseNeverEmpty returns the address of the underlying array in b.
// If b has zero length, it returns a pointer to a zero byte.
func baseNeverEmpty(b []byte) *byte {
	if len(b) == 0 {
		return &zero
	}
	return unsafe.SliceData(b)
}

// pbaseNeverEmpty returns the address of the underlying array in b.
// If b has zero length, it returns a pointer to a zero byte.
func pbaseNeverEmpty(b []byte) unsafe.Pointer {
	return unsafe.Pointer(baseNeverEmpty(b))
}

// pbase returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
func pbase(b []byte) unsafe.Pointer {
	return unsafe.Pointer(base(b))
}

// base returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
func base(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return unsafe.SliceData(b)
}

// cryptoMalloc allocates n bytes of memory on the OpenSSL heap, which may be
// different from the heap which C.malloc allocates on. The allocated object
// must be freed using cryptoFree. cryptoMalloc is equivalent to the
// OPENSSL_malloc macro.
//
// Like C.malloc, this function is guaranteed to never return nil. If OpenSSL's
// malloc indicates out of memory, it crashes the program.
//
// Only objects which the OpenSSL library will take ownership of (i.e. will be
// freed by OPENSSL_free / CRYPTO_free) need to be allocated on the OpenSSL
// heap.
func cryptoMalloc(n int) unsafe.Pointer {
	p, _ := ossl.CRYPTO_malloc(n, nil, 0)
	if p == nil {
		// Un-recover()-ably crash the program in the same manner as the
		// C.malloc() wrapper function.
		panic("openssl: CRYPTO_malloc failed")
	}
	return p
}

// cryptoFree frees an object allocated on the OpenSSL heap, which may be
// different from the heap which C.malloc allocates on. cryptoFree is equivalent
// to the OPENSSL_free macro.
func cryptoFree(p unsafe.Pointer) {
	ossl.CRYPTO_free(p, nil, 0)
}

const wordBytes = bits.UintSize / 8

// Reverse each limb of z.
func (z BigInt) byteSwap() {
	for i, d := range z {
		var n uint = 0
		for j := range wordBytes {
			n |= uint(byte(d)) << (8 * (wordBytes - j - 1))
			d >>= 8
		}
		z[i] = n
	}
}

func wbase(b BigInt) *byte {
	if len(b) == 0 {
		return nil
	}
	return (*byte)(unsafe.Pointer(unsafe.SliceData(b)))
}

func bigToBN(x BigInt) (ossl.BIGNUM_PTR, error) {
	if len(x) == 0 {
		return nil, nil
	}
	if isBigEndian {
		z := make(BigInt, len(x))
		copy(z, x)
		z.byteSwap()
		x = z
	}
	// Limbs are always ordered in LSB first, so we can safely apply
	// BN_lebin2bn regardless of host endianness.
	bn, err := ossl.BN_lebin2bn(wbase(x), int32(len(x)*wordBytes), nil)
	if err != nil {
		return nil, err
	}
	return bn, nil
}

func bnToBig(bn ossl.BIGNUM_PTR) BigInt {
	if bn == nil {
		return nil
	}

	// Limbs are always ordered in LSB first, so we can safely apply
	// BN_bn2lebinpad regardless of host endianness.
	x := make(BigInt, ossl.BN_num_bits(bn))
	if _, err := ossl.BN_bn2lebinpad(bn, wbase(x), int32(len(x)*wordBytes)); err != nil {
		panic(err)
	}
	if isBigEndian {
		x.byteSwap()
	}
	return x
}

// bnToBinPad converts the absolute value of bn into big-endian form and stores
// it at to, padding with zeroes if necessary. If len(to) is not large enough to
// hold the result, an error is returned.
func bnToBinPad(bn ossl.BIGNUM_PTR, to []byte) error {
	_, err := ossl.BN_bn2binpad(bn, base(to), int32(len(to)))
	return err
}

// versionAtOrAbove returns true when
// (vMajor, vMinor, vPatch) >= (major, minor, patch),
// compared lexicographically.
func versionAtOrAbove(major, minor, patch uint) bool {
	return vMajor > major || (vMajor == major && vMinor > minor) || (vMajor == major && vMinor == minor && vPatch >= patch)
}

func bigEndianUint64(b []byte) uint64 {
	_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}

// VersionText returns the version text of the OpenSSL currently loaded.
func VersionText() string {
	// For nocgo, we need to convert the C string manually
	return goString(ossl.OpenSSL_version(0))
}

// isProviderAvailable reports whether a provider with the given name is available.
// This function is used in export_test.go, but must be defined here as test files can't access C functions.
func isProviderAvailable(name string) bool {
	if vMajor == 1 {
		return false
	}
	return ossl.OSSL_PROVIDER_available(nil, unsafe.StringData(name+"\x00")) == 1
}
