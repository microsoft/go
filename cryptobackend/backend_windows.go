// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

// Package cng provides access to CNGCrypto implementation functions.
// Check the variable Enabled to find out whether CNGCrypto is available.
// If CNGCrypto is not available, the functions in this package all panic.
package backend

import (
	"crypto"
	"crypto/cipher"
	"crypto/fips140"
	"errors"
	"hash"
	_ "unsafe"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func init() {
	// Windows is considered FIPS compliant.
	if err := checkFIPS(func() bool { return true }); err != nil {
		panic("cngcrypto: " + err.Error())
	}
}

// Enabled controls whether FIPS crypto is enabled.
const Enabled = true

type BigInt = cng.BigInt

const RandReader = cng.RandReader

func SupportsHash(h crypto.Hash) bool {
	return cng.SupportsHash(h)
}

func FIPSApprovedHash(h hash.Hash) bool {
	return cng.FIPSApprovedHash(h)
}

func SupportsSHAKE(securityBits int) bool {
	return cng.SupportsSHAKE(securityBits)
}

func SupportsCSHAKE(securityBits int) bool {
	return cng.SupportsSHAKE(securityBits)
}

func SupportsCurve(curve string) bool {
	switch curve {
	case "P-224", "P-256", "P-384", "P-521", "X25519":
		return true
	}
	return false
}

func SupportsRSAOAEPLabel(label []byte) bool { return true }
func SupportsRSAPKCS1v15Encryption() bool    { return true }

func SupportsRSAPKCS1v15Signature(hash crypto.Hash) bool {
	// 0 and MD5SHA1 are special cases that are always supported for PKCS1v15 signatures.
	switch hash {
	case 0, crypto.MD5SHA1:
		return true
	default:
		return cng.SupportsHash(hash)
	}
}

type Hash = cng.Hash
type SHAKE = cng.SHAKE

func NewMD5() hash.Hash        { return cng.NewMD5() }
func NewSHA1() hash.Hash       { return cng.NewSHA1() }
func NewSHA224() hash.Hash     { panic("cngcrypto: not available") }
func NewSHA256() hash.Hash     { return cng.NewSHA256() }
func NewSHA384() hash.Hash     { return cng.NewSHA384() }
func NewSHA512() hash.Hash     { return cng.NewSHA512() }
func NewSHA512_224() hash.Hash { panic("cngcrypto: not available") }
func NewSHA512_256() hash.Hash { panic("cngcrypto: not available") }
func NewSHA3_224() *Hash       { panic("cngcrypto: not available") }
func NewSHA3_256() *Hash       { return cng.NewSHA3_256() }
func NewSHA3_384() *Hash       { return cng.NewSHA3_384() }
func NewSHA3_512() *Hash       { return cng.NewSHA3_512() }

func NewSHAKE128() *SHAKE             { return cng.NewSHAKE128() }
func NewSHAKE256() *SHAKE             { return cng.NewSHAKE256() }
func NewCSHAKE128(N, S []byte) *SHAKE { return cng.NewCSHAKE128(N, S) }
func NewCSHAKE256(N, S []byte) *SHAKE { return cng.NewCSHAKE256(N, S) }

func MD5(p []byte) (sum [16]byte)         { return cng.MD5(p) }
func SHA1(p []byte) (sum [20]byte)        { return cng.SHA1(p) }
func SHA224(p []byte) (sum [28]byte)      { panic("cngcrypto: not available") }
func SHA256(p []byte) (sum [32]byte)      { return cng.SHA256(p) }
func SHA384(p []byte) (sum [48]byte)      { return cng.SHA384(p) }
func SHA512(p []byte) (sum [64]byte)      { return cng.SHA512(p) }
func SHA512_224(p []byte) (sum [28]byte)  { panic("cngcrypto: not available") }
func SHA512_256(p []byte) (sum [32]byte)  { panic("cngcrypto: not available") }
func SumSHA3_224(p []byte) (sum [28]byte) { panic("cngcrypto: not available") }
func SumSHA3_256(p []byte) (sum [32]byte) { return cng.SumSHA3_256(p) }
func SumSHA3_384(p []byte) (sum [48]byte) { return cng.SumSHA3_384(p) }
func SumSHA3_512(p []byte) (sum [64]byte) { return cng.SumSHA3_512(p) }

func SumSHAKE128(data []byte, length int) (sum []byte) { return cng.SumSHAKE128(data, length) }
func SumSHAKE256(data []byte, length int) (sum []byte) { return cng.SumSHAKE256(data, length) }

func NewHMAC(h func() hash.Hash, key []byte) hash.Hash {
	return cng.NewHMAC(h, key)
}

func NewAESCipher(key []byte) (cipher.Block, error) {
	return cng.NewAESCipher(key)
}

func NewGCMTLS(c cipher.Block) (cipher.AEAD, error) {
	return cng.NewGCMTLS(c)
}

func NewGCMTLS13(c cipher.Block) (cipher.AEAD, error) {
	return cng.NewGCMTLS13(c)
}

type PublicKeyECDSA = cng.PublicKeyECDSA
type PrivateKeyECDSA = cng.PrivateKeyECDSA

func GenerateKeyECDSA(curve string) (X, Y, D cng.BigInt, err error) {
	return cng.GenerateKeyECDSA(curve)
}

func NewPrivateKeyECDSA(curve string, X, Y, D cng.BigInt) (*cng.PrivateKeyECDSA, error) {
	return cng.NewPrivateKeyECDSA(curve, X, Y, D)
}

func NewPublicKeyECDSA(curve string, X, Y cng.BigInt) (*cng.PublicKeyECDSA, error) {
	return cng.NewPublicKeyECDSA(curve, X, Y)
}

//go:linkname encodeSignature crypto/ecdsa.encodeSignature
func encodeSignature(r, s []byte) ([]byte, error)

//go:linkname parseSignature crypto/ecdsa.parseSignature
func parseSignature(sig []byte) (r, s []byte, err error)

func SignMarshalECDSA(priv *cng.PrivateKeyECDSA, hash []byte) ([]byte, error) {
	r, s, err := cng.SignECDSA(priv, hash)
	if err != nil {
		return nil, err
	}
	return encodeSignature(r, s)
}

func VerifyECDSA(pub *cng.PublicKeyECDSA, hash []byte, sig []byte) bool {
	rBytes, sBytes, err := parseSignature(sig)
	if err != nil {
		return false
	}
	return cng.VerifyECDSA(pub, hash, cng.BigInt(rBytes), cng.BigInt(sBytes))
}

func SignECDSA(priv *cng.PrivateKeyECDSA, hash []byte) (r, s cng.BigInt, err error) {
	return cng.SignECDSA(priv, hash)
}

func VerifyECDSARaw(pub *cng.PublicKeyECDSA, hash []byte, r, s cng.BigInt) bool {
	return cng.VerifyECDSA(pub, hash, r, s)
}

func SupportsRSAPrivateKey(bits, primes int) bool {
	return primes == 2 && SupportsRSAPublicKey(bits)
}

func SupportsRSAPublicKey(bits int) bool {
	return bits >= 512 && bits%8 == 0 && bits <= 16384
}

func SupportsRSASaltLength(sign bool, salt int) bool {
	if sign {
		return true
	}
	return salt != 0 // rsa.PSSSaltLengthAuto
}

type PublicKeyRSA = cng.PublicKeyRSA
type PrivateKeyRSA = cng.PrivateKeyRSA

func DecryptRSAOAEP(h, mgfHash hash.Hash, priv *cng.PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	return cng.DecryptRSAOAEP(h, priv, ciphertext, label)
}

func DecryptRSAPKCS1(priv *cng.PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return cng.DecryptRSAPKCS1(priv, ciphertext)
}

func DecryptRSANoPadding(priv *cng.PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return cng.DecryptRSANoPadding(priv, ciphertext)
}

func EncryptRSAOAEP(h, mgfHash hash.Hash, pub *cng.PublicKeyRSA, msg, label []byte) ([]byte, error) {
	return cng.EncryptRSAOAEP(h, pub, msg, label)
}

func EncryptRSAPKCS1(pub *cng.PublicKeyRSA, msg []byte) ([]byte, error) {
	return cng.EncryptRSAPKCS1(pub, msg)
}

func EncryptRSANoPadding(pub *cng.PublicKeyRSA, msg []byte) ([]byte, error) {
	return cng.EncryptRSANoPadding(pub, msg)
}

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv cng.BigInt, err error) {
	return cng.GenerateKeyRSA(bits)
}

func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv cng.BigInt) (*cng.PrivateKeyRSA, error) {
	return cng.NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv)
}

func NewPublicKeyRSA(N, E cng.BigInt) (*cng.PublicKeyRSA, error) {
	return cng.NewPublicKeyRSA(N, E)
}

func SignRSAPKCS1v15(priv *cng.PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	return cng.SignRSAPKCS1v15(priv, h, hashed)
}

func SignRSAPSS(priv *cng.PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	return cng.SignRSAPSS(priv, h, hashed, saltLen)
}

func VerifyRSAPKCS1v15(pub *cng.PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	return cng.VerifyRSAPKCS1v15(pub, h, hashed, sig)
}

func VerifyRSAPSS(pub *cng.PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	return cng.VerifyRSAPSS(pub, h, hashed, sig, saltLen)
}

type PrivateKeyECDH = cng.PrivateKeyECDH
type PublicKeyECDH = cng.PublicKeyECDH

func ECDH(priv *cng.PrivateKeyECDH, pub *cng.PublicKeyECDH) ([]byte, error) {
	return cng.ECDH(priv, pub)
}

func GenerateKeyECDH(curve string) (*cng.PrivateKeyECDH, []byte, error) {
	return cng.GenerateKeyECDH(curve)
}

func NewPrivateKeyECDH(curve string, bytes []byte) (*cng.PrivateKeyECDH, error) {
	return cng.NewPrivateKeyECDH(curve, bytes)
}

func NewPublicKeyECDH(curve string, bytes []byte) (*cng.PublicKeyECDH, error) {
	return cng.NewPublicKeyECDH(curve, bytes)
}

func SupportsTLS13KDF() bool {
	return false
}

func ExpandTLS13KDF(h func() hash.Hash, pseudorandomKey, label, context []byte, keyLength int) ([]byte, error) {
	panic("cryptobackend: not available")
}

func SupportsHKDF() bool {
	return cng.SupportsHKDF()
}

func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte, keyLength int) ([]byte, error) {
	return cng.ExpandHKDF(h, pseudorandomKey, info, keyLength)
}

func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	return cng.ExtractHKDF(h, secret, salt)
}

func SupportsPBKDF2() bool { return true }

func PBKDF2(password, salt []byte, iter, keyLen int, h func() hash.Hash) ([]byte, error) {
	return cng.PBKDF2(password, salt, iter, keyLen, h)
}

func SupportsTLS1PRF() bool {
	return true
}

func TLS1PRF(result, secret, label, seed []byte, h func() hash.Hash) error {
	return cng.TLS1PRF(result, secret, label, seed, h)
}

func SupportsDESCipher() bool {
	return true
}

func SupportsTripleDESCipher() bool {
	return true
}

func NewDESCipher(key []byte) (cipher.Block, error) {
	return cng.NewDESCipher(key)
}

func NewTripleDESCipher(key []byte) (cipher.Block, error) {
	return cng.NewTripleDESCipher(key)
}

func SupportsRC4() bool { return true }

type RC4Cipher = cng.RC4Cipher

func NewRC4Cipher(key []byte) (*RC4Cipher, error) { return cng.NewRC4Cipher(key) }

func SupportsEd25519() bool { return false }

type PublicKeyEd25519 struct{}

func (k PublicKeyEd25519) Bytes() ([]byte, error) {
	panic("cryptobackend: not available")
}

type PrivateKeyEd25519 struct{}

func (k PrivateKeyEd25519) Bytes() ([]byte, error) {
	panic("cryptobackend: not available")
}

func GenerateKeyEd25519() (PrivateKeyEd25519, error) {
	panic("cryptobackend: not available")
}

func NewPrivateKeyEd25519(priv []byte) (PrivateKeyEd25519, error) {
	panic("cryptobackend: not available")
}

func NewPublicKeyEd25519(pub []byte) (PublicKeyEd25519, error) {
	panic("cryptobackend: not available")
}

func NewPrivateKeyEd25519FromSeed(seed []byte) (PrivateKeyEd25519, error) {
	panic("cryptobackend: not available")
}

func SignEd25519(priv PrivateKeyEd25519, message []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}

func VerifyEd25519(pub PublicKeyEd25519, message, sig []byte) error {
	panic("cryptobackend: not available")
}

type PrivateKeyDSA = cng.PrivateKeyDSA
type PublicKeyDSA = cng.PublicKeyDSA

func SupportsDSA(l, n int) bool {
	// These are the only N values supported by CNG
	return n == 160 || n == 256
}

func GenerateParametersDSA(l, n int) (p, q, g cng.BigInt, err error) {
	params, err := cng.GenerateParametersDSA(l)
	if err != nil {
		return nil, nil, nil, err
	}
	return params.P, params.Q, params.G, nil
}

func GenerateKeyDSA(p, q, g cng.BigInt) (x, y cng.BigInt, err error) {
	return cng.GenerateKeyDSA(cng.DSAParameters{P: p, Q: q, G: g})
}

func NewPrivateKeyDSA(p, q, g, x, y cng.BigInt) (*cng.PrivateKeyDSA, error) {
	return cng.NewPrivateKeyDSA(cng.DSAParameters{P: p, Q: q, G: g}, x, y)
}

func NewPublicKeyDSA(p, q, g, y cng.BigInt) (*cng.PublicKeyDSA, error) {
	return cng.NewPublicKeyDSA(cng.DSAParameters{P: p, Q: q, G: g}, y)
}

func SignDSA(priv *PrivateKeyDSA, hash []byte, parseSignature func([]byte) (cng.BigInt, cng.BigInt, error)) (r, s cng.BigInt, err error) {
	return cng.SignDSA(priv, hash)
}

func VerifyDSA(pub *PublicKeyDSA, hashed []byte, r, s cng.BigInt, encodeSignature func(r, s cng.BigInt) ([]byte, error)) bool {
	return cng.VerifyDSA(pub, hashed, r, s)
}

func SupportsMLKEM768() bool {
	return cng.SupportsMLKEM()
}

func SupportsMLKEM1024() bool {
	return cng.SupportsMLKEM()
}

type DecapsulationKeyMLKEM768 = cng.DecapsulationKeyMLKEM768
type EncapsulationKeyMLKEM768 = cng.EncapsulationKeyMLKEM768

func GenerateKeyMLKEM768() (DecapsulationKeyMLKEM768, error) {
	return cng.GenerateKeyMLKEM768()
}

func NewDecapsulationKeyMLKEM768(seed []byte) (DecapsulationKeyMLKEM768, error) {
	return cng.NewDecapsulationKeyMLKEM768(seed)
}

func NewEncapsulationKeyMLKEM768(encapsulationKey []byte) (EncapsulationKeyMLKEM768, error) {
	return cng.NewEncapsulationKeyMLKEM768(encapsulationKey)
}

type DecapsulationKeyMLKEM1024 = cng.DecapsulationKeyMLKEM1024
type EncapsulationKeyMLKEM1024 = cng.EncapsulationKeyMLKEM1024

func GenerateKeyMLKEM1024() (DecapsulationKeyMLKEM1024, error) {
	return cng.GenerateKeyMLKEM1024()
}

func NewDecapsulationKeyMLKEM1024(seed []byte) (DecapsulationKeyMLKEM1024, error) {
	return cng.NewDecapsulationKeyMLKEM1024(seed)
}

func NewEncapsulationKeyMLKEM1024(encapsulationKey []byte) (EncapsulationKeyMLKEM1024, error) {
	return cng.NewEncapsulationKeyMLKEM1024(encapsulationKey)
}

type MLDSAParameters = cng.MLDSAParameters

func MLDSA44() MLDSAParameters { return cng.MLDSA44() }
func MLDSA65() MLDSAParameters { return cng.MLDSA65() }
func MLDSA87() MLDSAParameters { return cng.MLDSA87() }

// SupportsMLDSA reports whether the backend supports ML-DSA. The params
// argument is ignored because CNG support is all-or-nothing: it implements
// ML-DSA-44, -65, and -87 uniformly, unlike the parameter-aware OpenSSL and
// CryptoKit backends.
func SupportsMLDSA(params MLDSAParameters) bool {
	return cng.SupportsMLDSA()
}

// SupportsMLDSAExternalMu reports whether the backend can sign a pre-hashed mu
// message representative directly. CNG implements external-mu signing.
func SupportsMLDSAExternalMu() bool { return true }

type PrivateKeyMLDSA = cng.PrivateKeyMLDSA
type PublicKeyMLDSA = cng.PublicKeyMLDSA

func GenerateKeyMLDSA(params MLDSAParameters) (*PrivateKeyMLDSA, error) {
	return cng.GenerateKeyMLDSA(params)
}

func NewPrivateKeyMLDSA(params MLDSAParameters, seed []byte) (*PrivateKeyMLDSA, error) {
	return cng.NewPrivateKeyMLDSA(params, seed)
}

func NewPublicKeyMLDSA(params MLDSAParameters, publicKey []byte) (*PublicKeyMLDSA, error) {
	return cng.NewPublicKeyMLDSA(params, publicKey)
}

func SupportsChaCha20Poly1305() bool {
	return cng.SupportsChaCha20Poly1305()
}

func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if fips140.Enforced() {
		return nil, errors.New("chacha20poly1305: use of ChaCha20Poly1305 is not allowed in FIPS 140-only mode")
	}
	return cng.NewChaCha20Poly1305(key)
}
