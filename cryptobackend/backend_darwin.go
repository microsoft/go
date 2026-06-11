// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

// Package darwin provides access to DarwinCrypto implementation functions.
// Check the variable Enabled to find out whether DarwinCrypto is available.
// If DarwinCrypto is not available, the functions in this package all panic.
package backend

import (
	"crypto"
	"crypto/cipher"
	"crypto/internal/boring/sig"
	"crypto/internal/fips140only"
	"errors"
	"hash"
	"io"
	_ "unsafe"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func init() {
	// Darwin is considered FIPS compliant.
	if err := checkFIPS(func() bool { return true }); err != nil {
		panic("darwincrypto: " + err.Error())
	}
	sig.BoringCrypto()
	fips140only.BackendApprovedHash = FIPSApprovedHash
}

// Enabled controls whether FIPS crypto is enabled.
const Enabled = true

type BigInt = xcrypto.BigInt

const RandReader = xcrypto.RandReader

func SupportsHash(h crypto.Hash) bool {
	return xcrypto.SupportsHash(h)
}

func FIPSApprovedHash(h hash.Hash) bool {
	return xcrypto.FIPSApprovedHash(h)
}

func SupportsSHAKE(securityBits int) bool  { return false }
func SupportsCSHAKE(securityBits int) bool { return false }

func SupportsCurve(curve string) bool {
	switch curve {
	case "P-256", "P-384", "P-521", "X25519":
		return true
	}
	return false
}

func SupportsRSAOAEPLabel(label []byte) bool {
	// CommonCrypto doesn't support labels
	// https://github.com/microsoft/go-crypto-darwin/issues/22
	return len(label) == 0
}

func SupportsRSAPKCS1v15Encryption() bool { return true }

func SupportsRSAPKCS1v15Signature(hash crypto.Hash) bool {
	switch hash {
	case crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512, 0:
		return true
	}
	return false
}

type Hash = xcrypto.Hash

type SHAKE struct {
	io.Reader
	hash.Hash
}

func (s *SHAKE) MarshalBinary() ([]byte, error)        { panic("cryptobackend: not available") }
func (s *SHAKE) AppendBinary(p []byte) ([]byte, error) { panic("cryptobackend: not available") }
func (s *SHAKE) UnmarshalBinary(data []byte) error     { panic("cryptobackend: not available") }

func NewMD5() hash.Hash        { return xcrypto.NewMD5() }
func NewSHA1() hash.Hash       { return xcrypto.NewSHA1() }
func NewSHA224() hash.Hash     { panic("cryptobackend: not available") }
func NewSHA256() hash.Hash     { return xcrypto.NewSHA256() }
func NewSHA384() hash.Hash     { return xcrypto.NewSHA384() }
func NewSHA512() hash.Hash     { return xcrypto.NewSHA512() }
func NewSHA512_224() hash.Hash { panic("cryptobackend: not available") }
func NewSHA512_256() hash.Hash { panic("cryptobackend: not available") }
func NewSHA3_224() *Hash       { panic("cryptobackend: not available") }
func NewSHA3_256() *Hash       { return xcrypto.NewSHA3_256() }
func NewSHA3_384() *Hash       { return xcrypto.NewSHA3_384() }
func NewSHA3_512() *Hash       { return xcrypto.NewSHA3_512() }

func NewSHAKE128() *SHAKE             { panic("cryptobackend: not available") }
func NewSHAKE256() *SHAKE             { panic("cryptobackend: not available") }
func NewCSHAKE128(N, S []byte) *SHAKE { panic("cryptobackend: not available") }
func NewCSHAKE256(N, S []byte) *SHAKE { panic("cryptobackend: not available") }

func MD5(p []byte) (sum [16]byte)         { return xcrypto.MD5(p) }
func SHA1(p []byte) (sum [20]byte)        { return xcrypto.SHA1(p) }
func SHA224(p []byte) (sum [28]byte)      { panic("cryptobackend: not available") }
func SHA256(p []byte) (sum [32]byte)      { return xcrypto.SHA256(p) }
func SHA384(p []byte) (sum [48]byte)      { return xcrypto.SHA384(p) }
func SHA512(p []byte) (sum [64]byte)      { return xcrypto.SHA512(p) }
func SHA512_224(p []byte) (sum [28]byte)  { panic("cryptobackend: not available") }
func SHA512_256(p []byte) (sum [32]byte)  { panic("cryptobackend: not available") }
func SumSHA3_224(p []byte) (sum [28]byte) { panic("cryptobackend: not available") }
func SumSHA3_256(p []byte) (sum [32]byte) { return xcrypto.SumSHA3_256(p) }
func SumSHA3_384(p []byte) (sum [48]byte) { return xcrypto.SumSHA3_384(p) }
func SumSHA3_512(p []byte) (sum [64]byte) { return xcrypto.SumSHA3_512(p) }

func SumSHAKE128(data []byte, length int) (sum []byte) { panic("cryptobackend: not available") }
func SumSHAKE256(data []byte, length int) (sum []byte) { panic("cryptobackend: not available") }

func NewHMAC(h func() hash.Hash, key []byte) hash.Hash {
	return xcrypto.NewHMAC(h, key)
}

func NewAESCipher(key []byte) (cipher.Block, error) {
	return xcrypto.NewAESCipher(key)
}

func NewGCMTLS(c cipher.Block) (cipher.AEAD, error) {
	return xcrypto.NewGCMTLS(c)
}

func NewGCMTLS13(c cipher.Block) (cipher.AEAD, error) {
	return xcrypto.NewGCMTLS13(c)
}

type PublicKeyECDSA = xcrypto.PublicKeyECDSA
type PrivateKeyECDSA = xcrypto.PrivateKeyECDSA

func GenerateKeyECDSA(curve string) (X, Y, D xcrypto.BigInt, err error) {
	return xcrypto.GenerateKeyECDSA(curve)
}

func NewPrivateKeyECDSA(curve string, X, Y, D xcrypto.BigInt) (*xcrypto.PrivateKeyECDSA, error) {
	return xcrypto.NewPrivateKeyECDSA(curve, X, Y, D)
}

func NewPublicKeyECDSA(curve string, X, Y xcrypto.BigInt) (*xcrypto.PublicKeyECDSA, error) {
	return xcrypto.NewPublicKeyECDSA(curve, X, Y)
}

//go:linkname encodeSignature crypto/ecdsa.encodeSignature
func encodeSignature(r, s []byte) ([]byte, error)

//go:linkname parseSignature crypto/ecdsa.parseSignature
func parseSignature(sig []byte) (r, s []byte, err error)

func SignMarshalECDSA(priv *xcrypto.PrivateKeyECDSA, hash []byte) ([]byte, error) {
	return xcrypto.SignMarshalECDSA(priv, hash)
}

func VerifyECDSA(pub *xcrypto.PublicKeyECDSA, hash []byte, sig []byte) bool {
	return xcrypto.VerifyECDSA(pub, hash, sig)
}

func SupportsRSAPrivateKey(bits, primes int) bool {
	return primes == 2 && SupportsRSAPublicKey(bits)
}

func SupportsRSAPublicKey(bits int) bool {
	return bits >= 1024 && bits%8 == 0 && bits <= 16384
}

func SupportsRSASaltLength(sign bool, salt int) bool {
	// CommonCrypto doesn't support custom salt length
	return salt == -1
}

type PublicKeyRSA = xcrypto.PublicKeyRSA
type PrivateKeyRSA = xcrypto.PrivateKeyRSA

func DecryptRSAOAEP(h, mgfHash hash.Hash, priv *xcrypto.PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	return xcrypto.DecryptRSAOAEP(h, priv, ciphertext, label)
}

func DecryptRSAPKCS1(priv *xcrypto.PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return xcrypto.DecryptRSAPKCS1(priv, ciphertext)
}

func DecryptRSANoPadding(priv *xcrypto.PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return xcrypto.DecryptRSANoPadding(priv, ciphertext)
}

func EncryptRSAOAEP(h, mgfHash hash.Hash, pub *xcrypto.PublicKeyRSA, msg, label []byte) ([]byte, error) {
	return xcrypto.EncryptRSAOAEP(h, pub, msg, label)
}

func EncryptRSAPKCS1(pub *xcrypto.PublicKeyRSA, msg []byte) ([]byte, error) {
	return xcrypto.EncryptRSAPKCS1(pub, msg)
}

func EncryptRSANoPadding(pub *xcrypto.PublicKeyRSA, msg []byte) ([]byte, error) {
	return xcrypto.EncryptRSANoPadding(pub, msg)
}

//go:linkname decodeKeyRSA crypto/rsa.decodeKey
func decodeKeyRSA(data []byte) (N, E, D, P, Q, Dp, Dq, Qinv xcrypto.BigInt, err error)

//go:linkname encodeKeyRSA crypto/rsa.encodeKey
func encodeKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv xcrypto.BigInt) ([]byte, error)

//go:linkname encodePublicKeyRSA crypto/rsa.encodePublicKey
func encodePublicKeyRSA(N, E xcrypto.BigInt) ([]byte, error)

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv xcrypto.BigInt, err error) {
	data, err := xcrypto.GenerateKeyRSA(bits)
	if err != nil {
		return
	}
	return decodeKeyRSA(data)
}

func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv xcrypto.BigInt) (*xcrypto.PrivateKeyRSA, error) {
	encoded, err := encodeKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv)
	if err != nil {
		return nil, err
	}
	return xcrypto.NewPrivateKeyRSA(encoded)
}

func NewPublicKeyRSA(N, E xcrypto.BigInt) (*xcrypto.PublicKeyRSA, error) {
	encoded, err := encodePublicKeyRSA(N, E)
	if err != nil {
		return nil, err
	}
	return xcrypto.NewPublicKeyRSA(encoded)
}

func SignRSAPKCS1v15(priv *xcrypto.PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	return xcrypto.SignRSAPKCS1v15(priv, h, hashed)
}

func SignRSAPSS(priv *xcrypto.PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	return xcrypto.SignRSAPSS(priv, h, hashed, saltLen)
}

func VerifyRSAPKCS1v15(pub *xcrypto.PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	return xcrypto.VerifyRSAPKCS1v15(pub, h, hashed, sig)
}

func VerifyRSAPSS(pub *xcrypto.PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	return xcrypto.VerifyRSAPSS(pub, h, hashed, sig, saltLen)
}

type PrivateKeyECDH = xcrypto.PrivateKeyECDH
type PublicKeyECDH = xcrypto.PublicKeyECDH

func ECDH(priv *xcrypto.PrivateKeyECDH, pub *xcrypto.PublicKeyECDH) ([]byte, error) {
	return xcrypto.ECDH(priv, pub)
}

func GenerateKeyECDH(curve string) (*xcrypto.PrivateKeyECDH, []byte, error) {
	return xcrypto.GenerateKeyECDH(curve)
}

func NewPrivateKeyECDH(curve string, bytes []byte) (*xcrypto.PrivateKeyECDH, error) {
	return xcrypto.NewPrivateKeyECDH(curve, bytes)
}

func NewPublicKeyECDH(curve string, bytes []byte) (*xcrypto.PublicKeyECDH, error) {
	return xcrypto.NewPublicKeyECDH(curve, bytes)
}

func SupportsTLS13KDF() bool {
	return false
}

func ExpandTLS13KDF(h func() hash.Hash, pseudorandomKey, label, context []byte, keyLength int) ([]byte, error) {
	panic("cryptobackend: not available")
}

func SupportsHKDF() bool {
	return true
}

func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte, keyLength int) ([]byte, error) {
	return xcrypto.ExpandHKDF(h, pseudorandomKey, info, keyLength)
}

func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	return xcrypto.ExtractHKDF(h, secret, salt)
}

func SupportsPBKDF2() bool {
	return true
}

func PBKDF2(pass, salt []byte, iter, keyLen int, h func() hash.Hash) ([]byte, error) {
	return xcrypto.PBKDF2(pass, salt, iter, keyLen, h)
}

func SupportsTLS1PRF() bool {
	return false
}

func TLS1PRF(result, secret, label, seed []byte, h func() hash.Hash) error {
	panic("cryptobackend: not available")
}

func SupportsDESCipher() bool {
	return true
}

func SupportsTripleDESCipher() bool {
	return true
}

func NewDESCipher(key []byte) (cipher.Block, error) {
	return xcrypto.NewDESCipher(key)
}

func NewTripleDESCipher(key []byte) (cipher.Block, error) {
	return xcrypto.NewTripleDESCipher(key)
}

func SupportsRC4() bool { return true }

type RC4Cipher = xcrypto.RC4Cipher

func NewRC4Cipher(key []byte) (*RC4Cipher, error) { return xcrypto.NewRC4Cipher(key) }

func SupportsEd25519() bool {
	return true
}

type PublicKeyEd25519 = xcrypto.PublicKeyEd25519
type PrivateKeyEd25519 = xcrypto.PrivateKeyEd25519

func GenerateKeyEd25519() (PrivateKeyEd25519, error) {
	return xcrypto.GenerateKeyEd25519(), nil
}

func NewPrivateKeyEd25519(priv []byte) (PrivateKeyEd25519, error) {
	return xcrypto.NewPrivateKeyEd25519(priv)
}

func NewPublicKeyEd25519(pub []byte) (PublicKeyEd25519, error) {
	return xcrypto.NewPublicKeyEd25519(pub)
}

func NewPrivateKeyEd25519FromSeed(seed []byte) (PrivateKeyEd25519, error) {
	return xcrypto.NewPrivateKeyEd25519FromSeed(seed)
}

func SignEd25519(priv PrivateKeyEd25519, message []byte) ([]byte, error) {
	return xcrypto.SignEd25519(priv, message)
}

func VerifyEd25519(pub PublicKeyEd25519, message, sig []byte) error {
	return xcrypto.VerifyEd25519(pub, message, sig)
}

func SupportsDSA(l, n int) bool {
	return false
}

func GenerateParametersDSA(l, n int) (p, q, g xcrypto.BigInt, err error) {
	panic("cryptobackend: not available")
}

type PrivateKeyDSA struct{}
type PublicKeyDSA struct{}

func GenerateKeyDSA(p, q, g xcrypto.BigInt) (x, y xcrypto.BigInt, err error) {
	panic("cryptobackend: not available")
}

func NewPrivateKeyDSA(p, q, g, x, y xcrypto.BigInt) (*PrivateKeyDSA, error) {
	panic("cryptobackend: not available")
}

func NewPublicKeyDSA(p, q, g, y xcrypto.BigInt) (*PublicKeyDSA, error) {
	panic("cryptobackend: not available")
}

func SignDSA(priv *PrivateKeyDSA, hash []byte, parseSignature func([]byte) (xcrypto.BigInt, xcrypto.BigInt, error)) (r, s xcrypto.BigInt, err error) {
	panic("cryptobackend: not available")
}

func VerifyDSA(pub *PublicKeyDSA, hashed []byte, r, s xcrypto.BigInt, encodeSignature func(r, s xcrypto.BigInt) ([]byte, error)) bool {
	panic("cryptobackend: not available")
}

func SupportsMLKEM768() bool {
	return xcrypto.SupportsMLKEM()
}

func SupportsMLKEM1024() bool {
	return xcrypto.SupportsMLKEM()
}

type DecapsulationKeyMLKEM768 = xcrypto.DecapsulationKeyMLKEM768
type EncapsulationKeyMLKEM768 = xcrypto.EncapsulationKeyMLKEM768

func GenerateKeyMLKEM768() (DecapsulationKeyMLKEM768, error) {
	return xcrypto.GenerateKeyMLKEM768()
}

func NewDecapsulationKeyMLKEM768(seed []byte) (DecapsulationKeyMLKEM768, error) {
	return xcrypto.NewDecapsulationKeyMLKEM768(seed)
}

func NewEncapsulationKeyMLKEM768(encapsulationKey []byte) (EncapsulationKeyMLKEM768, error) {
	return xcrypto.NewEncapsulationKeyMLKEM768(encapsulationKey)
}

type DecapsulationKeyMLKEM1024 = xcrypto.DecapsulationKeyMLKEM1024
type EncapsulationKeyMLKEM1024 = xcrypto.EncapsulationKeyMLKEM1024

func GenerateKeyMLKEM1024() (DecapsulationKeyMLKEM1024, error) {
	return xcrypto.GenerateKeyMLKEM1024()
}

func NewDecapsulationKeyMLKEM1024(seed []byte) (DecapsulationKeyMLKEM1024, error) {
	return xcrypto.NewDecapsulationKeyMLKEM1024(seed)
}

func NewEncapsulationKeyMLKEM1024(encapsulationKey []byte) (EncapsulationKeyMLKEM1024, error) {
	return xcrypto.NewEncapsulationKeyMLKEM1024(encapsulationKey)
}

type MLDSAParameters = xcrypto.MLDSAParameters

// MLDSA44 returns an unsupported parameter set: CryptoKit does not implement
// ML-DSA-44. The zero value is reported as unsupported by [SupportsMLDSA], so
// callers fall back to the standard library implementation.
func MLDSA44() MLDSAParameters { return MLDSAParameters{} }
func MLDSA65() MLDSAParameters { return xcrypto.MLDSA65() }
func MLDSA87() MLDSAParameters { return xcrypto.MLDSA87() }

func SupportsMLDSA(params MLDSAParameters) bool {
	return xcrypto.SupportsMLDSA(params)
}

// SupportsMLDSAExternalMu reports whether the backend can sign a pre-hashed mu
// message representative directly. CryptoKit does not implement external-mu
// signing, so callers fall back to the standard library implementation.
func SupportsMLDSAExternalMu() bool { return false }

type PrivateKeyMLDSA = xcrypto.PrivateKeyMLDSA
type PublicKeyMLDSA = xcrypto.PublicKeyMLDSA

func GenerateKeyMLDSA(params MLDSAParameters) (*PrivateKeyMLDSA, error) {
	return xcrypto.GenerateKeyMLDSA(params)
}

func NewPrivateKeyMLDSA(params MLDSAParameters, seed []byte) (*PrivateKeyMLDSA, error) {
	return xcrypto.NewPrivateKeyMLDSA(params, seed)
}

func NewPublicKeyMLDSA(params MLDSAParameters, publicKey []byte) (*PublicKeyMLDSA, error) {
	return xcrypto.NewPublicKeyMLDSA(params, publicKey)
}

func SupportsChaCha20Poly1305() bool {
	return true
}

func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if fips140only.Enforced() {
		return nil, errors.New("chacha20poly1305: use of ChaCha20Poly1305 is not allowed in FIPS 140-only mode")
	}
	return xcrypto.NewChaCha20Poly1305(key)
}
