// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

// Package openssl provides access to OpenSSLCrypto implementation functions.
// Check the variable Enabled to find out whether OpenSSLCrypto is available.
// If OpenSSLCrypto is not available, the functions in this package all panic.
package backend

import (
	"crypto"
	"crypto/cipher"
	"crypto/internal/boring/sig"
	"crypto/internal/fips140only"
	"errors"
	"github.com/microsoft/go/cryptobackend/fips140"
	"hash"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go-crypto-openssl/osslsetup"
)

// Enabled controls whether FIPS crypto is enabled.
const Enabled = true

type BigInt = openssl.BigInt

func init() {
	// Some distributions, e.g. Azure Linux 3, don't set the `fips=yes` property when running in FIPS mode,
	// but they configure OpenSSL to use a FIPS-compliant provider (in the case of Azure Linux 3, the SCOSSL provider).
	// In this cases, openssl.FIPS would return `false` and openssl.FIPSCapable would return `true`.
	// We don't care about the `fips=yes` property as long as the provider is FIPS-compliant, so use
	// osslsetup.FIPSCapable to determine whether FIPS mode is enabled.
	if err := checkFIPS(func() bool { return osslsetup.FIPSCapable() }); err != nil {
		// This path can be reached for the following reasons:
		// - In OpenSSL 1, the active engine doesn't support FIPS mode.
		// - In OpenSSL 1, the active engine supports FIPS mode, but it is not enabled.
		// - In OpenSSL 3, the provider used by default doesn't match the `fips=yes` query.
		panic("opensslcrypto: " + err.Error() + ": " + osslsetup.VersionText())
	}
	sig.BoringCrypto()
	fips140only.BackendApprovedHash = FIPSApprovedHash
}

const RandReader = openssl.RandReader

func SupportsHash(h crypto.Hash) bool {
	return openssl.SupportsHash(h)
}

func FIPSApprovedHash(h hash.Hash) bool {
	return openssl.FIPSApprovedHash(h)
}

func SupportsSHAKE(securityBits int) bool {
	return openssl.SupportsSHAKE(securityBits)
}

func SupportsCSHAKE(securityBits int) bool {
	return openssl.SupportsCSHAKE(securityBits)
}

func SupportsCurve(curve string) bool {
	return openssl.SupportsCurve(curve)
}

func SupportsRSAOAEPLabel(label []byte) bool { return true }

func SupportsRSAPKCS1v15Encryption() bool {
	return openssl.SupportsRSAPKCS1v15Encryption()
}

func SupportsRSAPKCS1v15Signature(hash crypto.Hash) bool {
	return openssl.SupportsRSAPKCS1v15Signature(hash)
}

type Hash = openssl.Hash
type SHAKE = openssl.SHAKE

func NewMD5() hash.Hash        { return openssl.NewMD5() }
func NewSHA1() hash.Hash       { return openssl.NewSHA1() }
func NewSHA224() hash.Hash     { return openssl.NewSHA224() }
func NewSHA256() hash.Hash     { return openssl.NewSHA256() }
func NewSHA384() hash.Hash     { return openssl.NewSHA384() }
func NewSHA512() hash.Hash     { return openssl.NewSHA512() }
func NewSHA512_224() hash.Hash { return openssl.NewSHA512_224() }
func NewSHA512_256() hash.Hash { return openssl.NewSHA512_256() }
func NewSHA3_224() *Hash       { return openssl.NewSHA3_224() }
func NewSHA3_256() *Hash       { return openssl.NewSHA3_256() }
func NewSHA3_384() *Hash       { return openssl.NewSHA3_384() }
func NewSHA3_512() *Hash       { return openssl.NewSHA3_512() }

func NewSHAKE128() *SHAKE             { return openssl.NewSHAKE128() }
func NewSHAKE256() *SHAKE             { return openssl.NewSHAKE256() }
func NewCSHAKE128(N, S []byte) *SHAKE { return openssl.NewCSHAKE128(N, S) }
func NewCSHAKE256(N, S []byte) *SHAKE { return openssl.NewCSHAKE256(N, S) }

func MD5(p []byte) (sum [16]byte)         { return openssl.MD5(p) }
func SHA1(p []byte) (sum [20]byte)        { return openssl.SHA1(p) }
func SHA224(p []byte) (sum [28]byte)      { return openssl.SHA224(p) }
func SHA256(p []byte) (sum [32]byte)      { return openssl.SHA256(p) }
func SHA384(p []byte) (sum [48]byte)      { return openssl.SHA384(p) }
func SHA512(p []byte) (sum [64]byte)      { return openssl.SHA512(p) }
func SHA512_224(p []byte) (sum [28]byte)  { return openssl.SHA512_224(p) }
func SHA512_256(p []byte) (sum [32]byte)  { return openssl.SHA512_256(p) }
func SumSHA3_224(p []byte) (sum [28]byte) { return openssl.SumSHA3_224(p) }
func SumSHA3_256(p []byte) (sum [32]byte) { return openssl.SumSHA3_256(p) }
func SumSHA3_384(p []byte) (sum [48]byte) { return openssl.SumSHA3_384(p) }
func SumSHA3_512(p []byte) (sum [64]byte) { return openssl.SumSHA3_512(p) }

func SumSHAKE128(data []byte, length int) (sum []byte) { return openssl.SumSHAKE128(data, length) }
func SumSHAKE256(data []byte, length int) (sum []byte) { return openssl.SumSHAKE256(data, length) }

func NewHMAC(h func() hash.Hash, key []byte) hash.Hash { return openssl.NewHMAC(h, key) }

func NewAESCipher(key []byte) (cipher.Block, error)   { return openssl.NewAESCipher(key) }
func NewGCMTLS(c cipher.Block) (cipher.AEAD, error)   { return openssl.NewGCMTLS(c) }
func NewGCMTLS13(c cipher.Block) (cipher.AEAD, error) { return openssl.NewGCMTLS13(c) }

type PublicKeyECDSA = openssl.PublicKeyECDSA
type PrivateKeyECDSA = openssl.PrivateKeyECDSA

func GenerateKeyECDSA(curve string) (X, Y, D openssl.BigInt, err error) {
	return openssl.GenerateKeyECDSA(curve)
}

func NewPrivateKeyECDSA(curve string, X, Y, D openssl.BigInt) (*openssl.PrivateKeyECDSA, error) {
	return openssl.NewPrivateKeyECDSA(curve, X, Y, D)
}

func NewPublicKeyECDSA(curve string, X, Y openssl.BigInt) (*openssl.PublicKeyECDSA, error) {
	return openssl.NewPublicKeyECDSA(curve, X, Y)
}

func SignMarshalECDSA(priv *openssl.PrivateKeyECDSA, hash []byte) ([]byte, error) {
	return openssl.SignMarshalECDSA(priv, hash)
}

func VerifyECDSA(pub *openssl.PublicKeyECDSA, hash []byte, sig []byte) bool {
	return openssl.VerifyECDSA(pub, hash, sig)
}

func SupportsRSAPrivateKey(bits, primes int) bool {
	// The built-in OpenSSL 3 providers and OpenSSL 1 do support n-prime RSA keys,
	// but SCOSSL only supports 2-prime RSA keys.
	// Only 2-prime RSA keys are FIPS compliant, other n having compatibility
	// and security issues. Even crypto/rsa deprecated rsa.GenerateMultiPrimeKey as of Go 1.21.
	// Given the above reasons, we only support what SCOSSL supports.
	return primes == 2 && SupportsRSAPublicKey(bits)
}

func SupportsRSAPublicKey(bits int) bool {
	min := 1024
	if fips140.Enabled() {
		// The built-in OpenSSL 3 FIPS provider requires at least 2048 bits for FIPS compliance.
		min = 2048
	}
	return bits >= min && bits%8 == 0 && bits <= 16384
}

func SupportsRSASaltLength(sign bool, salt int) bool {
	return true
}

type PublicKeyRSA = openssl.PublicKeyRSA
type PrivateKeyRSA = openssl.PrivateKeyRSA

func DecryptRSAOAEP(h, mgfHash hash.Hash, priv *openssl.PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	return openssl.DecryptRSAOAEP(h, mgfHash, priv, ciphertext, label)
}

func DecryptRSAPKCS1(priv *openssl.PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return openssl.DecryptRSAPKCS1(priv, ciphertext)
}

func DecryptRSANoPadding(priv *openssl.PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return openssl.DecryptRSANoPadding(priv, ciphertext)
}

func EncryptRSAOAEP(h, mgfHash hash.Hash, pub *openssl.PublicKeyRSA, msg, label []byte) ([]byte, error) {
	return openssl.EncryptRSAOAEP(h, mgfHash, pub, msg, label)
}

func EncryptRSAPKCS1(pub *openssl.PublicKeyRSA, msg []byte) ([]byte, error) {
	return openssl.EncryptRSAPKCS1(pub, msg)
}

func EncryptRSANoPadding(pub *openssl.PublicKeyRSA, msg []byte) ([]byte, error) {
	return openssl.EncryptRSANoPadding(pub, msg)
}

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv openssl.BigInt, err error) {
	return openssl.GenerateKeyRSA(bits)
}

func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv openssl.BigInt) (*openssl.PrivateKeyRSA, error) {
	return openssl.NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv)
}

func NewPublicKeyRSA(N, E openssl.BigInt) (*openssl.PublicKeyRSA, error) {
	return openssl.NewPublicKeyRSA(N, E)
}

func SignRSAPKCS1v15(priv *openssl.PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	return openssl.SignRSAPKCS1v15(priv, h, hashed)
}

func SignRSAPSS(priv *openssl.PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	return openssl.SignRSAPSS(priv, h, hashed, saltLen)
}

func VerifyRSAPKCS1v15(pub *openssl.PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	return openssl.VerifyRSAPKCS1v15(pub, h, hashed, sig)
}

func VerifyRSAPSS(pub *openssl.PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	return openssl.VerifyRSAPSS(pub, h, hashed, sig, saltLen)
}

type PublicKeyECDH = openssl.PublicKeyECDH
type PrivateKeyECDH = openssl.PrivateKeyECDH

func ECDH(priv *openssl.PrivateKeyECDH, pub *openssl.PublicKeyECDH) ([]byte, error) {
	return openssl.ECDH(priv, pub)
}

func GenerateKeyECDH(curve string) (*openssl.PrivateKeyECDH, []byte, error) {
	return openssl.GenerateKeyECDH(curve)
}

func NewPrivateKeyECDH(curve string, bytes []byte) (*openssl.PrivateKeyECDH, error) {
	return openssl.NewPrivateKeyECDH(curve, bytes)
}

func NewPublicKeyECDH(curve string, bytes []byte) (*openssl.PublicKeyECDH, error) {
	return openssl.NewPublicKeyECDH(curve, bytes)
}

func SupportsTLS13KDF() bool {
	return openssl.SupportsTLS13KDF()
}

func ExpandTLS13KDF(h func() hash.Hash, pseudorandomKey, label, context []byte, keyLength int) ([]byte, error) {
	return openssl.ExpandTLS13KDF(h, pseudorandomKey, label, context, keyLength)
}

func SupportsHKDF() bool {
	return openssl.SupportsHKDF()
}

func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte, keyLength int) ([]byte, error) {
	return openssl.ExpandHKDF(h, pseudorandomKey, info, keyLength)
}

func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	return openssl.ExtractHKDF(h, secret, salt)
}

func SupportsPBKDF2() bool {
	return openssl.SupportsPBKDF2()
}

func PBKDF2(pass, salt []byte, iter, keyLen int, h func() hash.Hash) ([]byte, error) {
	return openssl.PBKDF2(pass, salt, iter, keyLen, h)
}

func SupportsTLS1PRF() bool {
	return openssl.SupportsTLS1PRF()
}

func TLS1PRF(result, secret, label, seed []byte, h func() hash.Hash) error {
	return openssl.TLS1PRF(result, secret, label, seed, h)
}

func SupportsDESCipher() bool {
	return openssl.SupportsDESCipher()
}

func SupportsTripleDESCipher() bool {
	return openssl.SupportsTripleDESCipher()
}

func NewDESCipher(key []byte) (cipher.Block, error) {
	return openssl.NewDESCipher(key)
}

func NewTripleDESCipher(key []byte) (cipher.Block, error) {
	return openssl.NewTripleDESCipher(key)
}

func SupportsRC4() bool {
	return openssl.SupportsRC4()
}

type RC4Cipher = openssl.RC4Cipher

func NewRC4Cipher(key []byte) (*RC4Cipher, error) { return openssl.NewRC4Cipher(key) }

func SupportsEd25519() bool { return openssl.SupportsEd25519() }

type PublicKeyEd25519 = *openssl.PublicKeyEd25519
type PrivateKeyEd25519 = *openssl.PrivateKeyEd25519

func GenerateKeyEd25519() (PrivateKeyEd25519, error) {
	return openssl.GenerateKeyEd25519()
}

// Deprecated: use NewPrivateKeyEd25519 instead.
func NewPrivateKeyEd25119(priv []byte) (PrivateKeyEd25519, error) {
	return openssl.NewPrivateKeyEd25519(priv)
}

// Deprecated: use NewPublicKeyEd25519 instead.
func NewPublicKeyEd25119(pub []byte) (PublicKeyEd25519, error) {
	return openssl.NewPublicKeyEd25519(pub)
}

func NewPrivateKeyEd25519(priv []byte) (PrivateKeyEd25519, error) {
	return openssl.NewPrivateKeyEd25519(priv)
}

func NewPublicKeyEd25519(pub []byte) (PublicKeyEd25519, error) {
	return openssl.NewPublicKeyEd25519(pub)
}

func NewPrivateKeyEd25519FromSeed(seed []byte) (PrivateKeyEd25519, error) {
	return openssl.NewPrivateKeyEd25519FromSeed(seed)
}

func SignEd25519(priv PrivateKeyEd25519, message []byte) ([]byte, error) {
	return openssl.SignEd25519(priv, message)
}

func VerifyEd25519(pub PublicKeyEd25519, message, sig []byte) error {
	return openssl.VerifyEd25519(pub, message, sig)
}

type PublicKeyDSA = openssl.PublicKeyDSA
type PrivateKeyDSA = openssl.PrivateKeyDSA

func SupportsDSA(l, n int) bool {
	return openssl.SupportsDSA()
}

func GenerateParametersDSA(l, n int) (p, q, g openssl.BigInt, err error) {
	params, err := openssl.GenerateParametersDSA(l, n)
	return params.P, params.Q, params.G, err
}

func GenerateKeyDSA(p, q, g openssl.BigInt) (x, y openssl.BigInt, err error) {
	return openssl.GenerateKeyDSA(openssl.DSAParameters{P: p, Q: q, G: g})
}

func NewPrivateKeyDSA(p, q, g, x, y openssl.BigInt) (*openssl.PrivateKeyDSA, error) {
	return openssl.NewPrivateKeyDSA(openssl.DSAParameters{P: p, Q: q, G: g}, x, y)
}

func NewPublicKeyDSA(p, q, g, y openssl.BigInt) (*openssl.PublicKeyDSA, error) {
	return openssl.NewPublicKeyDSA(openssl.DSAParameters{P: p, Q: q, G: g}, y)
}

func SignDSA(priv *PrivateKeyDSA, hash []byte, parseSignature func([]byte) (openssl.BigInt, openssl.BigInt, error)) (r, s openssl.BigInt, err error) {
	sig, err := openssl.SignDSA(priv, hash)
	if err != nil {
		return nil, nil, err
	}

	r, s, err = parseSignature(sig)
	if err != nil {
		return nil, nil, err
	}

	return openssl.BigInt(r), openssl.BigInt(s), nil
}

func VerifyDSA(pub *PublicKeyDSA, hashed []byte, r, s openssl.BigInt, encodeSignature func(r, s openssl.BigInt) ([]byte, error)) bool {
	sig, err := encodeSignature(r, s)
	if err != nil {
		return false
	}

	return openssl.VerifyDSA(pub, hashed, sig)
}

func SupportsMLKEM768() bool {
	return openssl.SupportsMLKEM768()
}

func SupportsMLKEM1024() bool {
	return openssl.SupportsMLKEM1024()
}

type DecapsulationKeyMLKEM768 = openssl.DecapsulationKeyMLKEM768
type EncapsulationKeyMLKEM768 = openssl.EncapsulationKeyMLKEM768

func GenerateKeyMLKEM768() (DecapsulationKeyMLKEM768, error) {
	return openssl.GenerateKeyMLKEM768()
}

func NewDecapsulationKeyMLKEM768(seed []byte) (DecapsulationKeyMLKEM768, error) {
	return openssl.NewDecapsulationKeyMLKEM768(seed)
}

func NewEncapsulationKeyMLKEM768(encapsulationKey []byte) (EncapsulationKeyMLKEM768, error) {
	return openssl.NewEncapsulationKeyMLKEM768(encapsulationKey)
}

type DecapsulationKeyMLKEM1024 = openssl.DecapsulationKeyMLKEM1024
type EncapsulationKeyMLKEM1024 = openssl.EncapsulationKeyMLKEM1024

func GenerateKeyMLKEM1024() (DecapsulationKeyMLKEM1024, error) {
	return openssl.GenerateKeyMLKEM1024()
}

func NewDecapsulationKeyMLKEM1024(seed []byte) (DecapsulationKeyMLKEM1024, error) {
	return openssl.NewDecapsulationKeyMLKEM1024(seed)
}

func NewEncapsulationKeyMLKEM1024(encapsulationKey []byte) (EncapsulationKeyMLKEM1024, error) {
	return openssl.NewEncapsulationKeyMLKEM1024(encapsulationKey)
}

type MLDSAParameters = openssl.MLDSAParameters

func MLDSA44() MLDSAParameters { return openssl.MLDSA44() }
func MLDSA65() MLDSAParameters { return openssl.MLDSA65() }
func MLDSA87() MLDSAParameters { return openssl.MLDSA87() }

func SupportsMLDSA(params MLDSAParameters) bool {
	return openssl.SupportsMLDSA(params)
}

// SupportsMLDSAExternalMu reports whether the backend can sign a pre-hashed mu
// message representative directly. OpenSSL implements external-mu signing.
func SupportsMLDSAExternalMu() bool { return true }

type PrivateKeyMLDSA = openssl.PrivateKeyMLDSA
type PublicKeyMLDSA = openssl.PublicKeyMLDSA

func GenerateKeyMLDSA(params MLDSAParameters) (*PrivateKeyMLDSA, error) {
	return openssl.GenerateKeyMLDSA(params)
}

func NewPrivateKeyMLDSA(params MLDSAParameters, seed []byte) (*PrivateKeyMLDSA, error) {
	return openssl.NewPrivateKeyMLDSA(params, seed)
}

func NewPublicKeyMLDSA(params MLDSAParameters, publicKey []byte) (*PublicKeyMLDSA, error) {
	return openssl.NewPublicKeyMLDSA(params, publicKey)
}

func SupportsChaCha20Poly1305() bool {
	return openssl.SupportsChaCha20Poly1305()
}

func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if fips140only.Enforced() {
		return nil, errors.New("chacha20poly1305: use of ChaCha20Poly1305 is not allowed in FIPS 140-only mode")
	}
	return openssl.NewChaCha20Poly1305(key)
}
