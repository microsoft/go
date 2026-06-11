// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package backend

import (
	"crypto"
	"crypto/cipher"
	"hash"
	"io"
)

func init() {
	if err := checkFIPS(func() bool { return false }); err != nil {
		panic(err)
	}
}

const Enabled = false

type BigInt = []uint

type randReader int

func (randReader) Read(b []byte) (int, error) { panic("cryptobackend: not available") }

const RandReader = randReader(0)

func SupportsHash(h crypto.Hash) bool   { panic("cryptobackend: not available") }
func FIPSApprovedHash(h hash.Hash) bool { panic("cryptobackend: not available") }

func SupportsSHAKE(securityBits int) bool  { panic("cryptobackend: not available") }
func SupportsCSHAKE(securityBits int) bool { panic("cryptobackend: not available") }

func SupportsCurve(curve string) bool                    { panic("cryptobackend: not available") }
func SupportsRSAOAEPLabel(label []byte) bool             { panic("cryptobackend: not available") }
func SupportsRSAPKCS1v15Encryption() bool                { panic("cryptobackend: not available") }
func SupportsRSAPKCS1v15Signature(hash crypto.Hash) bool { panic("cryptobackend: not available") }

type Hash struct {
	hash.Cloner
}

func (d *Hash) MarshalBinary() ([]byte, error)        { panic("cryptobackend: not available") }
func (d *Hash) AppendBinary(p []byte) ([]byte, error) { panic("cryptobackend: not available") }
func (d *Hash) UnmarshalBinary(data []byte) error     { panic("cryptobackend: not available") }

type SHAKE struct {
	io.Reader
	hash.Hash
}

func (s *SHAKE) MarshalBinary() ([]byte, error)        { panic("cryptobackend: not available") }
func (s *SHAKE) AppendBinary(p []byte) ([]byte, error) { panic("cryptobackend: not available") }
func (s *SHAKE) UnmarshalBinary(data []byte) error     { panic("cryptobackend: not available") }

func NewMD5() hash.Hash        { panic("cryptobackend: not available") }
func NewSHA1() hash.Hash       { panic("cryptobackend: not available") }
func NewSHA224() hash.Hash     { panic("cryptobackend: not available") }
func NewSHA256() hash.Hash     { panic("cryptobackend: not available") }
func NewSHA384() hash.Hash     { panic("cryptobackend: not available") }
func NewSHA512() hash.Hash     { panic("cryptobackend: not available") }
func NewSHA512_224() hash.Hash { panic("cryptobackend: not available") }
func NewSHA512_256() hash.Hash { panic("cryptobackend: not available") }
func NewSHA3_224() *Hash       { panic("cryptobackend: not available") }
func NewSHA3_256() *Hash       { panic("cryptobackend: not available") }
func NewSHA3_384() *Hash       { panic("cryptobackend: not available") }
func NewSHA3_512() *Hash       { panic("cryptobackend: not available") }

func NewSHAKE128() *SHAKE             { panic("cryptobackend: not available") }
func NewSHAKE256() *SHAKE             { panic("cryptobackend: not available") }
func NewCSHAKE128(N, S []byte) *SHAKE { panic("cryptobackend: not available") }
func NewCSHAKE256(N, S []byte) *SHAKE { panic("cryptobackend: not available") }

func MD5(p []byte) (sum [16]byte)         { panic("cryptobackend: not available") }
func SHA1(p []byte) (sum [20]byte)        { panic("cryptobackend: not available") }
func SHA224(p []byte) (sum [28]byte)      { panic("cryptobackend: not available") }
func SHA256(p []byte) (sum [32]byte)      { panic("cryptobackend: not available") }
func SHA384(p []byte) (sum [48]byte)      { panic("cryptobackend: not available") }
func SHA512(p []byte) (sum [64]byte)      { panic("cryptobackend: not available") }
func SHA512_224(p []byte) (sum [28]byte)  { panic("cryptobackend: not available") }
func SHA512_256(p []byte) (sum [32]byte)  { panic("cryptobackend: not available") }
func SumSHA3_224(p []byte) (sum [28]byte) { panic("cryptobackend: not available") }
func SumSHA3_256(p []byte) (sum [32]byte) { panic("cryptobackend: not available") }
func SumSHA3_384(p []byte) (sum [48]byte) { panic("cryptobackend: not available") }
func SumSHA3_512(p []byte) (sum [64]byte) { panic("cryptobackend: not available") }

func SumSHAKE128(data []byte, length int) (sum []byte) { panic("cryptobackend: not available") }
func SumSHAKE256(data []byte, length int) (sum []byte) { panic("cryptobackend: not available") }

func NewHMAC(h func() hash.Hash, key []byte) hash.Hash { panic("cryptobackend: not available") }

func NewAESCipher(key []byte) (cipher.Block, error)   { panic("cryptobackend: not available") }
func NewGCMTLS(c cipher.Block) (cipher.AEAD, error)   { panic("cryptobackend: not available") }
func NewGCMTLS13(c cipher.Block) (cipher.AEAD, error) { panic("cryptobackend: not available") }

type PublicKeyECDSA struct{ _ int }
type PrivateKeyECDSA struct{ _ int }

func GenerateKeyECDSA(curve string) (X, Y, D BigInt, err error) {
	panic("cryptobackend: not available")
}
func NewPrivateKeyECDSA(curve string, X, Y, D BigInt) (*PrivateKeyECDSA, error) {
	panic("cryptobackend: not available")
}
func NewPublicKeyECDSA(curve string, X, Y BigInt) (*PublicKeyECDSA, error) {
	panic("cryptobackend: not available")
}
func SignMarshalECDSA(priv *PrivateKeyECDSA, hash []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func VerifyECDSA(pub *PublicKeyECDSA, hash []byte, sig []byte) bool {
	panic("cryptobackend: not available")
}
func SupportsRSAPrivateKey(bits, primes int) bool    { panic("cryptobackend: not available") }
func SupportsRSAPublicKey(bits int) bool             { panic("cryptobackend: not available") }
func SupportsRSASaltLength(sign bool, salt int) bool { panic("cryptobackend: not available") }

type PublicKeyRSA struct{ _ int }
type PrivateKeyRSA struct{ _ int }

func DecryptRSAOAEP(h, mgfHash hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func EncryptRSAOAEP(h, mgfHash hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func EncryptRSANoPadding(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	panic("cryptobackend: not available")
}
func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKeyRSA, error) {
	panic("cryptobackend: not available")
}
func NewPublicKeyRSA(N, E BigInt) (*PublicKeyRSA, error) {
	panic("cryptobackend: not available")
}
func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	panic("cryptobackend: not available")
}
func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	panic("cryptobackend: not available")
}
func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	panic("cryptobackend: not available")
}

type PublicKeyECDH struct{}
type PrivateKeyECDH struct{}

func ECDH(*PrivateKeyECDH, *PublicKeyECDH) ([]byte, error)    { panic("cryptobackend: not available") }
func GenerateKeyECDH(string) (*PrivateKeyECDH, []byte, error) { panic("cryptobackend: not available") }
func NewPrivateKeyECDH(string, []byte) (*PrivateKeyECDH, error) {
	panic("cryptobackend: not available")
}
func NewPublicKeyECDH(string, []byte) (*PublicKeyECDH, error) { panic("cryptobackend: not available") }
func (*PublicKeyECDH) Bytes() []byte                          { panic("cryptobackend: not available") }
func (*PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error)    { panic("cryptobackend: not available") }

func SupportsTLS13KDF() bool { panic("cryptobackend: not available") }

func ExpandTLS13KDF(h func() hash.Hash, pseudorandomKey, label, context []byte, keyLength int) ([]byte, error) {
	panic("cryptobackend: not available")
}

func SupportsHKDF() bool { panic("cryptobackend: not available") }

func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte, keyLength int) ([]byte, error) {
	panic("cryptobackend: not available")
}

func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}

func SupportsPBKDF2() bool { panic("cryptobackend: not available") }

func PBKDF2(password, salt []byte, iter, keyLen int, fh func() hash.Hash) ([]byte, error) {
	panic("cryptobackend: not available")
}

func SupportsTLS1PRF() bool { panic("cryptobackend: not available") }

func TLS1PRF(result, secret, label, seed []byte, h func() hash.Hash) error {
	panic("cryptobackend: not available")
}

func SupportsDESCipher() bool { panic("cryptobackend: not available") }

func SupportsTripleDESCipher() bool { panic("cryptobackend: not available") }

func NewDESCipher(key []byte) (cipher.Block, error) { panic("cryptobackend: not available") }

func NewTripleDESCipher(key []byte) (cipher.Block, error) { panic("cryptobackend: not available") }

func SupportsRC4() bool { panic("cryptobackend: not available") }

type RC4Cipher struct{}

func (c *RC4Cipher) Reset()                       { panic("cryptobackend: not available") }
func (c *RC4Cipher) XORKeyStream(dst, src []byte) { panic("cryptobackend: not available") }

func NewRC4Cipher(key []byte) (*RC4Cipher, error) { panic("cryptobackend: not available") }

func SupportsEd25519() bool { panic("cryptobackend: not available") }

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

func SupportsDSA(l, n int) bool {
	panic("cryptobackend: not available")
}

func GenerateParametersDSA(l, n int) (p, q, g BigInt, err error) {
	panic("cryptobackend: not available")
}

type PublicKeyDSA struct{ _ int }
type PrivateKeyDSA struct{ _ int }

func GenerateKeyDSA(p, q, g BigInt) (x, y BigInt, err error) {
	panic("cryptobackend: not available")
}

func NewPrivateKeyDSA(p, q, g, x, y BigInt) (*PrivateKeyDSA, error) {
	panic("cryptobackend: not available")
}

func NewPublicKeyDSA(p, q, g, y BigInt) (*PublicKeyDSA, error) {
	panic("cryptobackend: not available")
}

func SignDSA(priv *PrivateKeyDSA, hash []byte, parseSignature func([]byte) (BigInt, BigInt, error)) (r, s BigInt, err error) {
	panic("cryptobackend: not available")
}

func VerifyDSA(pub *PublicKeyDSA, hashed []byte, r, s BigInt, encodeSignature func(r, s BigInt) ([]byte, error)) bool {
	panic("cryptobackend: not available")
}

func SupportsMLKEM768() bool {
	panic("cryptobackend: not available")
}

func SupportsMLKEM1024() bool {
	panic("cryptobackend: not available")
}

type DecapsulationKeyMLKEM768 struct{}
type EncapsulationKeyMLKEM768 struct{}

func GenerateKeyMLKEM768() (DecapsulationKeyMLKEM768, error) {
	panic("cryptobackend: not available")
}

func NewDecapsulationKeyMLKEM768(seed []byte) (DecapsulationKeyMLKEM768, error) {
	panic("cryptobackend: not available")
}

func NewEncapsulationKeyMLKEM768(encapsulationKey []byte) (EncapsulationKeyMLKEM768, error) {
	panic("cryptobackend: not available")
}

func (dk DecapsulationKeyMLKEM768) Bytes() []byte {
	panic("cryptobackend: not available")
}

func (dk DecapsulationKeyMLKEM768) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	panic("cryptobackend: not available")
}

func (dk DecapsulationKeyMLKEM768) EncapsulationKey() EncapsulationKeyMLKEM768 {
	panic("cryptobackend: not available")
}

func (ek EncapsulationKeyMLKEM768) Bytes() []byte {
	panic("cryptobackend: not available")
}

func (ek EncapsulationKeyMLKEM768) Encapsulate() (sharedKey, ciphertext []byte) {
	panic("cryptobackend: not available")
}

type DecapsulationKeyMLKEM1024 struct{}
type EncapsulationKeyMLKEM1024 struct{}

func GenerateKeyMLKEM1024() (DecapsulationKeyMLKEM1024, error) {
	panic("cryptobackend: not available")
}

func NewDecapsulationKeyMLKEM1024(seed []byte) (DecapsulationKeyMLKEM1024, error) {
	panic("cryptobackend: not available")
}

func NewEncapsulationKeyMLKEM1024(encapsulationKey []byte) (EncapsulationKeyMLKEM1024, error) {
	panic("cryptobackend: not available")
}

func (dk DecapsulationKeyMLKEM1024) Bytes() []byte {
	panic("cryptobackend: not available")
}

func (dk DecapsulationKeyMLKEM1024) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	panic("cryptobackend: not available")
}

func (dk DecapsulationKeyMLKEM1024) EncapsulationKey() EncapsulationKeyMLKEM1024 {
	panic("cryptobackend: not available")
}

func (ek EncapsulationKeyMLKEM1024) Bytes() []byte {
	panic("cryptobackend: not available")
}

func (ek EncapsulationKeyMLKEM1024) Encapsulate() (sharedKey, ciphertext []byte) {
	panic("cryptobackend: not available")
}

type MLDSAParameters struct{}

func MLDSA44() MLDSAParameters {
	panic("cryptobackend: not available")
}

func MLDSA65() MLDSAParameters {
	panic("cryptobackend: not available")
}

func MLDSA87() MLDSAParameters {
	panic("cryptobackend: not available")
}

func (params MLDSAParameters) String() string {
	panic("cryptobackend: not available")
}

func SupportsMLDSA(params MLDSAParameters) bool {
	panic("cryptobackend: not available")
}

func SupportsMLDSAExternalMu() bool {
	panic("cryptobackend: not available")
}

type PrivateKeyMLDSA struct{}
type PublicKeyMLDSA struct{}

func GenerateKeyMLDSA(params MLDSAParameters) (*PrivateKeyMLDSA, error) {
	panic("cryptobackend: not available")
}

func NewPrivateKeyMLDSA(params MLDSAParameters, seed []byte) (*PrivateKeyMLDSA, error) {
	panic("cryptobackend: not available")
}

func NewPublicKeyMLDSA(params MLDSAParameters, publicKey []byte) (*PublicKeyMLDSA, error) {
	panic("cryptobackend: not available")
}

func (key *PrivateKeyMLDSA) Bytes() []byte {
	panic("cryptobackend: not available")
}

func (key *PrivateKeyMLDSA) Equal(other *PrivateKeyMLDSA) bool {
	panic("cryptobackend: not available")
}

func (key *PrivateKeyMLDSA) Parameters() MLDSAParameters {
	panic("cryptobackend: not available")
}

func (key *PrivateKeyMLDSA) PublicKey() *PublicKeyMLDSA {
	panic("cryptobackend: not available")
}

func (key *PrivateKeyMLDSA) Sign(message []byte, context string) ([]byte, error) {
	panic("cryptobackend: not available")
}

func (key *PrivateKeyMLDSA) SignExternalMu(mu []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}

func (key *PublicKeyMLDSA) Bytes() []byte {
	panic("cryptobackend: not available")
}

func (key *PublicKeyMLDSA) Equal(other *PublicKeyMLDSA) bool {
	panic("cryptobackend: not available")
}

func (key *PublicKeyMLDSA) Parameters() MLDSAParameters {
	panic("cryptobackend: not available")
}

func (key *PublicKeyMLDSA) Verify(message, signature []byte, context string) error {
	panic("cryptobackend: not available")
}

func (key *PublicKeyMLDSA) VerifyExternalMu(mu, signature []byte) error {
	panic("cryptobackend: not available")
}

func SupportsChaCha20Poly1305() bool {
	return false
}

func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	panic("cryptobackend: not available")
}
