// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux || !cgo || android || cmd_go_bootstrap || msan || no_openssl
// +build !linux !cgo android cmd_go_bootstrap msan no_openssl

package openssl

import (
	"crypto"
	"crypto/cipher"
	"crypto/internal/boring/sig"
	"hash"
	"math/big"
)

const Enabled = false

// Unreachable marks code that should be unreachable
// when OpenSSLCrypto is in use. It is a no-op without OpenSSLCrypto.
func Unreachable() {
	// Code that's unreachable when using OpenSSLCrypto
	// is exactly the code we want to detect for reporting
	// standard Go crypto.
	sig.StandardCrypto()
}

// UnreachableExceptTests marks code that should be unreachable
// when OpenSSLCrypto is in use. It is a no-op without OpenSSLCrypto.
func UnreachableExceptTests() {}

type randReader int

func (randReader) Read(b []byte) (int, error) { panic("opensslcrypto: not available") }

const RandReader = randReader(0)

func NewSHA1() hash.Hash   { panic("opensslcrypto: not available") }
func NewSHA224() hash.Hash { panic("opensslcrypto: not available") }
func NewSHA256() hash.Hash { panic("opensslcrypto: not available") }
func NewSHA384() hash.Hash { panic("opensslcrypto: not available") }
func NewSHA512() hash.Hash { panic("opensslcrypto: not available") }

func NewHMAC(h func() hash.Hash, key []byte) hash.Hash { panic("opensslcrypto: not available") }

func NewAESCipher(key []byte) (cipher.Block, error) { panic("opensslcrypto: not available") }

type PublicKeyECDSA struct{ _ int }
type PrivateKeyECDSA struct{ _ int }

func GenerateKeyECDSA(curve string) (X, Y, D *big.Int, err error) {
	panic("opensslcrypto: not available")
}
func NewPrivateKeyECDSA(curve string, X, Y, D *big.Int) (*PrivateKeyECDSA, error) {
	panic("opensslcrypto: not available")
}
func NewPublicKeyECDSA(curve string, X, Y *big.Int) (*PublicKeyECDSA, error) {
	panic("opensslcrypto: not available")
}
func SignECDSA(priv *PrivateKeyECDSA, hash []byte) (r, s *big.Int, err error) {
	panic("opensslcrypto: not available")
}
func SignMarshalECDSA(priv *PrivateKeyECDSA, hash []byte) ([]byte, error) {
	panic("opensslcrypto: not available")
}
func VerifyECDSA(pub *PublicKeyECDSA, hash []byte, r, s *big.Int) bool {
	panic("opensslcrypto: not available")
}

type PublicKeyRSA struct{ _ int }
type PrivateKeyRSA struct{ _ int }

func DecryptRSAOAEP(h hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	panic("opensslcrypto: not available")
}
func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	panic("opensslcrypto: not available")
}
func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	panic("opensslcrypto: not available")
}
func EncryptRSAOAEP(h hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	panic("opensslcrypto: not available")
}
func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	panic("opensslcrypto: not available")
}
func EncryptRSANoPadding(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	panic("opensslcrypto: not available")
}
func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv *big.Int, err error) {
	panic("opensslcrypto: not available")
}
func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv *big.Int) (*PrivateKeyRSA, error) {
	panic("opensslcrypto: not available")
}
func NewPublicKeyRSA(N, E *big.Int) (*PublicKeyRSA, error) { panic("opensslcrypto: not available") }
func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	panic("opensslcrypto: not available")
}
func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	panic("opensslcrypto: not available")
}
func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	panic("opensslcrypto: not available")
}
func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	panic("opensslcrypto: not available")
}
