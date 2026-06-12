// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package rsa

import (
	"crypto"
	"hash"
)

type BigInt = []uint
type PrivateKey struct{ _ int }
type PublicKey struct{ _ int }

func SupportsPrivateKey(bits, primes int) bool     { panic("cryptobackend: not available") }
func SupportsPublicKey(bits int) bool              { panic("cryptobackend: not available") }
func SupportsSaltLength(sign bool, salt int) bool  { panic("cryptobackend: not available") }
func SupportsOAEPLabel(label []byte) bool          { panic("cryptobackend: not available") }
func SupportsPKCS1v15Encryption() bool             { panic("cryptobackend: not available") }
func SupportsPKCS1v15Signature(h crypto.Hash) bool { panic("cryptobackend: not available") }
func SupportsPSSHash(h crypto.Hash) bool           { panic("cryptobackend: not available") }
func GenerateKey(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	panic("cryptobackend: not available")
}
func NewPrivateKey(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}
func NewPublicKey(N, E BigInt) (*PublicKey, error) { panic("cryptobackend: not available") }
func EncryptOAEP(h, mgfHash hash.Hash, pub *PublicKey, msg, label []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func DecryptOAEP(h, mgfHash hash.Hash, priv *PrivateKey, ciphertext, label []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func EncryptPKCS1v15(pub *PublicKey, msg []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func DecryptPKCS1v15(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func EncryptNoPadding(pub *PublicKey, msg []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func DecryptNoPadding(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func SignPKCS1v15(priv *PrivateKey, h crypto.Hash, hashed []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func VerifyPKCS1v15(pub *PublicKey, h crypto.Hash, hashed, sig []byte) error {
	panic("cryptobackend: not available")
}
func SignPSS(priv *PrivateKey, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	panic("cryptobackend: not available")
}
func VerifyPSS(pub *PublicKey, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	panic("cryptobackend: not available")
}
