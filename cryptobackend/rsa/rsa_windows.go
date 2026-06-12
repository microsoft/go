// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package rsa

import (
	"crypto"
	"hash"

	"github.com/microsoft/go-crypto-winnative/cng"
)

type BigInt = cng.BigInt
type PrivateKey = cng.PrivateKeyRSA
type PublicKey = cng.PublicKeyRSA

func SupportsPrivateKey(bits, primes int) bool { return primes == 2 && SupportsPublicKey(bits) }
func SupportsPublicKey(bits int) bool          { return bits >= 512 && bits%8 == 0 && bits <= 16384 }
func SupportsSaltLength(sign bool, salt int) bool {
	if sign {
		return true
	}
	return salt != 0
}
func SupportsOAEPLabel(label []byte) bool { return true }
func SupportsPKCS1v15Encryption() bool    { return true }
func SupportsPKCS1v15Signature(h crypto.Hash) bool {
	switch h {
	case 0, crypto.MD5SHA1:
		return true
	default:
		return cng.SupportsHash(h)
	}
}

func SupportsPSSHash(h crypto.Hash) bool { return cng.SupportsHash(h) }

func GenerateKey(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	return cng.GenerateKeyRSA(bits)
}
func NewPrivateKey(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKey, error) {
	return cng.NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv)
}
func NewPublicKey(N, E BigInt) (*PublicKey, error) { return cng.NewPublicKeyRSA(N, E) }
func EncryptOAEP(h, mgfHash hash.Hash, pub *PublicKey, msg, label []byte) ([]byte, error) {
	return cng.EncryptRSAOAEP(h, pub, msg, label)
}
func DecryptOAEP(h, mgfHash hash.Hash, priv *PrivateKey, ciphertext, label []byte) ([]byte, error) {
	return cng.DecryptRSAOAEP(h, priv, ciphertext, label)
}
func EncryptPKCS1v15(pub *PublicKey, msg []byte) ([]byte, error) {
	return cng.EncryptRSAPKCS1(pub, msg)
}
func DecryptPKCS1v15(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return cng.DecryptRSAPKCS1(priv, ciphertext)
}
func EncryptNoPadding(pub *PublicKey, msg []byte) ([]byte, error) {
	return cng.EncryptRSANoPadding(pub, msg)
}
func DecryptNoPadding(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return cng.DecryptRSANoPadding(priv, ciphertext)
}
func SignPKCS1v15(priv *PrivateKey, h crypto.Hash, hashed []byte) ([]byte, error) {
	return cng.SignRSAPKCS1v15(priv, h, hashed)
}
func VerifyPKCS1v15(pub *PublicKey, h crypto.Hash, hashed, sig []byte) error {
	return cng.VerifyRSAPKCS1v15(pub, h, hashed, sig)
}
func SignPSS(priv *PrivateKey, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	return cng.SignRSAPSS(priv, h, hashed, saltLen)
}
func VerifyPSS(pub *PublicKey, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	return cng.VerifyRSAPSS(pub, h, hashed, sig, saltLen)
}
