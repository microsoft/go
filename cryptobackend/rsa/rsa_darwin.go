// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package rsa

import (
	"crypto"
	"hash"
	_ "unsafe"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

type BigInt = xcrypto.BigInt
type PrivateKey = xcrypto.PrivateKeyRSA
type PublicKey = xcrypto.PublicKeyRSA

func SupportsPrivateKey(bits, primes int) bool    { return primes == 2 && SupportsPublicKey(bits) }
func SupportsPublicKey(bits int) bool             { return bits >= 1024 && bits%8 == 0 && bits <= 16384 }
func SupportsSaltLength(sign bool, salt int) bool { return salt == -1 }
func SupportsOAEPLabel(label []byte) bool         { return len(label) == 0 }
func SupportsPKCS1v15Encryption() bool            { return true }
func SupportsPKCS1v15Signature(h crypto.Hash) bool {
	switch h {
	case crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512, 0:
		return true
	}
	return false
}

func SupportsPSSHash(h crypto.Hash) bool { return xcrypto.SupportsHash(h) }

//go:linkname decodeKey crypto/rsa.decodeKey
func decodeKey(data []byte) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error)

//go:linkname encodeKey crypto/rsa.encodeKey
func encodeKey(N, E, D, P, Q, Dp, Dq, Qinv BigInt) ([]byte, error)

//go:linkname encodePublicKey crypto/rsa.encodePublicKey
func encodePublicKey(N, E BigInt) ([]byte, error)

func GenerateKey(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	data, err := xcrypto.GenerateKeyRSA(bits)
	if err != nil {
		return
	}
	return decodeKey(data)
}

func NewPrivateKey(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKey, error) {
	encoded, err := encodeKey(N, E, D, P, Q, Dp, Dq, Qinv)
	if err != nil {
		return nil, err
	}
	return xcrypto.NewPrivateKeyRSA(encoded)
}

func NewPublicKey(N, E BigInt) (*PublicKey, error) {
	encoded, err := encodePublicKey(N, E)
	if err != nil {
		return nil, err
	}
	return xcrypto.NewPublicKeyRSA(encoded)
}

func EncryptOAEP(h, mgfHash hash.Hash, pub *PublicKey, msg, label []byte) ([]byte, error) {
	return xcrypto.EncryptRSAOAEP(h, pub, msg, label)
}

func DecryptOAEP(h, mgfHash hash.Hash, priv *PrivateKey, ciphertext, label []byte) ([]byte, error) {
	return xcrypto.DecryptRSAOAEP(h, priv, ciphertext, label)
}

func EncryptPKCS1v15(pub *PublicKey, msg []byte) ([]byte, error) {
	return xcrypto.EncryptRSAPKCS1(pub, msg)
}
func DecryptPKCS1v15(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return xcrypto.DecryptRSAPKCS1(priv, ciphertext)
}
func EncryptNoPadding(pub *PublicKey, msg []byte) ([]byte, error) {
	return xcrypto.EncryptRSANoPadding(pub, msg)
}
func DecryptNoPadding(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return xcrypto.DecryptRSANoPadding(priv, ciphertext)
}
func SignPKCS1v15(priv *PrivateKey, h crypto.Hash, hashed []byte) ([]byte, error) {
	return xcrypto.SignRSAPKCS1v15(priv, h, hashed)
}
func VerifyPKCS1v15(pub *PublicKey, h crypto.Hash, hashed, sig []byte) error {
	return xcrypto.VerifyRSAPKCS1v15(pub, h, hashed, sig)
}
func SignPSS(priv *PrivateKey, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	return xcrypto.SignRSAPSS(priv, h, hashed, saltLen)
}
func VerifyPSS(pub *PublicKey, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	return xcrypto.VerifyRSAPSS(pub, h, hashed, sig, saltLen)
}
