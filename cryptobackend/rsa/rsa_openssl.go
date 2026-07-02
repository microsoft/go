// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto && (linux || freebsd)

package rsa

import (
	"crypto"
	"hash"

	"github.com/microsoft/go-crypto-openssl/openssl"
	bfips140 "github.com/microsoft/go/cryptobackend/fips140"
)

type BigInt = openssl.BigInt
type PrivateKey = openssl.PrivateKeyRSA
type PublicKey = openssl.PublicKeyRSA

func SupportsPrivateKey(bits, primes int) bool { return primes == 2 && SupportsPublicKey(bits) }

func SupportsPublicKey(bits int) bool {
	min := 1024
	if bfips140.Enabled() {
		min = 2048
	}
	return bits >= min && bits%8 == 0 && bits <= 16384
}

func SupportsSaltLength(sign bool, salt int) bool  { return true }
func SupportsOAEPLabel(label []byte) bool          { return true }
func SupportsPKCS1v15Encryption() bool             { return openssl.SupportsRSAPKCS1v15Encryption() }
func SupportsPKCS1v15Signature(h crypto.Hash) bool { return openssl.SupportsRSAPKCS1v15Signature(h) }
func SupportsPSSHash(h crypto.Hash) bool           { return openssl.SupportsHash(h) }

func GenerateKey(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	return openssl.GenerateKeyRSA(bits)
}

func NewPrivateKey(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKey, error) {
	return openssl.NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv)
}

func NewPublicKey(N, E BigInt) (*PublicKey, error) { return openssl.NewPublicKeyRSA(N, E) }

func EncryptOAEP(h, mgfHash hash.Hash, pub *PublicKey, msg, label []byte) ([]byte, error) {
	return openssl.EncryptRSAOAEP(h, mgfHash, pub, msg, label)
}

func DecryptOAEP(h, mgfHash hash.Hash, priv *PrivateKey, ciphertext, label []byte) ([]byte, error) {
	return openssl.DecryptRSAOAEP(h, mgfHash, priv, ciphertext, label)
}

func EncryptPKCS1v15(pub *PublicKey, msg []byte) ([]byte, error) {
	return openssl.EncryptRSAPKCS1(pub, msg)
}

func DecryptPKCS1v15(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return openssl.DecryptRSAPKCS1(priv, ciphertext)
}

func EncryptNoPadding(pub *PublicKey, msg []byte) ([]byte, error) {
	return openssl.EncryptRSANoPadding(pub, msg)
}

func DecryptNoPadding(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return openssl.DecryptRSANoPadding(priv, ciphertext)
}

func SignPKCS1v15(priv *PrivateKey, h crypto.Hash, hashed []byte) ([]byte, error) {
	return openssl.SignRSAPKCS1v15(priv, h, hashed)
}

func VerifyPKCS1v15(pub *PublicKey, h crypto.Hash, hashed, sig []byte) error {
	return openssl.VerifyRSAPKCS1v15(pub, h, hashed, sig)
}

func SignPSS(priv *PrivateKey, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	return openssl.SignRSAPSS(priv, h, hashed, saltLen)
}

func VerifyPSS(pub *PublicKey, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	return openssl.VerifyRSAPSS(pub, h, hashed, sig, saltLen)
}
