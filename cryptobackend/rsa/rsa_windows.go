// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package rsa

import (
	"crypto"
	"hash"
	"math/big"

	"github.com/microsoft/go-crypto-winnative/cng"
)

type BigInt = cng.BigInt
type backendPrivateKey = cng.PrivateKeyRSA
type backendPublicKey = cng.PublicKeyRSA

func supportsPublicKey(bits int) bool { return bits >= 512 && bits%8 == 0 && bits <= 16384 }
func supportsSaltLength(sign bool, salt int) bool {
	if sign {
		return true
	}
	return salt != 0
}
func supportsPKCS1v15Encryption() bool { return true }
func supportsPKCS1v15Signature(h crypto.Hash) bool {
	switch h {
	case 0, crypto.MD5SHA1:
		return true
	default:
		return cng.SupportsHash(h)
	}
}

func supportsPSSHash(h crypto.Hash) bool { return cng.SupportsHash(h) }

func isNativeHash(h hash.Hash) bool {
	_, ok := h.(*cng.Hash)
	return ok
}

func supportsOAEPParameters(h, mgf crypto.Hash, label []byte) bool {
	return h == mgf && cng.SupportsHash(h)
}

func generateKey(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	return cng.GenerateKeyRSA(bits)
}
func newBackendPrivateKey(k *PrivateKey) (*backendPrivateKey, error) {
	return cng.NewPrivateKeyRSA(intBytes(k.pub.n), big.NewInt(int64(k.pub.e)).Bytes(), intBytes(k.d),
		intBytes(k.primes[0]), intBytes(k.primes[1]), intBytes(k.dp), intBytes(k.dq), intBytes(k.qi))
}
func newBackendPublicKey(N *big.Int, e int) (*backendPublicKey, error) {
	return cng.NewPublicKeyRSA(intBytes(N), big.NewInt(int64(e)).Bytes())
}
func encryptOAEP(h, mgfHash hash.Hash, pub *backendPublicKey, msg, label []byte) ([]byte, error) {
	return cng.EncryptRSAOAEP(h, pub, msg, label)
}
func decryptOAEP(h, mgfHash hash.Hash, priv *backendPrivateKey, ciphertext, label []byte) ([]byte, error) {
	return cng.DecryptRSAOAEP(h, priv, ciphertext, label)
}
func encryptNoPadding(pub *backendPublicKey, msg []byte) ([]byte, error) {
	return cng.EncryptRSANoPadding(pub, msg)
}
func decryptNoPadding(priv *backendPrivateKey, ciphertext []byte) ([]byte, error) {
	return cng.DecryptRSANoPadding(priv, ciphertext)
}
func signPKCS1v15(priv *backendPrivateKey, h crypto.Hash, hashed []byte) ([]byte, error) {
	return cng.SignRSAPKCS1v15(priv, h, hashed)
}
func verifyPKCS1v15(pub *backendPublicKey, h crypto.Hash, hashed, sig []byte) error {
	return cng.VerifyRSAPKCS1v15(pub, h, hashed, sig)
}
func signPSS(priv *backendPrivateKey, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	return cng.SignRSAPSS(priv, h, hashed, saltLen)
}
func verifyPSS(pub *backendPublicKey, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	return cng.VerifyRSAPSS(pub, h, hashed, sig, saltLen)
}
