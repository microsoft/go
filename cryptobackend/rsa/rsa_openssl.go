// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package rsa

import (
	"crypto"
	"hash"
	"math/big"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go/cryptobackend/bbig"
	bfips140 "github.com/microsoft/go/cryptobackend/fips140"
)

type BigInt = openssl.BigInt
type backendPrivateKey = openssl.PrivateKeyRSA
type backendPublicKey = openssl.PublicKeyRSA

func supportsPublicKey(bits int) bool {
	min := 1024
	if bfips140.Enabled() {
		min = 2048
	}
	return bits >= min && bits%8 == 0 && bits <= 16384
}

func supportsPrimeSizes(p, q int) bool             { return true }
func supportsSaltLength(sign bool, salt int) bool  { return true }
func supportsPKCS1v15Encryption() bool             { return openssl.SupportsRSAPKCS1v15Encryption() }
func supportsPKCS1v15Signature(h crypto.Hash) bool { return openssl.SupportsRSAPKCS1v15Signature(h) }
func supportsPSSHash(h crypto.Hash) bool           { return openssl.SupportsRSAPSS(h) }

func isNativeHash(h hash.Hash) bool {
	_, ok := h.(*openssl.Hash)
	return ok
}

func supportsOAEP(h, mgfHash hash.Hash, label []byte) bool {
	return nativeHashAlgorithm(h) != 0 && nativeHashAlgorithm(mgfHash) != 0 &&
		openssl.SupportsRSAOAEP(h, mgfHash)
}

func generateKey(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	return openssl.GenerateKeyRSA(bits)
}

func newBackendPrivateKey(k *PrivateKey) (*backendPrivateKey, error) {
	return openssl.NewPrivateKeyRSA(bbig.Enc(k.pub.n), bbig.Enc(big.NewInt(int64(k.pub.e))),
		bbig.Enc(k.d), bbig.Enc(k.primes[0]), bbig.Enc(k.primes[1]),
		bbig.Enc(k.dp), bbig.Enc(k.dq), bbig.Enc(k.qi))
}

func newBackendPublicKey(N *big.Int, e int) (*backendPublicKey, error) {
	return openssl.NewPublicKeyRSA(bbig.Enc(N), bbig.Enc(big.NewInt(int64(e))))
}

func encryptOAEP(h, mgfHash hash.Hash, pub *backendPublicKey, msg, label []byte) ([]byte, error) {
	return openssl.EncryptRSAOAEP(h, mgfHash, pub, msg, label)
}

func decryptOAEP(h, mgfHash hash.Hash, priv *backendPrivateKey, ciphertext, label []byte) ([]byte, error) {
	return openssl.DecryptRSAOAEP(h, mgfHash, priv, ciphertext, label)
}

func encryptNoPadding(pub *backendPublicKey, msg []byte) ([]byte, error) {
	return openssl.EncryptRSANoPadding(pub, msg)
}

func decryptNoPadding(priv *backendPrivateKey, ciphertext []byte) ([]byte, error) {
	return openssl.DecryptRSANoPadding(priv, ciphertext)
}

func signPKCS1v15(priv *backendPrivateKey, h crypto.Hash, hashed []byte) ([]byte, error) {
	return openssl.SignRSAPKCS1v15(priv, h, hashed)
}

func verifyPKCS1v15(pub *backendPublicKey, h crypto.Hash, hashed, sig []byte) error {
	return openssl.VerifyRSAPKCS1v15(pub, h, hashed, sig)
}

func signPSS(priv *backendPrivateKey, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	return openssl.SignRSAPSS(priv, h, hashed, saltLen)
}

func verifyPSS(pub *backendPublicKey, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	return openssl.VerifyRSAPSS(pub, h, hashed, sig, saltLen)
}
