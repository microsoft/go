// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package rsa

import (
	"crypto"
	"hash"
	"math/big"
)

type BigInt = []uint
type backendPrivateKey struct{}
type backendPublicKey struct{}

func supportsPublicKey(bits int) bool              { panic("cryptobackend: not available") }
func supportsPrimeSizes(p, q int) bool             { panic("cryptobackend: not available") }
func supportsSaltLength(sign bool, salt int) bool  { panic("cryptobackend: not available") }
func supportsPKCS1v15Encryption() bool             { panic("cryptobackend: not available") }
func supportsPKCS1v15Signature(h crypto.Hash) bool { panic("cryptobackend: not available") }
func supportsPSSHash(h crypto.Hash) bool           { panic("cryptobackend: not available") }
func isNativeHash(h hash.Hash) bool                { return false }
func supportsOAEP(h, mgfHash hash.Hash, label []byte) bool {
	panic("cryptobackend: not available")
}
func generateKey(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	panic("cryptobackend: not available")
}
func newBackendPrivateKey(k *PrivateKey) (*backendPrivateKey, error) {
	panic("cryptobackend: not available")
}
func newBackendPublicKey(N *big.Int, e int) (*backendPublicKey, error) {
	panic("cryptobackend: not available")
}
func encryptOAEP(h, mgfHash hash.Hash, pub *backendPublicKey, msg, label []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func decryptOAEP(h, mgfHash hash.Hash, priv *backendPrivateKey, ciphertext, label []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func encryptNoPadding(pub *backendPublicKey, msg []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func decryptNoPadding(priv *backendPrivateKey, ciphertext []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func signPKCS1v15(priv *backendPrivateKey, h crypto.Hash, hashed []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func verifyPKCS1v15(pub *backendPublicKey, h crypto.Hash, hashed, sig []byte) error {
	panic("cryptobackend: not available")
}
func signPSS(priv *backendPrivateKey, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	panic("cryptobackend: not available")
}
func verifyPSS(pub *backendPublicKey, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	panic("cryptobackend: not available")
}
