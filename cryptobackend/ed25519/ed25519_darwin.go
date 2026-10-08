// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ed25519

import "github.com/microsoft/go-crypto-darwin/xcrypto"

type backendPrivateKey = xcrypto.PrivateKeyEd25519
type backendPublicKey = xcrypto.PublicKeyEd25519

func Supports() bool                                       { return true }
func generateKey() (backendPrivateKey, error)              { return xcrypto.GenerateKeyEd25519(), nil }
func newPrivateKey(priv []byte) (backendPrivateKey, error) { return xcrypto.NewPrivateKeyEd25519(priv) }
func newPublicKey(pub []byte) (backendPublicKey, error)    { return xcrypto.NewPublicKeyEd25519(pub) }
func newPrivateKeyFromSeed(seed []byte) (backendPrivateKey, error) {
	return xcrypto.NewPrivateKeyEd25519FromSeed(seed)
}
func sign(priv backendPrivateKey, message []byte) ([]byte, error) {
	return xcrypto.SignEd25519(priv, message)
}
func verify(pub backendPublicKey, message, sig []byte) error {
	return xcrypto.VerifyEd25519(pub, message, sig)
}
