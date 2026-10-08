// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package ed25519

import "github.com/microsoft/go-crypto-openssl/openssl"

type backendPrivateKey = *openssl.PrivateKeyEd25519
type backendPublicKey = *openssl.PublicKeyEd25519

func Supports() bool                                       { return openssl.SupportsEd25519() }
func generateKey() (backendPrivateKey, error)              { return openssl.GenerateKeyEd25519() }
func newPrivateKey(priv []byte) (backendPrivateKey, error) { return openssl.NewPrivateKeyEd25519(priv) }
func newPublicKey(pub []byte) (backendPublicKey, error)    { return openssl.NewPublicKeyEd25519(pub) }
func newPrivateKeyFromSeed(seed []byte) (backendPrivateKey, error) {
	return openssl.NewPrivateKeyEd25519FromSeed(seed)
}
func sign(priv backendPrivateKey, message []byte) ([]byte, error) {
	return signBackend(openssl.SignEd25519, priv, message)
}
func signBackend(f func(backendPrivateKey, []byte) ([]byte, error), priv backendPrivateKey, message []byte) ([]byte, error) {
	return f(priv, message)
}
func verify(pub backendPublicKey, message, sig []byte) error {
	return openssl.VerifyEd25519(pub, message, sig)
}
