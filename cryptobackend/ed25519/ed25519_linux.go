// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ed25519

import "github.com/microsoft/go-crypto-openssl/openssl"

type PrivateKey = *openssl.PrivateKeyEd25519
type PublicKey = *openssl.PublicKeyEd25519

func Supports() bool                                { return openssl.SupportsEd25519() }
func GenerateKey() (PrivateKey, error)              { return openssl.GenerateKeyEd25519() }
func NewPrivateKey(priv []byte) (PrivateKey, error) { return openssl.NewPrivateKeyEd25519(priv) }
func NewPublicKey(pub []byte) (PublicKey, error)    { return openssl.NewPublicKeyEd25519(pub) }
func NewPrivateKeyFromSeed(seed []byte) (PrivateKey, error) {
	return openssl.NewPrivateKeyEd25519FromSeed(seed)
}
func Sign(priv PrivateKey, message []byte) ([]byte, error) { return openssl.SignEd25519(priv, message) }
func Verify(pub PublicKey, message, sig []byte) error {
	return openssl.VerifyEd25519(pub, message, sig)
}
