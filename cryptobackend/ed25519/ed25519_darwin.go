// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ed25519

import "github.com/microsoft/go-crypto-darwin/xcrypto"

type PrivateKey = xcrypto.PrivateKeyEd25519
type PublicKey = xcrypto.PublicKeyEd25519

func Supports() bool                                { return true }
func GenerateKey() (PrivateKey, error)              { return xcrypto.GenerateKeyEd25519(), nil }
func NewPrivateKey(priv []byte) (PrivateKey, error) { return xcrypto.NewPrivateKeyEd25519(priv) }
func NewPublicKey(pub []byte) (PublicKey, error)    { return xcrypto.NewPublicKeyEd25519(pub) }
func NewPrivateKeyFromSeed(seed []byte) (PrivateKey, error) {
	return xcrypto.NewPrivateKeyEd25519FromSeed(seed)
}
func Sign(priv PrivateKey, message []byte) ([]byte, error) { return xcrypto.SignEd25519(priv, message) }
func Verify(pub PublicKey, message, sig []byte) error {
	return xcrypto.VerifyEd25519(pub, message, sig)
}
