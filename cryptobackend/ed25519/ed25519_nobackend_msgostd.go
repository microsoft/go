// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (windows || !goexperiment.systemcrypto) && (msgostd || cmd_go_bootstrap)

package ed25519

import (
	fallback "crypto/internal/fips140/ed25519"

	_ "github.com/microsoft/go/cryptobackend"
)

// CNG does not implement Ed25519. Like Go-only builds, Windows uses the core
// types directly to avoid wrapping unsupported native operations.
type PrivateKey = fallback.PrivateKey
type PublicKey = fallback.PublicKey

// PrivateKeyBytes returns the key encoding for read-only cache comparisons.
// A static call keeps the core encoder inlineable through the Go-only type alias.
func PrivateKeyBytes(k *PrivateKey) []byte { return k.Bytes() }

// Keep these forwarding calls small enough to inline before the compiler
// expands the core constructors, so their returned keys can stay on the stack.
func generateGoKey(f func() (*PrivateKey, error)) (*PrivateKey, error) { return f() }
func newGoKey[K any](f func([]byte) (*K, error), encoding []byte) (*K, error) {
	return f(encoding)
}
func signGoVariant(f func(*PrivateKey, []byte, string) ([]byte, error), key *PrivateKey, message []byte, context string) ([]byte, error) {
	return f(key, message, context)
}

func GenerateKey() (*PrivateKey, error) { return generateGoKey(fallback.GenerateKey) }
func NewPrivateKey(encoding []byte) (*PrivateKey, error) {
	return newGoKey(fallback.NewPrivateKey, encoding)
}
func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	return newGoKey(fallback.NewPrivateKeyFromSeed, seed)
}
func NewPublicKey(encoding []byte) (*PublicKey, error) {
	return newGoKey(fallback.NewPublicKey, encoding)
}
func Sign(priv *PrivateKey, message []byte) []byte { return fallback.Sign(priv, message) }
func SignDeterministic(priv *PrivateKey, message []byte) []byte {
	return fallback.Sign(priv, message)
}
func SignPH(priv *PrivateKey, message []byte, context string) ([]byte, error) {
	return signGoVariant(fallback.SignPH, priv, message, context)
}
func SignCtx(priv *PrivateKey, message []byte, context string) ([]byte, error) {
	return signGoVariant(fallback.SignCtx, priv, message, context)
}
func Verify(pub *PublicKey, message, signature []byte) error {
	return fallback.Verify(pub, message, signature)
}
func VerifyPH(pub *PublicKey, message, signature []byte, context string) error {
	return fallback.VerifyPH(pub, message, signature, context)
}
func VerifyCtx(pub *PublicKey, message, signature []byte, context string) error {
	return fallback.VerifyCtx(pub, message, signature, context)
}
