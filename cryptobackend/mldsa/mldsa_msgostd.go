// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (msgostd || cmd_go_bootstrap) && !fips140v1.0

package mldsa

import (
	fallback "crypto/internal/fips140/mldsa"
	"crypto/internal/rand"
	cryptorand "crypto/rand"
	"errors"
)

type fipsPrivateKey = fallback.PrivateKey
type fipsPublicKey = fallback.PublicKey

func GenerateKey44() (key *PrivateKey, err error) {
	var k PrivateKey
	err = generate(&k, "ML-DSA-44", fallback.GenerateKey44)
	if err == nil {
		key = &k
	}
	return
}

func GenerateKey65() (key *PrivateKey, err error) {
	var k PrivateKey
	err = generate(&k, "ML-DSA-65", fallback.GenerateKey65)
	if err == nil {
		key = &k
	}
	return
}

func GenerateKey87() (key *PrivateKey, err error) {
	var k PrivateKey
	err = generate(&k, "ML-DSA-87", fallback.GenerateKey87)
	if err == nil {
		key = &k
	}
	return
}

func generate(k *PrivateKey, name string, goGenerate func() *fipsPrivateKey) error {
	if params, ok := nativeParameters(name); ok && rand.IsDefaultReader(cryptorand.Reader) {
		key, err := generateKey(params)
		if err != nil {
			return err
		}
		k.backend = &backendPrivateKeyState{key: *key}
		return nil
	}
	k.fips = goGenerate()
	return nil
}

func NewPrivateKey44(seed []byte) (key *PrivateKey, err error) {
	var k PrivateKey
	err = newPrivate(&k, "ML-DSA-44", seed)
	if err == nil {
		key = &k
	}
	return
}

func NewPrivateKey65(seed []byte) (key *PrivateKey, err error) {
	var k PrivateKey
	err = newPrivate(&k, "ML-DSA-65", seed)
	if err == nil {
		key = &k
	}
	return
}

func NewPrivateKey87(seed []byte) (key *PrivateKey, err error) {
	var k PrivateKey
	err = newPrivate(&k, "ML-DSA-87", seed)
	if err == nil {
		key = &k
	}
	return
}

func newPrivate(k *PrivateKey, name string, seed []byte) error {
	if len(seed) != 32 {
		return errors.New("mldsa: invalid seed length")
	}
	if params, ok := nativeParameters(name); ok {
		key, err := newPrivateKey(params, seed)
		if err != nil {
			return err
		}
		k.backend = &backendPrivateKeyState{key: *key}
		return nil
	}
	key, err := newGoPrivateKey(name, seed)
	if err != nil {
		return err
	}
	k.fips = key
	return nil
}

func newGoPrivateKey(name string, seed []byte) (*fipsPrivateKey, error) {
	switch name {
	case "ML-DSA-44":
		return fallback.NewPrivateKey44(seed)
	case "ML-DSA-65":
		return fallback.NewPrivateKey65(seed)
	case "ML-DSA-87":
		return fallback.NewPrivateKey87(seed)
	default:
		return nil, errors.New("mldsa: invalid parameters")
	}
}

func NewPublicKey44(encoding []byte) (key *PublicKey, err error) {
	var k PublicKey
	err = newPublic(&k, "ML-DSA-44", encoding)
	if err == nil {
		key = &k
	}
	return
}

func NewPublicKey65(encoding []byte) (key *PublicKey, err error) {
	var k PublicKey
	err = newPublic(&k, "ML-DSA-65", encoding)
	if err == nil {
		key = &k
	}
	return
}

func NewPublicKey87(encoding []byte) (key *PublicKey, err error) {
	var k PublicKey
	err = newPublic(&k, "ML-DSA-87", encoding)
	if err == nil {
		key = &k
	}
	return
}

func newPublic(k *PublicKey, name string, encoding []byte) error {
	if params, ok := nativeParameters(name); ok {
		key, err := newPublicKey(params, encoding)
		if err != nil {
			return err
		}
		k.backend = key
		return nil
	}
	var key *fipsPublicKey
	var err error
	switch name {
	case "ML-DSA-44":
		key, err = fallback.NewPublicKey44(encoding)
	case "ML-DSA-65":
		key, err = fallback.NewPublicKey65(encoding)
	case "ML-DSA-87":
		key, err = fallback.NewPublicKey87(encoding)
	}
	if err != nil {
		return err
	}
	k.fips = *key
	return nil
}

func Sign(priv *PrivateKey, message []byte, context string) ([]byte, error) {
	if priv.backend != nil && rand.IsDefaultReader(cryptorand.Reader) {
		return priv.backend.key.Sign(message, context)
	}
	key, err := priv.goKey()
	if err != nil {
		return nil, err
	}
	return fallback.Sign(key, message, context)
}

func SignExternalMu(priv *PrivateKey, mu []byte) ([]byte, error) {
	if priv.backend != nil && supportsExternalMu() && rand.IsDefaultReader(cryptorand.Reader) {
		return priv.backend.key.SignExternalMu(mu)
	}
	key, err := priv.goKey()
	if err != nil {
		return nil, err
	}
	return fallback.SignExternalMu(key, mu)
}

// SignDeterministic uses the Go implementation, which controls the signing nonce.
func SignDeterministic(priv *PrivateKey, message []byte, context string) ([]byte, error) {
	key, err := priv.goKey()
	if err != nil {
		return nil, err
	}
	return fallback.SignDeterministic(key, message, context)
}

// SignExternalMuDeterministic uses the Go implementation for deterministic nonces.
func SignExternalMuDeterministic(priv *PrivateKey, mu []byte) ([]byte, error) {
	key, err := priv.goKey()
	if err != nil {
		return nil, err
	}
	return fallback.SignExternalMuDeterministic(key, mu)
}

func Verify(pub *PublicKey, message, signature []byte, context string) error {
	if pub.backend != nil {
		return pub.backend.Verify(message, signature, context)
	}
	return fallback.Verify(&pub.fips, message, signature, context)
}
