// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto && !windows && (msgostd || cmd_go_bootstrap)

package ed25519

import (
	"crypto/internal/boring/bcache"
	fallback "crypto/internal/fips140/ed25519"
	"crypto/internal/fips140/edwards25519"
	"crypto/internal/rand"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"errors"
	"strconv"
)

type fipsPrivateKey = fallback.PrivateKey
type fipsPublicKey = fallback.PublicKey

func GenerateKey() (key *PrivateKey, err error) {
	var k PrivateKey
	err = generate(&k)
	if err == nil {
		key = &k
	}
	return
}

func generate(k *PrivateKey) error {
	if supportsBackend() && rand.IsDefaultReader(cryptorand.Reader) {
		key, err := generateKey()
		if err != nil {
			return err
		}
		return initBackendPrivateKey(k, key)
	}
	key, err := fallback.GenerateKey()
	if err != nil {
		return err
	}
	k.fips, k.encoding = key, [64]byte(key.Bytes())
	return nil
}

func NewPrivateKeyFromSeed(seed []byte) (key *PrivateKey, err error) {
	var k PrivateKey
	err = newPrivateFromSeed(&k, seed)
	if err == nil {
		key = &k
	}
	return
}

func newPrivateFromSeed(k *PrivateKey, seed []byte) error {
	if len(seed) != 32 {
		return errors.New("ed25519: bad seed length: " + strconv.Itoa(len(seed)))
	}
	if supportsBackend() {
		key, err := newPrivateKeyFromSeed(seed)
		if err != nil {
			return err
		}
		return initBackendPrivateKey(k, key)
	}
	key, err := fallback.NewPrivateKeyFromSeed(seed)
	if err != nil {
		return err
	}
	k.fips, k.encoding = key, [64]byte(key.Bytes())
	return nil
}

func NewPrivateKey(encoding []byte) (*PrivateKey, error) {
	if len(encoding) != 64 {
		return nil, errors.New("ed25519: bad private key length: " + strconv.Itoa(len(encoding)))
	}
	if supportsBackend() {
		key, err := newPrivateKey(encoding)
		if err != nil {
			return nil, err
		}
		k := new(PrivateKey)
		if err := initBackendPrivateKey(k, key); err != nil {
			return nil, err
		}
		// Native importers derive the public suffix from the seed. Go signing
		// uses the supplied suffix, even when it does not match that seed.
		if subtle.ConstantTimeCompare(encoding, k.encoding[:]) == 1 {
			return k, nil
		}
	}
	key, err := fallback.NewPrivateKey(encoding)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{fips: key, encoding: [64]byte(encoding)}, nil
}

func initBackendPrivateKey(k *PrivateKey, key backendPrivateKey) error {
	encoding, err := key.Bytes()
	if err != nil {
		return err
	}
	if len(encoding) != 64 {
		return errors.New("ed25519: invalid backend private key length")
	}
	k.backend = key
	copy(k.encoding[:], encoding)
	return nil
}

// Preserve the native public-key cache's GC-based eviction. Each cached key
// holds its own immutable encoding, so input mutations invalidate the entry.
var publicKeyCache bcache.Cache[byte, PublicKey]

func init() {
	if supportsBackend() {
		publicKeyCache.Register()
	}
}

func NewPublicKey(encoding []byte) (key *PublicKey, err error) {
	var k PublicKey
	err = importPublicKey(&k, encoding)
	if err == nil {
		key = &k
	}
	return
}

func importPublicKey(k *PublicKey, encoding []byte) error {
	if len(encoding) != 32 {
		return errors.New("ed25519: bad public key length: " + strconv.Itoa(len(encoding)))
	}
	if supportsBackend() && testMalleability() {
		p := &encoding[0]
		if cached := publicKeyCache.Get(p); cached != nil && subtle.ConstantTimeCompare(encoding, cached.backend.encoding[:]) == 1 {
			*k = *cached
			return nil
		}
		cached, err := importBackendPublicKey(encoding)
		if err != nil {
			return err
		}
		publicKeyCache.Put(p, cached)
		*k = *cached
		return nil
	}
	key, err := fallback.NewPublicKey(encoding)
	if err != nil {
		return err
	}
	k.fips = *key
	return nil
}

func importBackendPublicKey(encoding []byte) (*PublicKey, error) {
	// Preserve the Go point validation before accepting a native key.
	var point edwards25519.Point
	if _, err := point.SetBytes(encoding); err != nil {
		return nil, errors.New("ed25519: bad public key")
	}
	key, err := newPublicKey(encoding)
	if err != nil {
		return nil, err
	}
	s := &struct {
		PublicKey
		state backendPublicKeyState
	}{state: backendPublicKeyState{key: key, encoding: [32]byte(encoding)}}
	s.backend = &s.state
	return &s.PublicKey, nil
}

func newGoPrivateKey(encoding *[64]byte) *fipsPrivateKey {
	key, err := fallback.NewPrivateKey(encoding[:])
	if err != nil {
		panic(err)
	}
	return key
}

func newGoPublicKey(encoding *[32]byte) *fipsPublicKey {
	key, err := fallback.NewPublicKey(encoding[:])
	if err != nil {
		panic(err)
	}
	return key
}

func Sign(priv *PrivateKey, message []byte) []byte {
	signature := make([]byte, 64)
	signInto(signature, priv, message)
	return signature
}

func signInto(signature []byte, priv *PrivateKey, message []byte) {
	if priv.backend != nil {
		sig, err := sign(priv.backend, message)
		if err != nil {
			panic(err)
		}
		copy(signature, sig)
		return
	}
	copy(signature, fallback.Sign(priv.fips, message))
}

// SignDeterministic uses the Go implementation. PrivateKey.Sign uses this path
// because some native providers randomize otherwise valid Ed25519 signatures.
func SignDeterministic(priv *PrivateKey, message []byte) []byte {
	return fallback.Sign(priv.goKey(), message)
}

func SignPH(priv *PrivateKey, message []byte, context string) ([]byte, error) {
	return fallback.SignPH(priv.goKey(), message, context)
}

func SignCtx(priv *PrivateKey, message []byte, context string) ([]byte, error) {
	return fallback.SignCtx(priv.goKey(), message, context)
}

func Verify(pub *PublicKey, message, signature []byte) error {
	if pub.backend != nil {
		return verify(pub.backend.key, message, signature)
	}
	return fallback.Verify(pub.goKey(), message, signature)
}

func VerifyPH(pub *PublicKey, message, signature []byte, context string) error {
	return fallback.VerifyPH(pub.goKey(), message, signature, context)
}

func VerifyCtx(pub *PublicKey, message, signature []byte, context string) error {
	return fallback.VerifyCtx(pub.goKey(), message, signature, context)
}
