// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"math/big"
	"sync"
	"sync/atomic"

	backend "github.com/microsoft/go/cryptobackend"
)

// lazyKey caches a key conversion and marks its owning snapshot on failure.
type lazyKey[T any] struct {
	once sync.Once
	key  *T
	err  error
}

func (k *lazyKey[T]) get(failed *atomic.Bool, new func() (*T, error)) (*T, error) {
	k.once.Do(func() {
		k.key, k.err = new()
		if k.err != nil {
			failed.Store(true)
		}
	})
	return k.key, k.err
}

// PublicKey holds an owned RSA public-key snapshot and its cached implementations.
// Its parameters are immutable. A PublicKey must not be copied after first use.
type PublicKey struct {
	n *big.Int
	e int

	backend lazyKey[backendPublicKey]
	fips    lazyKey[fipsPublicKey]

	// A failed public or private conversion invalidates the whole snapshot.
	// The next cache lookup retries with a fresh snapshot.
	failed atomic.Bool
}

func (k *PublicKey) bitLen() int {
	if k.n == nil {
		return 0
	}
	return k.n.BitLen()
}

// Size returns the modulus size in bytes.
func (k *PublicKey) Size() int {
	return (k.bitLen() + 7) / 8
}

func (k *PublicKey) backendKey() (*backendPublicKey, error) {
	return k.backend.get(&k.failed, func() (*backendPublicKey, error) {
		return newBackendPublicKey(k.n, k.e)
	})
}

func (k *PublicKey) goKey() (*fipsPublicKey, error) {
	return k.fips.get(&k.failed, func() (*fipsPublicKey, error) {
		return newFallbackPublicKey(intBytes(k.n), k.e)
	})
}

// PrivateKey holds an owned RSA private-key snapshot and its cached implementations.
// Its parameters are immutable. A PrivateKey must not be copied after first use.
// Importing a native key does not validate it with the Go implementation;
// that validation takes place when the Go key is first requested.
type PrivateKey struct {
	pub           PublicKey
	d, dp, dq, qi *big.Int
	primes        []*big.Int

	// Keep the caller-supplied Go key separate from the lazy fips cache so
	// initialization does not change the snapshot used for cache matching.
	precomputed *fipsPrivateKey

	backend lazyKey[backendPrivateKey]
	fips    lazyKey[fipsPrivateKey]
}

// GeneratedKey is an RSA private key returned by [GenerateKey]. Its complete
// parameters can be exported without further computation or validation.
type GeneratedKey struct {
	n, d, p, q, dp, dq, qi []byte
	e                      int
	fips                   *fipsPrivateKey
}

// Export returns copies of the generated key parameters in big-endian form.
func (k GeneratedKey) Export() (N []byte, e int, d, P, Q, dP, dQ, qInv []byte) {
	if k.fips != nil {
		return k.fips.Export()
	}
	return bytes.Clone(k.n), k.e, bytes.Clone(k.d), bytes.Clone(k.p), bytes.Clone(k.q),
		bytes.Clone(k.dp), bytes.Clone(k.dq), bytes.Clone(k.qi)
}

// PublicKey returns the public part of k.
func (k *PrivateKey) PublicKey() *PublicKey {
	return &k.pub
}

// Size returns the modulus size in bytes.
func (k *PrivateKey) Size() int {
	return k.pub.Size()
}

func (k *PrivateKey) backendKey() (*backendPrivateKey, error) {
	return k.backend.get(&k.pub.failed, func() (*backendPrivateKey, error) {
		return newBackendPrivateKey(k)
	})
}

func (k *PrivateKey) goKey() (*fipsPrivateKey, error) {
	return k.fips.get(&k.pub.failed, func() (*fipsPrivateKey, error) {
		return newFallbackPrivateKey(k)
	})
}

func (k *PublicKey) supportsBackend() bool {
	return backend.Enabled && supportsPublicKey(k.bitLen())
}

func (k *PrivateKey) supportsBackend() bool {
	return backend.Enabled && len(k.primes) == 2 && k.primes[0] != nil && k.primes[1] != nil && supportsPublicKey(k.pub.bitLen())
}

func intBytes(x *big.Int) []byte {
	if x == nil {
		return nil
	}
	return x.Bytes()
}
