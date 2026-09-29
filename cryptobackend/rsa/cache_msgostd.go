// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package rsa

import (
	"crypto/internal/fips140cache"
	"math/big"
	"slices"
)

// PublicKeyCache associates immutable RSA key snapshots with caller-owned keys.
// Changes to the caller's parameters cause a new snapshot to be imported.
// A snapshot is retained until its owner becomes unreachable and must not
// contain a reference back to the owner.
type PublicKeyCache[K any] struct {
	cache fips140cache.Cache[K, PublicKey]
}

func (c *PublicKeyCache[K]) Get(owner *K, n *big.Int, e int) (*PublicKey, error) {
	return c.cache.Get(owner, func() (*PublicKey, error) {
		return &PublicKey{n: copyInt(n), e: e}, nil
	}, func(b *PublicKey) bool {
		return !b.failed.Load() && b.e == e && equalInt(b.n, n)
	})
}

// PrivateKeyCache reuses native imports and Go precomputation without modifying
// caller-owned keys. A supplied Go key retains its existing validation semantics.
// Like [PublicKeyCache], it must not retain its owners through cached values.
type PrivateKeyCache[K any] struct {
	cache fips140cache.Cache[K, PrivateKey]
}

func (c *PrivateKeyCache[K]) Get(owner *K, n *big.Int, e int, d *big.Int, primes []*big.Int, dp, dq, qi *big.Int, fips *fipsPrivateKey) (*PrivateKey, error) {
	return c.cache.Get(owner, func() (*PrivateKey, error) {
		b := &PrivateKey{
			pub: PublicKey{n: copyInt(n), e: e},
			d:   copyInt(d), dp: copyInt(dp), dq: copyInt(dq), qi: copyInt(qi),
			primes: make([]*big.Int, len(primes)), precomputed: fips,
		}
		for i, p := range primes {
			b.primes[i] = copyInt(p)
		}
		return b, nil
	}, func(b *PrivateKey) bool {
		return !b.pub.failed.Load() && b.pub.e == e && equalInt(b.pub.n, n) && equalInt(b.d, d) &&
			b.precomputed == fips && equalInt(b.dp, dp) && equalInt(b.dq, dq) && equalInt(b.qi, qi) &&
			slices.EqualFunc(b.primes, primes, equalInt)
	})
}

func copyInt(x *big.Int) *big.Int {
	if x == nil {
		return nil
	}
	return new(big.Int).Set(x)
}

func equalInt(a, b *big.Int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Cmp(b) == 0
}
