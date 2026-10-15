// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package dsa

import (
	"crypto/internal/fips140cache"
	"math/big"
)

// PublicKeyCache associates native keys with immutable snapshots of caller-owned
// keys. Snapshots must not reference their owners, so the cache can evict them
// when their owners become unreachable.
type PublicKeyCache[K any] struct {
	cache fips140cache.Cache[K, cachedPublicKey]
}

type cachedPublicKey struct {
	key        *PublicKey
	p, q, g, y *big.Int
}

func (c *PublicKeyCache[K]) Get(owner *K, p, q, g, y *big.Int) (*PublicKey, error) {
	b, err := c.cache.Get(owner, func() (*cachedPublicKey, error) {
		b := &cachedPublicKey{
			p: new(big.Int).Set(p),
			q: new(big.Int).Set(q),
			g: new(big.Int).Set(g),
			y: new(big.Int).Set(y),
		}
		key, err := NewPublicKey(b.p, b.q, b.g, b.y)
		if err != nil {
			return nil, err
		}
		b.key = key
		return b, nil
	}, func(b *cachedPublicKey) bool {
		return b.p.Cmp(p) == 0 && b.q.Cmp(q) == 0 && b.g.Cmp(g) == 0 && b.y.Cmp(y) == 0
	})
	if err != nil {
		return nil, err
	}
	return b.key, nil
}

// PrivateKeyCache is the private-key counterpart of [PublicKeyCache].
type PrivateKeyCache[K any] struct {
	cache fips140cache.Cache[K, cachedPrivateKey]
}

type cachedPrivateKey struct {
	key           *PrivateKey
	p, q, g, x, y *big.Int
}

func (c *PrivateKeyCache[K]) Get(owner *K, p, q, g, x, y *big.Int) (*PrivateKey, error) {
	b, err := c.cache.Get(owner, func() (*cachedPrivateKey, error) {
		b := &cachedPrivateKey{
			p: new(big.Int).Set(p),
			q: new(big.Int).Set(q),
			g: new(big.Int).Set(g),
			x: new(big.Int).Set(x),
			y: new(big.Int).Set(y),
		}
		key, err := NewPrivateKey(b.p, b.q, b.g, b.x, b.y)
		if err != nil {
			return nil, err
		}
		b.key = key
		return b, nil
	}, func(b *cachedPrivateKey) bool {
		return b.p.Cmp(p) == 0 && b.q.Cmp(q) == 0 && b.g.Cmp(g) == 0 && b.x.Cmp(x) == 0 && b.y.Cmp(y) == 0
	})
	if err != nil {
		return nil, err
	}
	return b.key, nil
}
