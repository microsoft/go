// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package rsa

import "math/big"

type fipsPublicKey struct{}
type fipsPrivateKey struct{}

// Keep the standard-library API visible to source-based importers, which load
// this variant without the msgostd tag.
type PublicKeyCache[K any] struct{}
type PrivateKeyCache[K any] struct{}

func (*PublicKeyCache[K]) Get(owner *K, n *big.Int, e int) (*PublicKey, error) {
	panic("cryptobackend: not available")
}

func (*PrivateKeyCache[K]) Get(owner *K, n *big.Int, e int, d *big.Int, primes []*big.Int, dp, dq, qi *big.Int, fips *fipsPrivateKey) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}

func GeneratedFIPSKey(k GeneratedKey) *fipsPrivateKey {
	panic("cryptobackend: not available")
}

func newFallbackPublicKey(N []byte, e int) (*fipsPublicKey, error) {
	panic("cryptobackend: not available")
}

func newFallbackPrivateKey(k *PrivateKey) (*fipsPrivateKey, error) {
	panic("cryptobackend: not available")
}

func (*fipsPrivateKey) Export() (N []byte, e int, d, P, Q, dP, dQ, qInv []byte) {
	panic("cryptobackend: not available")
}
