// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package dsa

import "math/big"

// Keep the standard-library API visible to source-based importers.
type PublicKeyCache[K any] struct{}
type PrivateKeyCache[K any] struct{}

func (*PublicKeyCache[K]) Get(owner *K, p, q, g, y *big.Int) (*PublicKey, error) {
	panic("cryptobackend: not available")
}

func (*PrivateKeyCache[K]) Get(owner *K, p, q, g, x, y *big.Int) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}
