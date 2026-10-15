// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package dsa

import "math/big"

type PrivateKey struct{}
type PublicKey struct{}

func Supports(l, n int) bool { return false }
func GenerateParameters(l, n int) (p, q, g *big.Int, err error) {
	panic("cryptobackend: not available")
}
func GenerateKey(p, q, g *big.Int) (x, y *big.Int, err error) {
	panic("cryptobackend: not available")
}
func NewPrivateKey(p, q, g, x, y *big.Int) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}
func NewPublicKey(p, q, g, y *big.Int) (*PublicKey, error) {
	panic("cryptobackend: not available")
}
func Sign(priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	panic("cryptobackend: not available")
}
func Verify(pub *PublicKey, hashed []byte, r, s *big.Int) bool {
	panic("cryptobackend: not available")
}
