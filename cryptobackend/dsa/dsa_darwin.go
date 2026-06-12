// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package dsa

import "github.com/microsoft/go-crypto-darwin/xcrypto"

type BigInt = xcrypto.BigInt
type PrivateKey struct{}
type PublicKey struct{}

func Supports(l, n int) bool                                  { return false }
func GenerateParameters(l, n int) (p, q, g BigInt, err error) { panic("cryptobackend: not available") }
func GenerateKey(p, q, g BigInt) (x, y BigInt, err error)     { panic("cryptobackend: not available") }
func NewPrivateKey(p, q, g, x, y BigInt) (*PrivateKey, error) { panic("cryptobackend: not available") }
func NewPublicKey(p, q, g, y BigInt) (*PublicKey, error)      { panic("cryptobackend: not available") }
func Sign(priv *PrivateKey, hash []byte, parseSignature func([]byte) (BigInt, BigInt, error)) (r, s BigInt, err error) {
	panic("cryptobackend: not available")
}
func Verify(pub *PublicKey, hashed []byte, r, s BigInt, encodeSignature func(r, s BigInt) ([]byte, error)) bool {
	panic("cryptobackend: not available")
}
