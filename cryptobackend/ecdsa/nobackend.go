// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package ecdsa

type BigInt = []uint
type PrivateKey struct{ _ int }
type PublicKey struct{ _ int }

func SupportsCurve(curve string) bool                      { panic("cryptobackend: not available") }
func GenerateKey(curve string) (X, Y, D BigInt, err error) { panic("cryptobackend: not available") }
func NewPrivateKey(curve string, X, Y, D BigInt) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}
func NewPublicKey(curve string, X, Y BigInt) (*PublicKey, error) {
	panic("cryptobackend: not available")
}
func SignMarshal(priv *PrivateKey, hash []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func Verify(pub *PublicKey, hash, sig []byte) bool { panic("cryptobackend: not available") }
