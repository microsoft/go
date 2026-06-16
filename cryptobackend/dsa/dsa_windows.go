// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package dsa

import "github.com/microsoft/go-crypto-winnative/cng"

type BigInt = cng.BigInt
type PrivateKey = cng.PrivateKeyDSA
type PublicKey = cng.PublicKeyDSA

func Supports(l, n int) bool { return n == 160 || n == 256 }
func GenerateParameters(l, n int) (p, q, g BigInt, err error) {
	params, err := cng.GenerateParametersDSA(l)
	if err != nil {
		return nil, nil, nil, err
	}
	return params.P, params.Q, params.G, nil
}
func GenerateKey(p, q, g BigInt) (x, y BigInt, err error) {
	return cng.GenerateKeyDSA(cng.DSAParameters{P: p, Q: q, G: g})
}
func NewPrivateKey(p, q, g, x, y BigInt) (*PrivateKey, error) {
	return cng.NewPrivateKeyDSA(cng.DSAParameters{P: p, Q: q, G: g}, x, y)
}
func NewPublicKey(p, q, g, y BigInt) (*PublicKey, error) {
	return cng.NewPublicKeyDSA(cng.DSAParameters{P: p, Q: q, G: g}, y)
}
func Sign(priv *PrivateKey, hash []byte) (r, s BigInt, err error) {
	return cng.SignDSA(priv, hash)
}
func Verify(pub *PublicKey, hashed []byte, r, s BigInt) bool {
	return cng.VerifyDSA(pub, hashed, r, s)
}
