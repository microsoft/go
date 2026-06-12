// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package dsa

import "github.com/microsoft/go-crypto-openssl/openssl"

type BigInt = openssl.BigInt
type PrivateKey = openssl.PrivateKeyDSA
type PublicKey = openssl.PublicKeyDSA

func Supports(l, n int) bool { return openssl.SupportsDSA() }
func GenerateParameters(l, n int) (p, q, g BigInt, err error) {
	params, err := openssl.GenerateParametersDSA(l, n)
	return params.P, params.Q, params.G, err
}
func GenerateKey(p, q, g BigInt) (x, y BigInt, err error) {
	return openssl.GenerateKeyDSA(openssl.DSAParameters{P: p, Q: q, G: g})
}
func NewPrivateKey(p, q, g, x, y BigInt) (*PrivateKey, error) {
	return openssl.NewPrivateKeyDSA(openssl.DSAParameters{P: p, Q: q, G: g}, x, y)
}
func NewPublicKey(p, q, g, y BigInt) (*PublicKey, error) {
	return openssl.NewPublicKeyDSA(openssl.DSAParameters{P: p, Q: q, G: g}, y)
}
func Sign(priv *PrivateKey, hash []byte, parseSignature func([]byte) (BigInt, BigInt, error)) (r, s BigInt, err error) {
	sig, err := openssl.SignDSA(priv, hash)
	if err != nil {
		return nil, nil, err
	}
	r, s, err = parseSignature(sig)
	if err != nil {
		return nil, nil, err
	}
	return BigInt(r), BigInt(s), nil
}
func Verify(pub *PublicKey, hashed []byte, r, s BigInt, encodeSignature func(r, s BigInt) ([]byte, error)) bool {
	sig, err := encodeSignature(r, s)
	if err != nil {
		return false
	}
	return openssl.VerifyDSA(pub, hashed, sig)
}
