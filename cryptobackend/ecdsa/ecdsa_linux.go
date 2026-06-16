// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ecdsa

import "github.com/microsoft/go-crypto-openssl/openssl"

type BigInt = openssl.BigInt
type PrivateKey = openssl.PrivateKeyECDSA
type PublicKey = openssl.PublicKeyECDSA

func SupportsCurve(curve string) bool { return openssl.SupportsCurve(curve) }

func GenerateKey(curve string) (X, Y, D BigInt, err error) { return openssl.GenerateKeyECDSA(curve) }

func NewPrivateKey(curve string, X, Y, D BigInt) (*PrivateKey, error) {
	return openssl.NewPrivateKeyECDSA(curve, X, Y, D)
}

func NewPublicKey(curve string, X, Y BigInt) (*PublicKey, error) {
	return openssl.NewPublicKeyECDSA(curve, X, Y)
}

func SignASN1(priv *PrivateKey, hash []byte) ([]byte, error) {
	return openssl.SignMarshalECDSA(priv, hash)
}

func VerifyASN1(pub *PublicKey, hash, sig []byte) (bool, error) {
	return openssl.VerifyECDSA(pub, hash, sig), nil
}
