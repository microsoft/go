// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ecdsa

import "github.com/microsoft/go-crypto-darwin/xcrypto"

type BigInt = xcrypto.BigInt
type PrivateKey = xcrypto.PrivateKeyECDSA
type PublicKey = xcrypto.PublicKeyECDSA

func SupportsCurve(curve string) bool {
	switch curve {
	case "P-256", "P-384", "P-521", "X25519":
		return true
	}
	return false
}

func GenerateKey(curve string) (X, Y, D BigInt, err error) { return xcrypto.GenerateKeyECDSA(curve) }

func NewPrivateKey(curve string, X, Y, D BigInt) (*PrivateKey, error) {
	return xcrypto.NewPrivateKeyECDSA(curve, X, Y, D)
}

func NewPublicKey(curve string, X, Y BigInt) (*PublicKey, error) {
	return xcrypto.NewPublicKeyECDSA(curve, X, Y)
}

func SignASN1(priv *PrivateKey, hash []byte) ([]byte, error) {
	return xcrypto.SignMarshalECDSA(priv, hash)
}

func VerifyASN1(pub *PublicKey, hash, sig []byte) (bool, error) {
	return xcrypto.VerifyECDSA(pub, hash, sig), nil
}
