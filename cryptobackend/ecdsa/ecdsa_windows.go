// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ecdsa

import (
	"errors"

	"github.com/microsoft/go-crypto-winnative/cng"
)

type BigInt = cng.BigInt
type PrivateKey = cng.PrivateKeyECDSA
type PublicKey = cng.PublicKeyECDSA

func SupportsCurve(curve string) bool {
	switch curve {
	case "P-224", "P-256", "P-384", "P-521", "X25519":
		return true
	}
	return false
}

func GenerateKey(curve string) (X, Y, D BigInt, err error) { return cng.GenerateKeyECDSA(curve) }

func NewPrivateKey(curve string, X, Y, D BigInt) (*PrivateKey, error) {
	return cng.NewPrivateKeyECDSA(curve, X, Y, D)
}

func NewPublicKey(curve string, X, Y BigInt) (*PublicKey, error) {
	return cng.NewPublicKeyECDSA(curve, X, Y)
}

func Sign(priv *PrivateKey, hash []byte) (r, s []byte, err error) {
	return cng.SignECDSA(priv, hash)
}

func SignASN1(priv *PrivateKey, hash []byte) ([]byte, error) {
	return nil, errors.ErrUnsupported
}

func VerifyASN1(pub *PublicKey, hash, sig []byte) (bool, error) {
	return false, errors.ErrUnsupported
}

func Verify(pub *PublicKey, hash, r, s []byte) (bool, error) {
	return cng.VerifyECDSA(pub, hash, cng.BigInt(r), cng.BigInt(s)), nil
}
