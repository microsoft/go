// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ecdsa

import (
	_ "unsafe"

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

//go:linkname encodeSignature crypto/ecdsa.encodeSignature
func encodeSignature(r, s []byte) ([]byte, error)

//go:linkname parseSignature crypto/ecdsa.parseSignature
func parseSignature(sig []byte) (r, s []byte, err error)

func SignMarshal(priv *PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := cng.SignECDSA(priv, hash)
	if err != nil {
		return nil, err
	}
	return encodeSignature(r, s)
}

func Verify(pub *PublicKey, hash, sig []byte) bool {
	r, s, err := parseSignature(sig)
	if err != nil {
		return false
	}
	return cng.VerifyECDSA(pub, hash, cng.BigInt(r), cng.BigInt(s))
}
