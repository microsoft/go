// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ecdh

import "github.com/microsoft/go-crypto-winnative/cng"

type PrivateKey = cng.PrivateKeyECDH
type PublicKey = cng.PublicKeyECDH

func SupportsCurve(curve string) bool {
	switch curve {
	case "P-224", "P-256", "P-384", "P-521", "X25519":
		return true
	}
	return false
}

func GenerateKey(curve string) (*PrivateKey, []byte, error) { return cng.GenerateKeyECDH(curve) }

func NewPrivateKey(curve string, key []byte) (*PrivateKey, error) {
	return cng.NewPrivateKeyECDH(curve, key)
}

func NewPublicKey(curve string, key []byte) (*PublicKey, error) {
	return cng.NewPublicKeyECDH(curve, key)
}

func ECDH(priv *PrivateKey, pub *PublicKey) ([]byte, error) { return cng.ECDH(priv, pub) }
