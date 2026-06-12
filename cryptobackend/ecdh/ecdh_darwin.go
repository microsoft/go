// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ecdh

import "github.com/microsoft/go-crypto-darwin/xcrypto"

type PrivateKey = xcrypto.PrivateKeyECDH
type PublicKey = xcrypto.PublicKeyECDH

func SupportsCurve(curve string) bool {
	switch curve {
	case "P-256", "P-384", "P-521", "X25519":
		return true
	}
	return false
}

func GenerateKey(curve string) (*PrivateKey, []byte, error) { return xcrypto.GenerateKeyECDH(curve) }

func NewPrivateKey(curve string, key []byte) (*PrivateKey, error) {
	return xcrypto.NewPrivateKeyECDH(curve, key)
}

func NewPublicKey(curve string, key []byte) (*PublicKey, error) {
	return xcrypto.NewPublicKeyECDH(curve, key)
}

func ECDH(priv *PrivateKey, pub *PublicKey) ([]byte, error) { return xcrypto.ECDH(priv, pub) }
