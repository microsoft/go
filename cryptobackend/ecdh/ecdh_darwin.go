// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ecdh

import "github.com/microsoft/go-crypto-darwin/xcrypto"

type backendPrivateKey = xcrypto.PrivateKeyECDH
type backendPublicKey = xcrypto.PublicKeyECDH

func SupportsCurve(curve string) bool {
	switch curve {
	case "P-256", "P-384", "P-521", "X25519":
		return true
	}
	return false
}

func generateKey(curve string) (*backendPrivateKey, []byte, error) {
	return xcrypto.GenerateKeyECDH(curve)
}

func newPrivateKey(curve string, key []byte) (*backendPrivateKey, error) {
	return xcrypto.NewPrivateKeyECDH(curve, key)
}

func newPublicKey(curve string, key []byte) (*backendPublicKey, error) {
	return xcrypto.NewPublicKeyECDH(curve, key)
}

func ecdh(priv *backendPrivateKey, pub *backendPublicKey) ([]byte, error) {
	return xcrypto.ECDH(priv, pub)
}
