// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package ecdh

import "github.com/microsoft/go-crypto-openssl/openssl"

type backendPrivateKey = openssl.PrivateKeyECDH
type backendPublicKey = openssl.PublicKeyECDH

func SupportsCurve(curve string) bool { return openssl.SupportsCurve(curve) }

func generateKey(curve string) (*backendPrivateKey, []byte, error) {
	return openssl.GenerateKeyECDH(curve)
}

func newPrivateKey(curve string, key []byte) (*backendPrivateKey, error) {
	return openssl.NewPrivateKeyECDH(curve, key)
}

func newPublicKey(curve string, key []byte) (*backendPublicKey, error) {
	return openssl.NewPublicKeyECDH(curve, key)
}

func ecdh(priv *backendPrivateKey, pub *backendPublicKey) ([]byte, error) {
	return openssl.ECDH(priv, pub)
}
