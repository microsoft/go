// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package ecdh

import "github.com/microsoft/go-crypto-openssl/openssl"

type PrivateKey = openssl.PrivateKeyECDH
type PublicKey = openssl.PublicKeyECDH

func SupportsCurve(curve string) bool { return openssl.SupportsCurve(curve) }

func GenerateKey(curve string) (*PrivateKey, []byte, error) { return openssl.GenerateKeyECDH(curve) }

func NewPrivateKey(curve string, key []byte) (*PrivateKey, error) {
	return openssl.NewPrivateKeyECDH(curve, key)
}

func NewPublicKey(curve string, key []byte) (*PublicKey, error) {
	return openssl.NewPublicKeyECDH(curve, key)
}

func ECDH(priv *PrivateKey, pub *PublicKey) ([]byte, error) { return openssl.ECDH(priv, pub) }
