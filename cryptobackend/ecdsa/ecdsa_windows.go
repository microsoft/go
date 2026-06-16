// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ecdsa

import (
	"errors"

	"github.com/microsoft/go-crypto-winnative/cng"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
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

func SignASN1(priv *PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := cng.SignECDSA(priv, hash)
	if err != nil {
		return nil, err
	}
	return encodeSignature(r, s)
}

func VerifyASN1(pub *PublicKey, hash, sig []byte) (bool, error) {
	r, s, err := parseSignature(sig)
	if err != nil {
		return false, err
	}
	return cng.VerifyECDSA(pub, hash, cng.BigInt(r), cng.BigInt(s)), nil
}

func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

func parseSignature(sig []byte) (r, s []byte, err error) {
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&r) ||
		!inner.ReadASN1Integer(&s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1")
	}
	return r, s, nil
}
