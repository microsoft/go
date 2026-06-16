// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package dsa

import (
	"errors"
	"math/big"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go/cryptobackend/bbig"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type BigInt = openssl.BigInt
type PrivateKey = openssl.PrivateKeyDSA
type PublicKey = openssl.PublicKeyDSA

func Supports(l, n int) bool { return openssl.SupportsDSA() }
func GenerateParameters(l, n int) (p, q, g BigInt, err error) {
	params, err := openssl.GenerateParametersDSA(l, n)
	return params.P, params.Q, params.G, err
}
func GenerateKey(p, q, g BigInt) (x, y BigInt, err error) {
	return openssl.GenerateKeyDSA(openssl.DSAParameters{P: p, Q: q, G: g})
}
func NewPrivateKey(p, q, g, x, y BigInt) (*PrivateKey, error) {
	return openssl.NewPrivateKeyDSA(openssl.DSAParameters{P: p, Q: q, G: g}, x, y)
}
func NewPublicKey(p, q, g, y BigInt) (*PublicKey, error) {
	return openssl.NewPublicKeyDSA(openssl.DSAParameters{P: p, Q: q, G: g}, y)
}
func Sign(priv *PrivateKey, hash []byte) (r, s BigInt, err error) {
	sig, err := openssl.SignDSA(priv, hash)
	if err != nil {
		return nil, nil, err
	}
	return parseSignature(sig)
}
func Verify(pub *PublicKey, hashed []byte, r, s BigInt) bool {
	sig, err := encodeSignature(r, s)
	if err != nil {
		return false
	}
	return openssl.VerifyDSA(pub, hashed, sig)
}

func parseSignature(sig []byte) (BigInt, BigInt, error) {
	var r, s []byte
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&r) ||
		!inner.ReadASN1Integer(&s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1")
	}
	return bbig.Enc(new(big.Int).SetBytes(r)), bbig.Enc(new(big.Int).SetBytes(s)), nil
}

func encodeSignature(r, s BigInt) ([]byte, error) {
	rb, sb := bbig.Dec(r), bbig.Dec(s)
	if rb == nil || rb.Sign() <= 0 || sb == nil || sb.Sign() <= 0 {
		return nil, errors.New("invalid integer")
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, rb.Bytes())
		addASN1IntBytes(b, sb.Bytes())
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
