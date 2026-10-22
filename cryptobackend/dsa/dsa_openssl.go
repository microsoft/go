// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package dsa

import (
	"errors"
	"math/big"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go/cryptobackend/bbig"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type PrivateKey = openssl.PrivateKeyDSA
type PublicKey = openssl.PublicKeyDSA

func Supports(l, n int) bool { return openssl.SupportsDSA() }
func GenerateParameters(l, n int) (p, q, g *big.Int, err error) {
	params, err := openssl.GenerateParametersDSA(l, n)
	if err != nil {
		return nil, nil, nil, err
	}
	return bbig.Dec(params.P), bbig.Dec(params.Q), bbig.Dec(params.G), nil
}
func GenerateKey(p, q, g *big.Int) (x, y *big.Int, err error) {
	bx, by, err := openssl.GenerateKeyDSA(openssl.DSAParameters{P: bbig.Enc(p), Q: bbig.Enc(q), G: bbig.Enc(g)})
	if err != nil {
		return nil, nil, err
	}
	return bbig.Dec(bx), bbig.Dec(by), nil
}
func NewPrivateKey(p, q, g, x, y *big.Int) (*PrivateKey, error) {
	return openssl.NewPrivateKeyDSA(openssl.DSAParameters{P: bbig.Enc(p), Q: bbig.Enc(q), G: bbig.Enc(g)}, bbig.Enc(x), bbig.Enc(y))
}
func NewPublicKey(p, q, g, y *big.Int) (*PublicKey, error) {
	return openssl.NewPublicKeyDSA(openssl.DSAParameters{P: bbig.Enc(p), Q: bbig.Enc(q), G: bbig.Enc(g)}, bbig.Enc(y))
}
func Sign(priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	sig, err := openssl.SignDSA(priv, hash)
	if err != nil {
		return nil, nil, err
	}
	return parseSignature(sig)
}
func Verify(pub *PublicKey, hashed []byte, r, s *big.Int) bool {
	sig, err := encodeSignature(r, s)
	if err != nil {
		return false
	}
	return openssl.VerifyDSA(pub, hashed, sig)
}

func parseSignature(sig []byte) (*big.Int, *big.Int, error) {
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
	return new(big.Int).SetBytes(r), new(big.Int).SetBytes(s), nil
}

func encodeSignature(r, s *big.Int) ([]byte, error) {
	if r == nil || r.Sign() <= 0 || s == nil || s.Sign() <= 0 {
		return nil, errors.New("invalid integer")
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}
