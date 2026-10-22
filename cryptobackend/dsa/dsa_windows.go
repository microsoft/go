// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package dsa

import (
	"math/big"

	"github.com/microsoft/go-crypto-winnative/cng"
	"github.com/microsoft/go/cryptobackend/bbig"
)

type PrivateKey = cng.PrivateKeyDSA
type PublicKey = cng.PublicKeyDSA

func Supports(l, n int) bool { return n == 160 || n == 256 }
func GenerateParameters(l, n int) (p, q, g *big.Int, err error) {
	params, err := cng.GenerateParametersDSA(l)
	if err != nil {
		return nil, nil, nil, err
	}
	return bbig.Dec(params.P), bbig.Dec(params.Q), bbig.Dec(params.G), nil
}
func GenerateKey(p, q, g *big.Int) (x, y *big.Int, err error) {
	bx, by, err := cng.GenerateKeyDSA(cng.DSAParameters{P: bbig.Enc(p), Q: bbig.Enc(q), G: bbig.Enc(g)})
	if err != nil {
		return nil, nil, err
	}
	return bbig.Dec(bx), bbig.Dec(by), nil
}
func NewPrivateKey(p, q, g, x, y *big.Int) (*PrivateKey, error) {
	return cng.NewPrivateKeyDSA(cng.DSAParameters{P: bbig.Enc(p), Q: bbig.Enc(q), G: bbig.Enc(g)}, bbig.Enc(x), bbig.Enc(y))
}
func NewPublicKey(p, q, g, y *big.Int) (*PublicKey, error) {
	return cng.NewPublicKeyDSA(cng.DSAParameters{P: bbig.Enc(p), Q: bbig.Enc(q), G: bbig.Enc(g)}, bbig.Enc(y))
}
func Sign(priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	br, bs, err := cng.SignDSA(priv, hash)
	if err != nil {
		return nil, nil, err
	}
	return bbig.Dec(br), bbig.Dec(bs), nil
}
func Verify(pub *PublicKey, hashed []byte, r, s *big.Int) bool {
	if r == nil || r.Sign() <= 0 || s == nil || s.Sign() <= 0 {
		return false
	}
	return cng.VerifyDSA(pub, hashed, bbig.Enc(r), bbig.Enc(s))
}
