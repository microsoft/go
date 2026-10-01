// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package ecdsa

import (
	"math/big"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go/cryptobackend/bbig"
)

type backendPrivateKey = openssl.PrivateKeyECDSA
type backendPublicKey = openssl.PublicKeyECDSA

func supportsCurve(curve string) bool { return openssl.SupportsCurve(curve) }

func generateKey(curve string) (X, Y, D openssl.BigInt, err error) {
	return openssl.GenerateKeyECDSA(curve)
}

func newPrivateKey(curve string, Q, D []byte) (*backendPrivateKey, error) {
	size := (len(Q) - 1) / 2
	return openssl.NewPrivateKeyECDSA(curve, bbig.Enc(new(big.Int).SetBytes(Q[1:1+size])),
		bbig.Enc(new(big.Int).SetBytes(Q[1+size:])), bbig.Enc(new(big.Int).SetBytes(D)))
}

func newPublicKey(curve string, Q []byte) (*backendPublicKey, error) {
	size := (len(Q) - 1) / 2
	return openssl.NewPublicKeyECDSA(curve, bbig.Enc(new(big.Int).SetBytes(Q[1:1+size])),
		bbig.Enc(new(big.Int).SetBytes(Q[1+size:])))
}

func sign(priv *backendPrivateKey, hash []byte) (*Signature, error) {
	sig, err := openssl.SignMarshalECDSA(priv, hash)
	if err != nil {
		return nil, err
	}
	return parseSignature(sig)
}

func verify(pub *backendPublicKey, hash []byte, sig *Signature) error {
	der, err := encodeSignature(sig)
	if err != nil {
		return err
	}
	if !openssl.VerifyECDSA(pub, hash, der) {
		return errVerification
	}
	return nil
}
