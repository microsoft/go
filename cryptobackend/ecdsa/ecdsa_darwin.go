// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ecdsa

import "github.com/microsoft/go-crypto-darwin/xcrypto"

type backendPrivateKey = xcrypto.PrivateKeyECDSA
type backendPublicKey = xcrypto.PublicKeyECDSA

func supportsCurve(curve string) bool {
	switch curve {
	case "P-256", "P-384", "P-521":
		return true
	}
	return false
}

func generateKey(curve string) (X, Y, D xcrypto.BigInt, err error) {
	return xcrypto.GenerateKeyECDSA(curve)
}

func newPrivateKey(curve string, Q, D []byte) (*backendPrivateKey, error) {
	size := (len(Q) - 1) / 2
	return xcrypto.NewPrivateKeyECDSA(curve, Q[1:1+size], Q[1+size:], D)
}

func newPublicKey(curve string, Q []byte) (*backendPublicKey, error) {
	size := (len(Q) - 1) / 2
	return xcrypto.NewPublicKeyECDSA(curve, Q[1:1+size], Q[1+size:])
}

func sign(priv *backendPrivateKey, hash []byte) (*Signature, error) {
	sig, err := xcrypto.SignMarshalECDSA(priv, hash)
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
	if !xcrypto.VerifyECDSA(pub, hash, der) {
		return errVerification
	}
	return nil
}
