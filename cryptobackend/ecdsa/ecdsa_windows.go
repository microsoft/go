// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ecdsa

import "github.com/microsoft/go-crypto-winnative/cng"

type backendPrivateKey = cng.PrivateKeyECDSA
type backendPublicKey = cng.PublicKeyECDSA

func supportsCurve(curve string) bool {
	switch curve {
	case "P-224", "P-256", "P-384", "P-521":
		return true
	}
	return false
}

func generateKey(curve string) (X, Y, D cng.BigInt, err error) {
	return cng.GenerateKeyECDSA(curve)
}

func newPrivateKey(curve string, Q, D []byte) (*backendPrivateKey, error) {
	size := (len(Q) - 1) / 2
	return cng.NewPrivateKeyECDSA(curve, Q[1:1+size], Q[1+size:], D)
}

func newPublicKey(curve string, Q []byte) (*backendPublicKey, error) {
	size := (len(Q) - 1) / 2
	return cng.NewPublicKeyECDSA(curve, Q[1:1+size], Q[1+size:])
}

func sign(priv *backendPrivateKey, hash []byte) (*Signature, error) {
	r, s, err := cng.SignECDSA(priv, hash)
	if err != nil {
		return nil, err
	}
	return &Signature{R: r, S: s}, nil
}

func verify(pub *backendPublicKey, hash []byte, sig *Signature) error {
	if !cng.VerifyECDSA(pub, hash, sig.R, sig.S) {
		return errVerification
	}
	return nil
}
