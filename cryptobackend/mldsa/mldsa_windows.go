// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package mldsa

import "github.com/microsoft/go-crypto-winnative/cng"

type Parameters = cng.MLDSAParameters
type PrivateKey = cng.PrivateKeyMLDSA
type PublicKey = cng.PublicKeyMLDSA

func MLDSA44() Parameters                                { return cng.MLDSA44() }
func MLDSA65() Parameters                                { return cng.MLDSA65() }
func MLDSA87() Parameters                                { return cng.MLDSA87() }
func Supports(params Parameters) bool                    { return cng.SupportsMLDSA() }
func SupportsExternalMu() bool                           { return true }
func GenerateKey(params Parameters) (*PrivateKey, error) { return cng.GenerateKeyMLDSA(params) }
func NewPrivateKey(params Parameters, seed []byte) (*PrivateKey, error) {
	return cng.NewPrivateKeyMLDSA(params, seed)
}
func NewPublicKey(params Parameters, publicKey []byte) (*PublicKey, error) {
	return cng.NewPublicKeyMLDSA(params, publicKey)
}
