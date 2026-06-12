// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package mldsa

import "github.com/microsoft/go-crypto-openssl/openssl"

type Parameters = openssl.MLDSAParameters
type PrivateKey = openssl.PrivateKeyMLDSA
type PublicKey = openssl.PublicKeyMLDSA

func MLDSA44() Parameters                                { return openssl.MLDSA44() }
func MLDSA65() Parameters                                { return openssl.MLDSA65() }
func MLDSA87() Parameters                                { return openssl.MLDSA87() }
func Supports(params Parameters) bool                    { return openssl.SupportsMLDSA(params) }
func SupportsExternalMu() bool                           { return true }
func GenerateKey(params Parameters) (*PrivateKey, error) { return openssl.GenerateKeyMLDSA(params) }
func NewPrivateKey(params Parameters, seed []byte) (*PrivateKey, error) {
	return openssl.NewPrivateKeyMLDSA(params, seed)
}
func NewPublicKey(params Parameters, publicKey []byte) (*PublicKey, error) {
	return openssl.NewPublicKeyMLDSA(params, publicKey)
}
