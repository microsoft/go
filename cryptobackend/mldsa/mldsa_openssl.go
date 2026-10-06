// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package mldsa

import "github.com/microsoft/go-crypto-openssl/openssl"

type Parameters = openssl.MLDSAParameters
type backendPrivateKey = openssl.PrivateKeyMLDSA
type backendPublicKey = openssl.PublicKeyMLDSA

func MLDSA44() Parameters             { return openssl.MLDSA44() }
func MLDSA65() Parameters             { return openssl.MLDSA65() }
func MLDSA87() Parameters             { return openssl.MLDSA87() }
func Supports(params Parameters) bool { return openssl.SupportsMLDSA(params) }
func supportsExternalMu() bool        { return true }
func generateKey(params Parameters) (*backendPrivateKey, error) {
	return openssl.GenerateKeyMLDSA(params)
}
func newPrivateKey(params Parameters, seed []byte) (*backendPrivateKey, error) {
	return openssl.NewPrivateKeyMLDSA(params, seed)
}
func newPublicKey(params Parameters, publicKey []byte) (*backendPublicKey, error) {
	return openssl.NewPublicKeyMLDSA(params, publicKey)
}
