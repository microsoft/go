// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package mldsa

import "github.com/microsoft/go-crypto-darwin/xcrypto"

type Parameters = xcrypto.MLDSAParameters
type backendPrivateKey = xcrypto.PrivateKeyMLDSA
type backendPublicKey = xcrypto.PublicKeyMLDSA

func MLDSA44() Parameters             { return Parameters{} }
func MLDSA65() Parameters             { return xcrypto.MLDSA65() }
func MLDSA87() Parameters             { return xcrypto.MLDSA87() }
func Supports(params Parameters) bool { return xcrypto.SupportsMLDSA(params) }
func supportsExternalMu() bool        { return false }
func generateKey(params Parameters) (*backendPrivateKey, error) {
	return xcrypto.GenerateKeyMLDSA(params)
}
func newPrivateKey(params Parameters, seed []byte) (*backendPrivateKey, error) {
	return xcrypto.NewPrivateKeyMLDSA(params, seed)
}
func newPublicKey(params Parameters, publicKey []byte) (*backendPublicKey, error) {
	return xcrypto.NewPublicKeyMLDSA(params, publicKey)
}
