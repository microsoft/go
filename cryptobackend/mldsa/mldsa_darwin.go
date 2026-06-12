// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package mldsa

import "github.com/microsoft/go-crypto-darwin/xcrypto"

type Parameters = xcrypto.MLDSAParameters
type PrivateKey = xcrypto.PrivateKeyMLDSA
type PublicKey = xcrypto.PublicKeyMLDSA

func MLDSA44() Parameters                                { return Parameters{} }
func MLDSA65() Parameters                                { return xcrypto.MLDSA65() }
func MLDSA87() Parameters                                { return xcrypto.MLDSA87() }
func Supports(params Parameters) bool                    { return xcrypto.SupportsMLDSA(params) }
func SupportsExternalMu() bool                           { return false }
func GenerateKey(params Parameters) (*PrivateKey, error) { return xcrypto.GenerateKeyMLDSA(params) }
func NewPrivateKey(params Parameters, seed []byte) (*PrivateKey, error) {
	return xcrypto.NewPrivateKeyMLDSA(params, seed)
}
func NewPublicKey(params Parameters, publicKey []byte) (*PublicKey, error) {
	return xcrypto.NewPublicKeyMLDSA(params, publicKey)
}
