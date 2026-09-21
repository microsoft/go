// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package sha3

import (
	"crypto"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

type backendHash = openssl.Hash
type backendSHAKE = openssl.SHAKE

func Supports224() bool { return openssl.SupportsHash(crypto.SHA3_224) }
func Supports256() bool { return openssl.SupportsHash(crypto.SHA3_256) }
func Supports384() bool { return openssl.SupportsHash(crypto.SHA3_384) }
func Supports512() bool { return openssl.SupportsHash(crypto.SHA3_512) }

func SupportsSHAKE(securityBits int) bool  { return openssl.SupportsSHAKE(securityBits) }
func SupportsCSHAKE(securityBits int) bool { return openssl.SupportsCSHAKE(securityBits) }

func newBackendHash256() *backendHash   { return openssl.NewSHA3_256() }
func newBackendHash224() *backendHash   { return openssl.NewSHA3_224() }
func newBackendHash384() *backendHash   { return openssl.NewSHA3_384() }
func newBackendHash512() *backendHash   { return openssl.NewSHA3_512() }
func newBackendShake128() *backendSHAKE { return openssl.NewSHAKE128() }
func newBackendShake256() *backendSHAKE { return openssl.NewSHAKE256() }
func newBackendCShake128(N, S []byte) *backendSHAKE {
	return openssl.NewCSHAKE128(N, S)
}
func newBackendCShake256(N, S []byte) *backendSHAKE {
	return openssl.NewCSHAKE256(N, S)
}
func sum224(data []byte) [28]byte                { return openssl.SumSHA3_224(data) }
func sum256(data []byte) [32]byte                { return openssl.SumSHA3_256(data) }
func sum384(data []byte) [48]byte                { return openssl.SumSHA3_384(data) }
func sum512(data []byte) [64]byte                { return openssl.SumSHA3_512(data) }
func sumSHAKE128(data []byte, length int) []byte { return openssl.SumSHAKE128(data, length) }
func sumSHAKE256(data []byte, length int) []byte { return openssl.SumSHAKE256(data, length) }
