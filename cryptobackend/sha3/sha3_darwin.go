// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package sha3

import (
	"crypto"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

type backendHash = xcrypto.Hash

type backendSHAKE struct{}

func (*backendSHAKE) Write([]byte) (int, error)      { panic("cryptobackend: not available") }
func (*backendSHAKE) Read([]byte) (int, error)       { panic("cryptobackend: not available") }
func (*backendSHAKE) Reset()                         { panic("cryptobackend: not available") }
func (*backendSHAKE) BlockSize() int                 { panic("cryptobackend: not available") }
func (*backendSHAKE) MarshalBinary() ([]byte, error) { panic("cryptobackend: not available") }
func (*backendSHAKE) AppendBinary([]byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (*backendSHAKE) UnmarshalBinary([]byte) error { panic("cryptobackend: not available") }

func Supports224() bool { return false }
func Supports256() bool { return xcrypto.SupportsHash(crypto.SHA3_256) }
func Supports384() bool { return xcrypto.SupportsHash(crypto.SHA3_384) }
func Supports512() bool { return xcrypto.SupportsHash(crypto.SHA3_512) }

func SupportsSHAKE(securityBits int) bool  { return false }
func SupportsCSHAKE(securityBits int) bool { return false }

func newBackendHash256() *backendHash               { return xcrypto.NewSHA3_256() }
func newBackendHash224() *backendHash               { panic("cryptobackend: not available") }
func newBackendHash384() *backendHash               { return xcrypto.NewSHA3_384() }
func newBackendHash512() *backendHash               { return xcrypto.NewSHA3_512() }
func newBackendShake128() *backendSHAKE             { panic("cryptobackend: not available") }
func newBackendShake256() *backendSHAKE             { panic("cryptobackend: not available") }
func newBackendCShake128(N, S []byte) *backendSHAKE { panic("cryptobackend: not available") }
func newBackendCShake256(N, S []byte) *backendSHAKE { panic("cryptobackend: not available") }
func sum224(data []byte) [28]byte                   { panic("cryptobackend: not available") }
func sum256(data []byte) [32]byte                   { return xcrypto.SumSHA3_256(data) }
func sum384(data []byte) [48]byte                   { return xcrypto.SumSHA3_384(data) }
func sum512(data []byte) [64]byte                   { return xcrypto.SumSHA3_512(data) }
func sumSHAKE128(data []byte, length int) []byte    { panic("cryptobackend: not available") }
func sumSHAKE256(data []byte, length int) []byte    { panic("cryptobackend: not available") }
