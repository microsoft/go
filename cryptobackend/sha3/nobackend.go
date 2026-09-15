// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package sha3

import (
	"hash"
)

type backendHash struct{}

func (h *backendHash) Write(p []byte) (int, error)           { panic("cryptobackend: not available") }
func (h *backendHash) Sum(p []byte) []byte                   { panic("cryptobackend: not available") }
func (h *backendHash) Reset()                                { panic("cryptobackend: not available") }
func (h *backendHash) Size() int                             { panic("cryptobackend: not available") }
func (h *backendHash) BlockSize() int                        { panic("cryptobackend: not available") }
func (h *backendHash) MarshalBinary() ([]byte, error)        { panic("cryptobackend: not available") }
func (h *backendHash) AppendBinary(p []byte) ([]byte, error) { panic("cryptobackend: not available") }
func (h *backendHash) UnmarshalBinary(data []byte) error     { panic("cryptobackend: not available") }
func (h *backendHash) Clone() (hash.Cloner, error)           { panic("cryptobackend: not available") }

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

func Supports224() bool { panic("cryptobackend: not available") }
func Supports256() bool { panic("cryptobackend: not available") }
func Supports384() bool { panic("cryptobackend: not available") }
func Supports512() bool { panic("cryptobackend: not available") }

func SupportsSHAKE(securityBits int) bool  { panic("cryptobackend: not available") }
func SupportsCSHAKE(securityBits int) bool { panic("cryptobackend: not available") }

func newBackendHash256() *backendHash               { panic("cryptobackend: not available") }
func newBackendHash224() *backendHash               { panic("cryptobackend: not available") }
func newBackendHash384() *backendHash               { panic("cryptobackend: not available") }
func newBackendHash512() *backendHash               { panic("cryptobackend: not available") }
func newBackendShake128() *backendSHAKE             { panic("cryptobackend: not available") }
func newBackendShake256() *backendSHAKE             { panic("cryptobackend: not available") }
func newBackendCShake128(N, S []byte) *backendSHAKE { panic("cryptobackend: not available") }
func newBackendCShake256(N, S []byte) *backendSHAKE { panic("cryptobackend: not available") }
func sum224(data []byte) [28]byte                   { panic("cryptobackend: not available") }
func sum256(data []byte) [32]byte                   { panic("cryptobackend: not available") }
func sum384(data []byte) [48]byte                   { panic("cryptobackend: not available") }
func sum512(data []byte) [64]byte                   { panic("cryptobackend: not available") }
func sumSHAKE128(data []byte, length int) []byte    { panic("cryptobackend: not available") }
func sumSHAKE256(data []byte, length int) []byte    { panic("cryptobackend: not available") }
