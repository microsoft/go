// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package sha3

import (
	"crypto"
	"hash"
	"io"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

type Digest = xcrypto.Hash
type Hash = xcrypto.Hash

type SHAKE struct {
	io.Reader
	hash.Hash
}

func (s *SHAKE) MarshalBinary() ([]byte, error)        { panic("cryptobackend: not available") }
func (s *SHAKE) AppendBinary(p []byte) ([]byte, error) { panic("cryptobackend: not available") }
func (s *SHAKE) UnmarshalBinary(data []byte) error     { panic("cryptobackend: not available") }

func Supports224() bool { return false }
func Supports256() bool { return xcrypto.SupportsHash(crypto.SHA3_256) }
func Supports384() bool { return xcrypto.SupportsHash(crypto.SHA3_384) }
func Supports512() bool { return xcrypto.SupportsHash(crypto.SHA3_512) }

func SupportsSHAKE(securityBits int) bool  { return false }
func SupportsCSHAKE(securityBits int) bool { return false }

func New224() *Digest                            { panic("cryptobackend: not available") }
func New256() *Digest                            { return xcrypto.NewSHA3_256() }
func New384() *Digest                            { return xcrypto.NewSHA3_384() }
func New512() *Digest                            { return xcrypto.NewSHA3_512() }
func NewShake128() *SHAKE                        { panic("cryptobackend: not available") }
func NewShake256() *SHAKE                        { panic("cryptobackend: not available") }
func NewCShake128(N, S []byte) *SHAKE            { panic("cryptobackend: not available") }
func NewCShake256(N, S []byte) *SHAKE            { panic("cryptobackend: not available") }
func Sum224(data []byte) [28]byte                { panic("cryptobackend: not available") }
func Sum256(data []byte) [32]byte                { return xcrypto.SumSHA3_256(data) }
func Sum384(data []byte) [48]byte                { return xcrypto.SumSHA3_384(data) }
func Sum512(data []byte) [64]byte                { return xcrypto.SumSHA3_512(data) }
func SumSHAKE128(data []byte, length int) []byte { panic("cryptobackend: not available") }
func SumSHAKE256(data []byte, length int) []byte { panic("cryptobackend: not available") }
