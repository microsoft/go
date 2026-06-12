// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package sha3

import (
	"hash"
	"io"
)

type Digest struct{ hash.Cloner }
type Hash = Digest

type SHAKE struct {
	io.Reader
	hash.Hash
}

func (d *Digest) MarshalBinary() ([]byte, error)        { panic("cryptobackend: not available") }
func (d *Digest) AppendBinary(p []byte) ([]byte, error) { panic("cryptobackend: not available") }
func (d *Digest) UnmarshalBinary(data []byte) error     { panic("cryptobackend: not available") }
func (s *SHAKE) MarshalBinary() ([]byte, error)         { panic("cryptobackend: not available") }
func (s *SHAKE) AppendBinary(p []byte) ([]byte, error)  { panic("cryptobackend: not available") }
func (s *SHAKE) UnmarshalBinary(data []byte) error      { panic("cryptobackend: not available") }

func Supports224() bool { panic("cryptobackend: not available") }
func Supports256() bool { panic("cryptobackend: not available") }
func Supports384() bool { panic("cryptobackend: not available") }
func Supports512() bool { panic("cryptobackend: not available") }

func SupportsSHAKE(securityBits int) bool  { panic("cryptobackend: not available") }
func SupportsCSHAKE(securityBits int) bool { panic("cryptobackend: not available") }

func New224() *Digest                            { panic("cryptobackend: not available") }
func New256() *Digest                            { panic("cryptobackend: not available") }
func New384() *Digest                            { panic("cryptobackend: not available") }
func New512() *Digest                            { panic("cryptobackend: not available") }
func NewShake128() *SHAKE                        { panic("cryptobackend: not available") }
func NewShake256() *SHAKE                        { panic("cryptobackend: not available") }
func NewCShake128(N, S []byte) *SHAKE            { panic("cryptobackend: not available") }
func NewCShake256(N, S []byte) *SHAKE            { panic("cryptobackend: not available") }
func Sum224(data []byte) [28]byte                { panic("cryptobackend: not available") }
func Sum256(data []byte) [32]byte                { panic("cryptobackend: not available") }
func Sum384(data []byte) [48]byte                { panic("cryptobackend: not available") }
func Sum512(data []byte) [64]byte                { panic("cryptobackend: not available") }
func SumSHAKE128(data []byte, length int) []byte { panic("cryptobackend: not available") }
func SumSHAKE256(data []byte, length int) []byte { panic("cryptobackend: not available") }
