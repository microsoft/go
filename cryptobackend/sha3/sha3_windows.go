// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package sha3

import (
	"crypto"

	"github.com/microsoft/go-crypto-winnative/cng"
)

type Digest = cng.Hash
type Hash = cng.Hash
type SHAKE = cng.SHAKE

func Supports224() bool { return false }
func Supports256() bool { return cng.SupportsHash(crypto.SHA3_256) }
func Supports384() bool { return cng.SupportsHash(crypto.SHA3_384) }
func Supports512() bool { return cng.SupportsHash(crypto.SHA3_512) }

func SupportsSHAKE(securityBits int) bool  { return cng.SupportsSHAKE(securityBits) }
func SupportsCSHAKE(securityBits int) bool { return cng.SupportsSHAKE(securityBits) }

func New224() *Digest                            { panic("cryptobackend: not available") }
func New256() *Digest                            { return cng.NewSHA3_256() }
func New384() *Digest                            { return cng.NewSHA3_384() }
func New512() *Digest                            { return cng.NewSHA3_512() }
func NewShake128() *SHAKE                        { return cng.NewSHAKE128() }
func NewShake256() *SHAKE                        { return cng.NewSHAKE256() }
func NewCShake128(N, S []byte) *SHAKE            { return cng.NewCSHAKE128(N, S) }
func NewCShake256(N, S []byte) *SHAKE            { return cng.NewCSHAKE256(N, S) }
func Sum224(data []byte) [28]byte                { panic("cryptobackend: not available") }
func Sum256(data []byte) [32]byte                { return cng.SumSHA3_256(data) }
func Sum384(data []byte) [48]byte                { return cng.SumSHA3_384(data) }
func Sum512(data []byte) [64]byte                { return cng.SumSHA3_512(data) }
func SumSHAKE128(data []byte, length int) []byte { return cng.SumSHAKE128(data, length) }
func SumSHAKE256(data []byte, length int) []byte { return cng.SumSHAKE256(data, length) }
