// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package sha3

import (
	"crypto"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

type Digest = openssl.Hash
type Hash = openssl.Hash
type SHAKE = openssl.SHAKE

func Supports224() bool { return openssl.SupportsHash(crypto.SHA3_224) }
func Supports256() bool { return openssl.SupportsHash(crypto.SHA3_256) }
func Supports384() bool { return openssl.SupportsHash(crypto.SHA3_384) }
func Supports512() bool { return openssl.SupportsHash(crypto.SHA3_512) }

func SupportsSHAKE(securityBits int) bool  { return openssl.SupportsSHAKE(securityBits) }
func SupportsCSHAKE(securityBits int) bool { return openssl.SupportsCSHAKE(securityBits) }

func New224() *Digest                            { return openssl.NewSHA3_224() }
func New256() *Digest                            { return openssl.NewSHA3_256() }
func New384() *Digest                            { return openssl.NewSHA3_384() }
func New512() *Digest                            { return openssl.NewSHA3_512() }
func NewShake128() *SHAKE                        { return openssl.NewSHAKE128() }
func NewShake256() *SHAKE                        { return openssl.NewSHAKE256() }
func NewCShake128(N, S []byte) *SHAKE            { return openssl.NewCSHAKE128(N, S) }
func NewCShake256(N, S []byte) *SHAKE            { return openssl.NewCSHAKE256(N, S) }
func Sum224(data []byte) [28]byte                { return openssl.SumSHA3_224(data) }
func Sum256(data []byte) [32]byte                { return openssl.SumSHA3_256(data) }
func Sum384(data []byte) [48]byte                { return openssl.SumSHA3_384(data) }
func Sum512(data []byte) [64]byte                { return openssl.SumSHA3_512(data) }
func SumSHAKE128(data []byte, length int) []byte { return openssl.SumSHAKE128(data, length) }
func SumSHAKE256(data []byte, length int) []byte { return openssl.SumSHAKE256(data, length) }
