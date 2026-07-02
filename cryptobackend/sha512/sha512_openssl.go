// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto && (linux || freebsd)

package sha512

import (
	"crypto"
	"hash"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

func Supports512_224() bool { return openssl.SupportsHash(crypto.SHA512_224) }
func Supports512_256() bool { return openssl.SupportsHash(crypto.SHA512_256) }

func New() hash.Hash                  { return openssl.NewSHA512() }
func New512_224() hash.Hash           { return openssl.NewSHA512_224() }
func New512_256() hash.Hash           { return openssl.NewSHA512_256() }
func New384() hash.Hash               { return openssl.NewSHA384() }
func Sum512(data []byte) [64]byte     { return openssl.SHA512(data) }
func Sum384(data []byte) [48]byte     { return openssl.SHA384(data) }
func Sum512_224(data []byte) [28]byte { return openssl.SHA512_224(data) }
func Sum512_256(data []byte) [32]byte { return openssl.SHA512_256(data) }
