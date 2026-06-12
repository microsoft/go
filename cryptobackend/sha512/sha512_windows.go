// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package sha512

import (
	"hash"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func Supports512_224() bool { return false }
func Supports512_256() bool { return false }

func New() hash.Hash                  { return cng.NewSHA512() }
func New512_224() hash.Hash           { panic("cngcrypto: not available") }
func New512_256() hash.Hash           { panic("cngcrypto: not available") }
func New384() hash.Hash               { return cng.NewSHA384() }
func Sum512(data []byte) [64]byte     { return cng.SHA512(data) }
func Sum384(data []byte) [48]byte     { return cng.SHA384(data) }
func Sum512_224(data []byte) [28]byte { panic("cngcrypto: not available") }
func Sum512_256(data []byte) [32]byte { panic("cngcrypto: not available") }
