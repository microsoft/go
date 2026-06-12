// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package sha512

import "hash"

func Supports512_224() bool { panic("cryptobackend: not available") }
func Supports512_256() bool { panic("cryptobackend: not available") }

func New() hash.Hash                  { panic("cryptobackend: not available") }
func New512_224() hash.Hash           { panic("cryptobackend: not available") }
func New512_256() hash.Hash           { panic("cryptobackend: not available") }
func New384() hash.Hash               { panic("cryptobackend: not available") }
func Sum512(data []byte) [64]byte     { panic("cryptobackend: not available") }
func Sum384(data []byte) [48]byte     { panic("cryptobackend: not available") }
func Sum512_224(data []byte) [28]byte { panic("cryptobackend: not available") }
func Sum512_256(data []byte) [32]byte { panic("cryptobackend: not available") }
