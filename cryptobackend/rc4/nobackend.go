// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package rc4

type Cipher struct{}

func (c *Cipher) Reset() { panic("cryptobackend: not available") }

func (c *Cipher) XORKeyStream(dst, src []byte) { panic("cryptobackend: not available") }

func Supports() bool { panic("cryptobackend: not available") }

func New(key []byte) (*Cipher, error) { panic("cryptobackend: not available") }
