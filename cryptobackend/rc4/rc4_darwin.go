// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package rc4

import "github.com/microsoft/go-crypto-darwin/xcrypto"

type Cipher = xcrypto.RC4Cipher

func Supports() bool { return true }

func New(key []byte) (*Cipher, error) { return xcrypto.NewRC4Cipher(key) }
