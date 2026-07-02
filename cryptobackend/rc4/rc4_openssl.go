// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto && (linux || freebsd)

package rc4

import "github.com/microsoft/go-crypto-openssl/openssl"

type Cipher = openssl.RC4Cipher

func Supports() bool { return openssl.SupportsRC4() }

func New(key []byte) (*Cipher, error) { return openssl.NewRC4Cipher(key) }
