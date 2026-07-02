// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package aes

import (
	"crypto/cipher"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

func New(key []byte) (cipher.Block, error) { return openssl.NewAESCipher(key) }
