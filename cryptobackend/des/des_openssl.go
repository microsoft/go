// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package des

import (
	"crypto/cipher"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

func SupportsDES() bool { return openssl.SupportsDESCipher() }

func SupportsTripleDES() bool { return openssl.SupportsTripleDESCipher() }

func NewDES(key []byte) (cipher.Block, error) { return openssl.NewDESCipher(key) }

func NewTripleDES(key []byte) (cipher.Block, error) { return openssl.NewTripleDESCipher(key) }
