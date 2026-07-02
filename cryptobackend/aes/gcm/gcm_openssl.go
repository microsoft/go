// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package gcm

import (
	"crypto/cipher"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

func NewTLS(c cipher.Block) (cipher.AEAD, error) { return openssl.NewGCMTLS(c) }

func NewTLS13(c cipher.Block) (cipher.AEAD, error) { return openssl.NewGCMTLS13(c) }
