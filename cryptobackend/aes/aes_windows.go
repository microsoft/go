// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package aes

import (
	"crypto/cipher"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func New(key []byte) (cipher.Block, error) { return cng.NewAESCipher(key) }
