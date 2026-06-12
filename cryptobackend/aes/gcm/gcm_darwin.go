// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package gcm

import (
	"crypto/cipher"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func NewTLS(c cipher.Block) (cipher.AEAD, error) { return xcrypto.NewGCMTLS(c) }

func NewTLS13(c cipher.Block) (cipher.AEAD, error) { return xcrypto.NewGCMTLS13(c) }
