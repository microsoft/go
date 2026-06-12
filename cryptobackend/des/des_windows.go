// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package des

import (
	"crypto/cipher"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func SupportsDES() bool { return true }

func SupportsTripleDES() bool { return true }

func NewDES(key []byte) (cipher.Block, error) { return cng.NewDESCipher(key) }

func NewTripleDES(key []byte) (cipher.Block, error) { return cng.NewTripleDESCipher(key) }
