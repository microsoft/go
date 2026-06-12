// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package md5

import (
	"crypto"
	"hash"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func Supports() bool { return xcrypto.SupportsHash(crypto.MD5) }

func New() hash.Hash { return xcrypto.NewMD5() }

func Sum(data []byte) [16]byte { return xcrypto.MD5(data) }
