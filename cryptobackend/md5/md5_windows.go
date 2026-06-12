// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package md5

import (
	"crypto"
	"hash"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func Supports() bool { return cng.SupportsHash(crypto.MD5) }

func New() hash.Hash { return cng.NewMD5() }

func Sum(data []byte) [16]byte { return cng.MD5(data) }
