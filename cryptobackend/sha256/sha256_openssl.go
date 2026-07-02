// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto && (linux || freebsd)

package sha256

import (
	"crypto"
	"hash"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

func Supports224() bool { return openssl.SupportsHash(crypto.SHA224) }

func New() hash.Hash              { return openssl.NewSHA256() }
func New224() hash.Hash           { return openssl.NewSHA224() }
func Sum256(data []byte) [32]byte { return openssl.SHA256(data) }
func Sum224(data []byte) [28]byte { return openssl.SHA224(data) }
