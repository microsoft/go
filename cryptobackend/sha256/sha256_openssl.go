// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package sha256

import (
	"crypto"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

type backendHash = openssl.Hash

func Supports256() bool { return openssl.SupportsHash(crypto.SHA256) }
func Supports224() bool { return openssl.SupportsHash(crypto.SHA224) }

func newBackendHash256() *backendHash { return openssl.NewSHA256() }
func newBackendHash224() *backendHash { return openssl.NewSHA224() }
func sum256(data []byte) [32]byte     { return openssl.SHA256(data) }
func sum224(data []byte) [28]byte     { return openssl.SHA224(data) }
