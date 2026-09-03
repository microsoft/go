// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package sha512

import (
	"crypto"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

type backendHash = openssl.Hash

func Supports512() bool     { return openssl.SupportsHash(crypto.SHA512) }
func Supports384() bool     { return openssl.SupportsHash(crypto.SHA384) }
func Supports512_224() bool { return openssl.SupportsHash(crypto.SHA512_224) }
func Supports512_256() bool { return openssl.SupportsHash(crypto.SHA512_256) }

func newBackendHash512() *backendHash     { return openssl.NewSHA512() }
func newBackendHash384() *backendHash     { return openssl.NewSHA384() }
func newBackendHash512_224() *backendHash { return openssl.NewSHA512_224() }
func newBackendHash512_256() *backendHash { return openssl.NewSHA512_256() }
func sum512(data []byte) [64]byte         { return openssl.SHA512(data) }
func sum384(data []byte) [48]byte         { return openssl.SHA384(data) }
func sum512_224(data []byte) [28]byte     { return openssl.SHA512_224(data) }
func sum512_256(data []byte) [32]byte     { return openssl.SHA512_256(data) }
