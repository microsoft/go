// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package sha512

import (
	"crypto"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

type backendHash = xcrypto.Hash

func Supports512() bool     { return xcrypto.SupportsHash(crypto.SHA512) }
func Supports384() bool     { return xcrypto.SupportsHash(crypto.SHA384) }
func Supports512_224() bool { return false }
func Supports512_256() bool { return false }

func newBackendHash512() *backendHash     { return xcrypto.NewSHA512() }
func newBackendHash384() *backendHash     { return xcrypto.NewSHA384() }
func newBackendHash512_224() *backendHash { panic("cryptobackend: not available") }
func newBackendHash512_256() *backendHash { panic("cryptobackend: not available") }
func sum512(data []byte) [64]byte         { return xcrypto.SHA512(data) }
func sum384(data []byte) [48]byte         { return xcrypto.SHA384(data) }
func sum512_224(data []byte) [28]byte     { panic("cryptobackend: not available") }
func sum512_256(data []byte) [32]byte     { panic("cryptobackend: not available") }
