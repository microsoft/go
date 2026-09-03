// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package sha256

import (
	"crypto"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

type backendHash = xcrypto.Hash

func Supports256() bool { return xcrypto.SupportsHash(crypto.SHA256) }
func Supports224() bool { return false }

func newBackendHash256() *backendHash { return xcrypto.NewSHA256() }
func newBackendHash224() *backendHash { panic("cryptobackend: not available") }
func sum256(data []byte) [32]byte     { return xcrypto.SHA256(data) }
func sum224(data []byte) [28]byte     { panic("cryptobackend: not available") }
