// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package sha256

import (
	"hash"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func Supports224() bool { return false }

func New() hash.Hash              { return xcrypto.NewSHA256() }
func New224() hash.Hash           { panic("cryptobackend: not available") }
func Sum256(data []byte) [32]byte { return xcrypto.SHA256(data) }
func Sum224(data []byte) [28]byte { panic("cryptobackend: not available") }
