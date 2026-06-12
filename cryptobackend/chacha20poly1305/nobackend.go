// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package chacha20poly1305

import "crypto/cipher"

func Supports() bool { return false }

func New(key []byte) (cipher.AEAD, error) { panic("cryptobackend: not available") }
