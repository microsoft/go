// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package des

import "crypto/cipher"

func SupportsDES() bool { panic("cryptobackend: not available") }

func SupportsTripleDES() bool { panic("cryptobackend: not available") }

func NewDES(key []byte) (cipher.Block, error) { panic("cryptobackend: not available") }

func NewTripleDES(key []byte) (cipher.Block, error) { panic("cryptobackend: not available") }
