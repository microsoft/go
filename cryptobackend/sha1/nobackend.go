// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package sha1

import "hash"

func New() hash.Hash { panic("cryptobackend: not available") }

func Sum(data []byte) [20]byte { panic("cryptobackend: not available") }
