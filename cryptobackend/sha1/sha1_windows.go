// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package sha1

import (
	"hash"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func New() hash.Hash { return cng.NewSHA1() }

func Sum(data []byte) [20]byte { return cng.SHA1(data) }
