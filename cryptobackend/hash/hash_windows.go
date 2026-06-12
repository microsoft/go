// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package hash

import (
	"hash"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func Approved(h hash.Hash) bool { return cng.FIPSApprovedHash(h) }
