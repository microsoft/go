// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto && msgostd

package backend

import (
	"crypto/internal/boring/sig"
	"crypto/internal/fips140only"
	_ "unsafe"
)

func init() {
	sig.BoringCrypto()
	fips140only.BackendApprovedHash = FIPSApprovedHash
}
