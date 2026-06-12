// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package backend

func init() {
	// Darwin is considered FIPS compliant.
	if err := checkFIPS(func() bool { return true }); err != nil {
		panic("darwincrypto: " + err.Error())
	}
}

// Enabled controls whether FIPS crypto is enabled.
const Enabled = true
