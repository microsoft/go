// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backend

import "github.com/microsoft/go/cryptobackend/internal/fips140state"

func checkFIPS(fips func() bool) error {
	return fips140state.Check(Enabled, fips)
}

// Unreachable marks code that should be unreachable
// when backend is in use.
func Unreachable() {
	if Enabled {
		panic("cryptobackend: invalid code execution")
	}
}
