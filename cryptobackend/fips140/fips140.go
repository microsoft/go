// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fips140

import (
	"github.com/microsoft/go/cryptobackend/internal/fips140state"
)

// Enabled reports whether FIPS 140 mode is enabled by using GODEBUG, GOFIPS,
// GOLANG_FIPS, or any platform-specific mechanism.
func Enabled() bool {
	return fips140state.Enabled()
}
