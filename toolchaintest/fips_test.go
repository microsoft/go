// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toolchaintest

import (
	"crypto/fips140"
	"flag"
	"testing"
)

var requireFIPS = flag.Bool("require-fips", false, "Require FIPS mode to be enabled in the test process")

func TestFIPSMode(t *testing.T) {
	if !*requireFIPS {
		t.Skip("FIPS mode is not required")
	}
	if !fips140.Enabled() {
		t.Fatal("FIPS mode is required, but crypto/fips140.Enabled() is false")
	}
}
