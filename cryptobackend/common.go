// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backend

import (
	"runtime"

	"github.com/microsoft/go/cryptobackend/internal/fips140state"
)

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

// Provided by runtime.crypto_backend_runtime_arg0 to avoid os import.
func runtime_arg0() string

func hasSuffix(s, t string) bool {
	return len(s) > len(t) && s[len(s)-len(t):] == t
}

// UnreachableExceptTests marks code that should be unreachable
// when backend is in use. It panics.
func UnreachableExceptTests() {
	// runtime_arg0 is not supported on windows.
	// We are going through the same code patch on linux,
	// so if we are unintentionally calling an 'unreachable' function,
	// we will catch it there.
	if Enabled && runtime.GOOS != "windows" {
		name := runtime_arg0()
		// If ran on Windows we'd need to allow _test.exe and .test.exe as well.
		if !hasSuffix(name, "_test") && !hasSuffix(name, ".test") {
			println("cryptobackend: unexpected code execution in", name)
			panic("cryptobackend: invalid code execution")
		}
	}
}
