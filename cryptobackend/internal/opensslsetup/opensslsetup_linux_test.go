// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto && cgo

package opensslsetup

import "testing"

func mockCheckVersion(t *testing.T, fn func(string) (bool, bool)) {
	original := checkVersion
	t.Cleanup(func() {
		checkVersion = original
	})
	checkVersion = fn
}

func assertLibrary(t *testing.T, expected string) {
	if result := library(); result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestLibraryWithEnvOverride(t *testing.T) {
	t.Setenv("GO_OPENSSL_VERSION_OVERRIDE", "1.1")
	mockCheckVersion(t, func(s string) (bool, bool) { return false, false })
	assertLibrary(t, "libcrypto.so.1.1")
}

func TestLibraryWithKnownVersion(t *testing.T) {
	t.Setenv("GO_OPENSSL_VERSION_OVERRIDE", "")

	const maxLib = "libcrypto.so.3"

	t.Run("AllExistsNoneFIPS", func(t *testing.T) {
		mockCheckVersion(t, func(s string) (bool, bool) {
			return true, false
		})
		for _, v := range knownVersions {
			t.Run(v, func(t *testing.T) {
				assertLibrary(t, maxLib)
			})
		}
	})

	t.Run("OnlyOneExists", func(t *testing.T) {
		for _, v := range knownVersions {
			t.Run(v, func(t *testing.T) {
				expected := "libcrypto.so." + v
				mockCheckVersion(t, func(s string) (bool, bool) {
					if s == expected {
						return true, false
					}
					return false, false
				})
				assertLibrary(t, expected)
			})
		}
	})

	t.Run("AllExistsOnlyOneFIPS", func(t *testing.T) {
		fipsLib := "libcrypto.so.1.1"
		mockCheckVersion(t, func(s string) (bool, bool) {
			return true, s == fipsLib
		})
		for _, v := range knownVersions {
			t.Run(v, func(t *testing.T) {
				assertLibrary(t, fipsLib)
			})
		}
	})

	t.Run("AllExistsAndAreFIPS", func(t *testing.T) {
		mockCheckVersion(t, func(s string) (bool, bool) {
			return true, true
		})
		for _, v := range knownVersions {
			t.Run(v, func(t *testing.T) {
				assertLibrary(t, maxLib)
			})
		}
	})
}

func TestLibraryNoVersionFound(t *testing.T) {
	t.Setenv("GO_OPENSSL_VERSION_OVERRIDE", "")
	mockCheckVersion(t, func(string) (bool, bool) {
		return false, false
	})
	assertLibrary(t, "libcrypto.so")
}
