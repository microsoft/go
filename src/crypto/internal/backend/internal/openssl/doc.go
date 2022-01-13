// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package openssl provides access to OpenSSLCrypto implementation functions.
// Check the constant Enabled to find out whether OpenSSLCrypto is available.
// If OpenSSLCrypto is not available, the functions in this package all panic.
package openssl

// Enabled returns whether or not the boring package is enabled. When
// the boring package is enabled that means FIPS mode is enabled.
func Enabled() bool {
	return enabled
}
