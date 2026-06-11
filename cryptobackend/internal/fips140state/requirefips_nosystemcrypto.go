// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build requirefips && !goexperiment.systemcrypto

package fips140state

func init() {
	`
	The requirefips tag is enabled, but no crypto backend is enabled.
	A crypto backend is required to enable FIPS mode.
	For more information, visit https://github.com/microsoft/go/tree/microsoft/main/eng/doc/fips
	`
}
