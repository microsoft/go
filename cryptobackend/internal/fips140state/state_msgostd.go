// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd

package fips140state

import "internal/godebug"

var fips140GODEBUG = godebug.New("fips140").Value()
