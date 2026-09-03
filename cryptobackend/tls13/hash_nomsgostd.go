// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd

package tls13

import "hash"

func unwrapHashFunc[H hash.Hash](newHash func() H) func() H {
	return newHash
}