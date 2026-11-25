// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package sha3

import "hash"

// Unwrap returns the selected hash implementation.
func Unwrap(h *Hash) hash.Hash { return h.unwrap() }
