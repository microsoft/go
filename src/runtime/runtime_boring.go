// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import _ "unsafe" // for go:linkname

//go:linkname boring_runtime_arg0 crypto/internal/boring.runtime_arg0
func boring_runtime_arg0() string {
	// On Windows, argslice is not set, and it's too much work to find argv0.
	if len(argslice) == 0 {
		return ""
	}
	return argslice[0]
}

//go:linkname fipstls_runtime_arg0 crypto/internal/boring/fipstls.runtime_arg0
func fipstls_runtime_arg0() string { return boring_runtime_arg0() }

//go:linkname crypto_backend_runtime_arg0 crypto/internal/backend.runtime_arg0
func crypto_backend_runtime_arg0() string {
	return boring_runtime_arg0()
}

//go:linkname crypto_backend_runtime_envs crypto/internal/backend.runtime_envs
func crypto_backend_runtime_envs() []string { return append([]string{}, envs...) }
