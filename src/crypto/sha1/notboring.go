// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cmd_go_bootstrap no_openssl

package sha1

import (
	"hash"
)

func boringEnabled() bool {
	return false
}

func boringNewSHA1() hash.Hash { panic("boringcrypto: not available") }

func boringUnreachable() {}
