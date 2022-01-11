// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package openssl

import "testing"

// Just tests that we can create an HMAC instance.
// Previously would cause panic because of incorrect
// stack allocation of opaque OpenSSL type.
func TestNewHMAC(t *testing.T) {
	mac := NewHMAC(NewSHA256, nil)
	mac.Write([]byte("foo"))
	t.Logf("%x\n", mac.Sum(nil))
}
