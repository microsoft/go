// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pbkdf2_test

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"
)

type wrappedHash struct {
	hash.Hash
}

// TestFallback exercises the GOROOT-vendored backend, where the Go fallback is available.
func TestFallback(t *testing.T) {
	h := func() wrappedHash { return wrappedHash{sha256.New()} }
	want, err := hex.DecodeString("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
	if err != nil {
		t.Fatal(err)
	}
	key, err := pbkdf2.Key(h, "password", []byte("salt"), 2, len(want))
	if err != nil || !bytes.Equal(key, want) {
		t.Fatalf("Key = %x, %v; want %x, nil", key, err, want)
	}
	for _, keyLength := range []int{-1, 0} {
		if _, err := pbkdf2.Key(h, "password", []byte("salt"), 2, keyLength); err == nil {
			t.Errorf("Key accepted keyLength %d", keyLength)
		}
	}
}
