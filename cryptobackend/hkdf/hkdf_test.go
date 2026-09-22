// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hkdf_test

import (
	"bytes"
	"crypto/hkdf"
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
	// RFC 5869, test case 1, using a hash that native backends do not recognize.
	secret := bytes.Repeat([]byte{0x0b}, 22)
	salt := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	info := string([]byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9})
	wantPRK, err := hex.DecodeString("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	if err != nil {
		t.Fatal(err)
	}
	wantKey, err := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	if err != nil {
		t.Fatal(err)
	}

	prk, err := hkdf.Extract(h, secret, salt)
	if err != nil || !bytes.Equal(prk, wantPRK) {
		t.Fatalf("Extract = %x, %v; want %x, nil", prk, err, wantPRK)
	}
	expanded, err := hkdf.Expand(h, prk, info, len(wantKey))
	if err != nil || !bytes.Equal(expanded, wantKey) {
		t.Fatalf("Expand = %x, %v; want %x, nil", expanded, err, wantKey)
	}
	key, err := hkdf.Key(h, secret, salt, info, len(wantKey))
	if err != nil || !bytes.Equal(key, wantKey) {
		t.Fatalf("Key = %x, %v; want %x, nil", key, err, wantKey)
	}

	key, err = hkdf.Key(h, secret, nil, "", 0)
	if err != nil || len(key) != 0 {
		t.Fatalf("Key with zero length = %x, %v; want an empty key", key, err)
	}
	if _, err := hkdf.Key(h, secret, salt, info, 255*sha256.Size+1); err == nil {
		t.Error("Key accepted an excessive key length")
	}
	if _, err := hkdf.Expand(h, prk, info, 255*sha256.Size+1); err == nil {
		t.Error("Expand accepted an excessive key length")
	}
}
