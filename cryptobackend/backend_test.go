// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backend

import (
	"testing"
)

// Test that Unreachable panics.
func TestUnreachable(t *testing.T) {
	defer func() {
		if Enabled {
			if err := recover(); err == nil {
				t.Fatal("expected Unreachable to panic")
			}
		} else {
			if err := recover(); err != nil {
				t.Fatalf("expected Unreachable to be a no-op")
			}
		}
	}()
	Unreachable()
}

// Test that UnreachableExceptTests does not panic (this is a test).
func TestUnreachableExceptTests(t *testing.T) {
	UnreachableExceptTests()
}

func TestSupportsRSAPrivateKey(t *testing.T) {
	if !Enabled {
		t.Skip("BoringCrypto not enabled")
	}
	tests := []struct {
		bitLen    int
		numPrimes int
		supported bool
	}{
		{2048, 2, true},
		{3072, 2, true},
		{4096, 2, true},
		{2048, 3, false},
		{3072, 3, false},
		{4096, 3, false},
	}
	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			supported := SupportsRSAPrivateKey(test.bitLen, test.numPrimes)
			if supported != test.supported {
				t.Errorf("SupportsRSAPrivateKey(%d, %d) = %v; want %v", test.bitLen, test.numPrimes, supported, test.supported)
			}
		})
	}
}
