// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import (
	"testing"

	boring "github.com/microsoft/go/cryptobackend"
)

func TestSupportsPrivateKey(t *testing.T) {
	if !boring.Enabled {
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
			supported := SupportsPrivateKey(test.bitLen, test.numPrimes)
			if supported != test.supported {
				t.Errorf("SupportsPrivateKey(%d, %d) = %v; want %v", test.bitLen, test.numPrimes, supported, test.supported)
			}
		})
	}
}
