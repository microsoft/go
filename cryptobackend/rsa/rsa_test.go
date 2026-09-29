// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto"
	"crypto/rand"
	"math/big"
	"runtime/debug"
	"sync"
	"testing"

	backend "github.com/microsoft/go/cryptobackend"
)

func TestSupportsPrivateKey(t *testing.T) {
	if !backend.Enabled {
		t.Skip("systemcrypto not enabled")
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
	primes := []*big.Int{big.NewInt(2), big.NewInt(3), big.NewInt(5)}
	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			key := &PrivateKey{
				pub:    PublicKey{n: new(big.Int).Lsh(big.NewInt(1), uint(test.bitLen-1))},
				primes: primes[:test.numPrimes],
			}
			supported := key.supportsBackend()
			if supported != test.supported {
				t.Errorf("supportsBackend(%d bits, %d primes) = %v; want %v", test.bitLen, test.numPrimes, supported, test.supported)
			}
		})
	}
}

func TestFinalizers(t *testing.T) {
	if !backend.Enabled {
		t.Skip("systemcrypto not enabled")
	}
	if !supportsPublicKey(2048) || !supportsPKCS1v15Signature(crypto.SHA256) {
		t.Skip("backend does not support RSA-2048 with SHA-256")
	}
	k, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	N, e, d, P, Q, dP, dQ, qInv := k.Export()

	// Frequent GC stresses the native key's lifetime during signing.
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	for n := 0; n < 200; n++ {
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Import a fresh key in each goroutine so cached keys cannot
				// keep the native objects alive for the whole test.
				priv := &PrivateKey{
					pub: PublicKey{n: new(big.Int).SetBytes(N), e: e},
					d:   new(big.Int).SetBytes(d),
					primes: []*big.Int{
						new(big.Int).SetBytes(P), new(big.Int).SetBytes(Q),
					},
					dp: new(big.Int).SetBytes(dP),
					dq: new(big.Int).SetBytes(dQ),
					qi: new(big.Int).SetBytes(qInv),
				}
				sum := make([]byte, crypto.SHA256.Size())
				if _, err := SignPKCS1v15(priv, crypto.SHA256.String(), sum); err != nil {
					panic(err) // Native lifetime errors can corrupt memory; stop immediately.
				}
			}()
		}
		wg.Wait()
	}
}
