// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package dsa_test

import (
	"crypto/dsa"
	"math/big"
	"runtime"
	"sync"
	"testing"

	bdsa "github.com/microsoft/go/cryptobackend/dsa"
)

func TestPublicKeyCache(t *testing.T) {
	requireDSA(t)
	var cache bdsa.PublicKeyCache[dsa.PublicKey]
	testKeyCache(t, func(k *dsa.PrivateKey) (*bdsa.PublicKey, error) {
		return cache.Get(&k.PublicKey, k.P, k.Q, k.G, k.Y)
	}, []string{"P", "Q", "G", "Y"})
}

func TestPrivateKeyCache(t *testing.T) {
	requireDSA(t)
	var cache bdsa.PrivateKeyCache[dsa.PrivateKey]
	testKeyCache(t, func(k *dsa.PrivateKey) (*bdsa.PrivateKey, error) {
		return cache.Get(k, k.P, k.Q, k.G, k.X, k.Y)
	}, []string{"P", "Q", "G", "X", "Y"})
}

func testKeyCache[K any](t *testing.T, get func(*dsa.PrivateKey) (*K, error), fields []string) {
	t.Helper()
	t.Run("reuse", func(t *testing.T) {
		owner := testKey(t)
		first, err := get(owner)
		if err != nil {
			t.Fatal(err)
		}
		owner.Y = new(big.Int).Set(owner.Y)
		runtime.GC()
		second, err := get(owner)
		if err != nil {
			t.Fatal(err)
		}
		if first != second {
			t.Fatal("unchanged parameters did not reuse the native key")
		}
		other, err := get(testKey(t))
		if err != nil {
			t.Fatal(err)
		}
		if first == other {
			t.Fatal("different owners shared a cache entry")
		}
		allocs := testing.AllocsPerRun(100, func() {
			key, err := get(owner)
			if err != nil {
				t.Fatal(err)
			}
			if key != first {
				t.Fatal("unchanged parameters did not reuse the native key")
			}
		})
		if allocs != 0 {
			t.Errorf("cache hit allocated %v times, want 0", allocs)
		}
	})
	for _, field := range fields {
		t.Run("mutate"+field, func(t *testing.T) {
			owner := testKey(t)
			first, err := get(owner)
			if err != nil {
				t.Fatal(err)
			}
			param := map[string]*big.Int{
				"P": owner.P, "Q": owner.Q, "G": owner.G, "X": owner.X, "Y": owner.Y,
			}[field]
			original := new(big.Int).Set(param)
			param.Add(param, big.NewInt(1))
			changed, err := get(owner)
			if changed == first {
				t.Fatal("mutated parameters reused the old native key")
			}
			if err != nil {
				if changed != nil {
					t.Fatal("failed key import returned a key")
				}
				t.Logf("native provider rejected the mutated %s: %v", field, err)
			}
			param.Set(original)
			restored, err := get(owner)
			if err != nil {
				t.Fatal(err)
			}
			if restored == nil || restored == changed {
				t.Fatal("restored parameters did not recover a valid cache entry")
			}
		})
	}
	t.Run("concurrent", func(t *testing.T) {
		owner := testKey(t)
		first, err := get(owner)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				key, err := get(owner)
				if err != nil {
					t.Error(err)
				} else if key != first {
					t.Error("concurrent lookup did not reuse the native key")
				}
			}()
		}
		wg.Wait()
	})
}
