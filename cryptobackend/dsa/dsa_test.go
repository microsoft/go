// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dsa_test

import (
	"crypto/dsa"
	"crypto/fips140"
	"crypto/rand"
	"math/big"
	"runtime"
	"testing"

	boring "github.com/microsoft/go/cryptobackend"
	bdsa "github.com/microsoft/go/cryptobackend/dsa"
)

func requireDSA(t *testing.T) {
	t.Helper()
	if !boring.Enabled || !bdsa.Supports(1024, 160) {
		t.Skip("backend does not support DSA-1024/160")
	}
}

func requireDSASigning(t *testing.T) {
	t.Helper()
	requireDSA(t)
	if runtime.GOOS == "linux" && fips140.Enabled() {
		t.Skip("some OpenSSL FIPS providers do not support DSA signing")
	}
}

func testKey(t *testing.T) *dsa.PrivateKey {
	t.Helper()
	fromHex := func(s string) *big.Int {
		t.Helper()
		n, ok := new(big.Int).SetString(s, 16)
		if !ok {
			t.Fatal("invalid test key")
		}
		return n
	}
	priv := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: fromHex("A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF"),
				Q: fromHex("E1D3391245933D68A0714ED34BBCB7A1F422B9C1"),
				G: fromHex("634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA"),
			},
		},
		X: big.NewInt(2),
	}
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)
	return priv
}

func TestSignAndVerify(t *testing.T) {
	requireDSASigning(t)
	k := testKey(t)
	priv, err := bdsa.NewPrivateKey(k.P, k.Q, k.G, k.X, k.Y)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := bdsa.NewPublicKey(k.P, k.Q, k.G, k.Y)
	if err != nil {
		t.Fatal(err)
	}
	hash := []byte("testing")
	for range 3 {
		r, s, err := bdsa.Sign(priv, hash)
		if err != nil {
			t.Fatal(err)
		}
		if r == nil || s == nil || r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(k.Q) >= 0 || s.Cmp(k.Q) >= 0 {
			t.Fatal("signature integers are out of range")
		}
		if !bdsa.Verify(pub, hash, r, s) {
			t.Fatal("valid signature rejected")
		}
		if bdsa.Verify(pub, []byte("changed"), r, s) {
			t.Fatal("signature accepted for a different hash")
		}
		for _, invalid := range []*big.Int{nil, big.NewInt(0), new(big.Int).Neg(r), new(big.Int).Neg(s), k.Q} {
			if bdsa.Verify(pub, hash, invalid, s) || bdsa.Verify(pub, hash, r, invalid) {
				t.Fatal("signature accepted with an invalid integer")
			}
		}
	}
}

func TestStandardKeyMutation(t *testing.T) {
	requireDSASigning(t)
	k := testKey(t)
	hash := []byte("testing")
	r, s, err := dsa.Sign(rand.Reader, k, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !dsa.Verify(&k.PublicKey, hash, r, s) {
		t.Fatal("valid signature rejected")
	}

	original := k.PublicKey
	original.Y = new(big.Int).Set(k.Y)
	k.X.Add(k.X, big.NewInt(1))
	k.Y.Exp(k.G, k.X, k.P)
	if dsa.Verify(&k.PublicKey, hash, r, s) {
		t.Fatal("verification reused the old public key")
	}
	r, s, err = dsa.Sign(rand.Reader, k, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !dsa.Verify(&k.PublicKey, hash, r, s) || dsa.Verify(&original, hash, r, s) {
		t.Fatal("signing did not use the updated private key")
	}
}

func TestGenerateParameters(t *testing.T) {
	requireDSA(t)
	p, q, g, err := bdsa.GenerateParameters(1024, 160)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil || q == nil || g == nil {
		t.Fatal("missing generated parameters")
	}
	if p.BitLen() != 1024 || q.BitLen() != 160 {
		t.Fatalf("parameter sizes = %d/%d, want 1024/160", p.BitLen(), q.BitLen())
	}
	one := big.NewInt(1)
	if !p.ProbablyPrime(20) || !q.ProbablyPrime(20) ||
		new(big.Int).Mod(new(big.Int).Sub(p, one), q).Sign() != 0 ||
		g.Cmp(one) <= 0 || g.Cmp(p) >= 0 || new(big.Int).Exp(g, q, p).Cmp(one) != 0 {
		t.Fatal("invalid generated parameters")
	}
}

func TestGenerateKey(t *testing.T) {
	requireDSA(t)
	k := testKey(t)
	x, y, err := bdsa.GenerateKey(k.P, k.Q, k.G)
	if err != nil {
		t.Fatal(err)
	}
	if x == nil || y == nil || x.Sign() <= 0 || x.Cmp(k.Q) >= 0 {
		t.Fatal("invalid generated key")
	}
	if new(big.Int).Exp(k.G, x, k.P).Cmp(y) != 0 {
		t.Fatal("public and private values do not match")
	}
}

func TestGenerateErrors(t *testing.T) {
	requireDSA(t)
	p, q, g, err := bdsa.GenerateParameters(-1, -1)
	if err == nil || p != nil || q != nil || g != nil {
		t.Fatalf("GenerateParameters(-1, -1) = %v, %v, %v, %v; want nil outputs and an error", p, q, g, err)
	}
	x, y, err := bdsa.GenerateKey(nil, nil, nil)
	if err == nil || x != nil || y != nil {
		t.Fatalf("GenerateKey(nil, nil, nil) = %v, %v, %v; want nil outputs and an error", x, y, err)
	}
}

func TestGenerateKeyErrorPreservesKey(t *testing.T) {
	requireDSA(t)
	k := testKey(t)
	k.P.SetInt64(0)
	x, y := k.X, k.Y
	if err := dsa.GenerateKey(k, rand.Reader); err == nil {
		t.Fatal("GenerateKey succeeded with an invalid modulus")
	}
	if k.X != x || k.Y != y {
		t.Fatal("GenerateKey changed the key on error")
	}
}
