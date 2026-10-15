// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package dsa

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestSignatureEncoding(t *testing.T) {
	for _, values := range [][2]int64{{1, 127}, {128, 255}, {256, 65535}} {
		r, s := big.NewInt(values[0]), big.NewInt(values[1])
		sig, err := encodeSignature(r, s)
		if err != nil {
			t.Fatal(err)
		}
		want, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sig, want) {
			t.Fatalf("signature = %x, want %x", sig, want)
		}
		gotR, gotS, err := parseSignature(sig)
		if err != nil {
			t.Fatal(err)
		}
		if gotR.Cmp(r) != 0 || gotS.Cmp(s) != 0 {
			t.Fatal("signature integers changed during encoding")
		}
		if _, _, err := parseSignature(append(sig, 0)); err == nil {
			t.Fatal("accepted trailing data")
		}
	}
	for _, invalid := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1)} {
		if _, err := encodeSignature(invalid, big.NewInt(1)); err == nil {
			t.Fatal("encoded an invalid r")
		}
		if _, err := encodeSignature(big.NewInt(1), invalid); err == nil {
			t.Fatal("encoded an invalid s")
		}
	}
	for _, invalid := range [][]byte{
		nil,
		{0x30, 0x00},
		{0x30, 0x06, 0x02, 0x01, 0xff, 0x02, 0x01, 0x01},
		{0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01},
	} {
		if _, _, err := parseSignature(invalid); err == nil {
			t.Fatalf("accepted invalid ASN.1: %x", invalid)
		}
	}
}
