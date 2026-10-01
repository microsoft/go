// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdsa

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var errVerification = errors.New("ecdsa: signature did not verify")

func encodeSignature(sig *Signature) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, sig.R)
		addASN1IntBytes(b, sig.S)
	})
	return b.Bytes()
}

func addASN1IntBytes(b *cryptobyte.Builder, v []byte) {
	for len(v) > 0 && v[0] == 0 {
		v = v[1:]
	}
	if len(v) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(b *cryptobyte.Builder) {
		if v[0]&0x80 != 0 {
			b.AddUint8(0)
		}
		b.AddBytes(v)
	})
}

func parseSignature(sig []byte) (*Signature, error) {
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	var r, s []byte
	if !input.ReadASN1(&inner, asn1.SEQUENCE) || !input.Empty() ||
		!inner.ReadASN1Integer(&r) || !inner.ReadASN1Integer(&s) || !inner.Empty() {
		return nil, errors.New("invalid ASN.1")
	}
	return &Signature{R: r, S: s}, nil
}
