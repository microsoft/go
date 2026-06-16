// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package rsa

import (
	"crypto"
	"errors"
	"hash"
	"math/big"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
	"github.com/microsoft/go/cryptobackend/bbig"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type BigInt = xcrypto.BigInt
type PrivateKey = xcrypto.PrivateKeyRSA
type PublicKey = xcrypto.PublicKeyRSA

func SupportsPrivateKey(bits, primes int) bool    { return primes == 2 && SupportsPublicKey(bits) }
func SupportsPublicKey(bits int) bool             { return bits >= 1024 && bits%8 == 0 && bits <= 16384 }
func SupportsSaltLength(sign bool, salt int) bool { return salt == -1 }
func SupportsOAEPLabel(label []byte) bool         { return len(label) == 0 }
func SupportsPKCS1v15Encryption() bool            { return true }
func SupportsPKCS1v15Signature(h crypto.Hash) bool {
	switch h {
	case crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512, 0:
		return true
	}
	return false
}

func SupportsPSSHash(h crypto.Hash) bool { return xcrypto.SupportsHash(h) }

func decodeKey(data []byte) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	bad := func(e error) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
		return nil, nil, nil, nil, nil, nil, nil, nil, e
	}
	input := cryptobyte.String(data)
	var seq cryptobyte.String
	var version int
	n, e, d, p, q, dp, dq, qinv := new(big.Int), new(big.Int), new(big.Int), new(big.Int),
		new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	if !input.ReadASN1(&seq, asn1.SEQUENCE) {
		return bad(errors.New("invalid ASN.1 structure: not a sequence"))
	}
	if !input.Empty() {
		return bad(errors.New("invalid ASN.1 structure: trailing data"))
	}
	if !seq.ReadASN1Integer(&version) || version != 0 {
		return bad(errors.New("invalid ASN.1 structure: unsupported version"))
	}
	if !seq.ReadASN1Integer(n) || !seq.ReadASN1Integer(e) ||
		!seq.ReadASN1Integer(d) || !seq.ReadASN1Integer(p) ||
		!seq.ReadASN1Integer(q) || !seq.ReadASN1Integer(dp) ||
		!seq.ReadASN1Integer(dq) || !seq.ReadASN1Integer(qinv) ||
		!seq.Empty() {
		return bad(errors.New("invalid ASN.1 structure"))
	}
	return bbig.Enc(n), bbig.Enc(e), bbig.Enc(d), bbig.Enc(p), bbig.Enc(q),
		bbig.Enc(dp), bbig.Enc(dq), bbig.Enc(qinv), nil
}

func encodeKey(N, E, D, P, Q, Dp, Dq, Qinv BigInt) ([]byte, error) {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1BigInt(bbig.Dec(N))
		b.AddASN1BigInt(bbig.Dec(E))
		b.AddASN1BigInt(bbig.Dec(D))
		b.AddASN1BigInt(bbig.Dec(P))
		b.AddASN1BigInt(bbig.Dec(Q))
		b.AddASN1BigInt(bbig.Dec(Dp))
		b.AddASN1BigInt(bbig.Dec(Dq))
		b.AddASN1BigInt(bbig.Dec(Qinv))
	})
	return builder.Bytes()
}

func encodePublicKey(N, E BigInt) ([]byte, error) {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(bbig.Dec(N))
		b.AddASN1BigInt(bbig.Dec(E))
	})
	return builder.Bytes()
}

func GenerateKey(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	data, err := xcrypto.GenerateKeyRSA(bits)
	if err != nil {
		return
	}
	return decodeKey(data)
}

func NewPrivateKey(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKey, error) {
	encoded, err := encodeKey(N, E, D, P, Q, Dp, Dq, Qinv)
	if err != nil {
		return nil, err
	}
	return xcrypto.NewPrivateKeyRSA(encoded)
}

func NewPublicKey(N, E BigInt) (*PublicKey, error) {
	encoded, err := encodePublicKey(N, E)
	if err != nil {
		return nil, err
	}
	return xcrypto.NewPublicKeyRSA(encoded)
}

func EncryptOAEP(h, mgfHash hash.Hash, pub *PublicKey, msg, label []byte) ([]byte, error) {
	return xcrypto.EncryptRSAOAEP(h, pub, msg, label)
}

func DecryptOAEP(h, mgfHash hash.Hash, priv *PrivateKey, ciphertext, label []byte) ([]byte, error) {
	return xcrypto.DecryptRSAOAEP(h, priv, ciphertext, label)
}

func EncryptPKCS1v15(pub *PublicKey, msg []byte) ([]byte, error) {
	return xcrypto.EncryptRSAPKCS1(pub, msg)
}
func DecryptPKCS1v15(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return xcrypto.DecryptRSAPKCS1(priv, ciphertext)
}
func EncryptNoPadding(pub *PublicKey, msg []byte) ([]byte, error) {
	return xcrypto.EncryptRSANoPadding(pub, msg)
}
func DecryptNoPadding(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return xcrypto.DecryptRSANoPadding(priv, ciphertext)
}
func SignPKCS1v15(priv *PrivateKey, h crypto.Hash, hashed []byte) ([]byte, error) {
	return xcrypto.SignRSAPKCS1v15(priv, h, hashed)
}
func VerifyPKCS1v15(pub *PublicKey, h crypto.Hash, hashed, sig []byte) error {
	return xcrypto.VerifyRSAPKCS1v15(pub, h, hashed, sig)
}
func SignPSS(priv *PrivateKey, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	return xcrypto.SignRSAPSS(priv, h, hashed, saltLen)
}
func VerifyPSS(pub *PublicKey, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	return xcrypto.VerifyRSAPSS(pub, h, hashed, sig, saltLen)
}
