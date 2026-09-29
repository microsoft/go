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
type backendPrivateKey = xcrypto.PrivateKeyRSA
type backendPublicKey = xcrypto.PublicKeyRSA

func supportsPublicKey(bits int) bool { return bits >= 1024 && bits%8 == 0 && bits <= 16384 }
func supportsPrimeSizes(p, q int) bool {
	// Use Go for unbalanced primes, which SecKey can reject at operation time.
	return p == q
}

func supportsSaltLength(sign bool, salt int) bool { return salt == -1 }
func supportsPKCS1v15Encryption() bool            { return true }
func supportsPKCS1v15Signature(h crypto.Hash) bool {
	switch h {
	case crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512, 0:
		return true
	}
	return false
}

func supportsPSSHash(h crypto.Hash) bool {
	// SecKey's RSA algorithms do not include every CryptoKit hash algorithm.
	switch h {
	case crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return xcrypto.SupportsHash(h)
	}
	return false
}

func isNativeHash(h hash.Hash) bool {
	_, ok := h.(*xcrypto.Hash)
	return ok
}

func supportsOAEP(h, mgfHash hash.Hash, label []byte) bool {
	hash, mgf := nativeHashAlgorithm(h), nativeHashAlgorithm(mgfHash)
	return len(label) == 0 && hash != 0 && hash == mgf && supportsPSSHash(hash)
}

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

func generateKey(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	data, err := xcrypto.GenerateKeyRSA(bits)
	if err != nil {
		return
	}
	return decodeKey(data)
}

func newBackendPrivateKey(k *PrivateKey) (*backendPrivateKey, error) {
	dp, dq, qi := intBytes(k.dp), intBytes(k.dq), intBytes(k.qi)
	if dp == nil || dq == nil || qi == nil {
		// SecKey imports require CRT values. Calculate them without modifying
		// the caller's key and retain the Go key for future fallback operations.
		fk, err := k.goKey()
		if err != nil {
			return nil, err
		}
		_, _, _, _, _, dp, dq, qi = fk.Export()
	}
	encoded, err := encodeKey(bbig.Enc(k.pub.n), bbig.Enc(big.NewInt(int64(k.pub.e))), bbig.Enc(k.d),
		bbig.Enc(k.primes[0]), bbig.Enc(k.primes[1]), dp, dq, qi)
	if err != nil {
		return nil, err
	}
	return xcrypto.NewPrivateKeyRSA(encoded)
}

func newBackendPublicKey(N *big.Int, e int) (*backendPublicKey, error) {
	encoded, err := encodePublicKey(bbig.Enc(N), bbig.Enc(big.NewInt(int64(e))))
	if err != nil {
		return nil, err
	}
	return xcrypto.NewPublicKeyRSA(encoded)
}

func encryptOAEP(h, mgfHash hash.Hash, pub *backendPublicKey, msg, label []byte) ([]byte, error) {
	return xcrypto.EncryptRSAOAEP(h, pub, msg, label)
}

func decryptOAEP(h, mgfHash hash.Hash, priv *backendPrivateKey, ciphertext, label []byte) ([]byte, error) {
	return xcrypto.DecryptRSAOAEP(h, priv, ciphertext, label)
}

func encryptNoPadding(pub *backendPublicKey, msg []byte) ([]byte, error) {
	return xcrypto.EncryptRSANoPadding(pub, msg)
}
func decryptNoPadding(priv *backendPrivateKey, ciphertext []byte) ([]byte, error) {
	return xcrypto.DecryptRSANoPadding(priv, ciphertext)
}
func signPKCS1v15(priv *backendPrivateKey, h crypto.Hash, hashed []byte) ([]byte, error) {
	return xcrypto.SignRSAPKCS1v15(priv, h, hashed)
}
func verifyPKCS1v15(pub *backendPublicKey, h crypto.Hash, hashed, sig []byte) error {
	return xcrypto.VerifyRSAPKCS1v15(pub, h, hashed, sig)
}
func signPSS(priv *backendPrivateKey, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	return xcrypto.SignRSAPSS(priv, h, hashed, saltLen)
}
func verifyPSS(pub *backendPublicKey, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	return xcrypto.VerifyRSAPSS(pub, h, hashed, sig, saltLen)
}
