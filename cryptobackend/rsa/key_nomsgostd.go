// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package rsa

type fipsPublicKey struct{}
type fipsPrivateKey struct{}

func newFallbackPublicKey(N []byte, e int) (*fipsPublicKey, error) {
	panic("cryptobackend: not available")
}

func newFallbackPrivateKey(k *PrivateKey) (*fipsPrivateKey, error) {
	panic("cryptobackend: not available")
}

func (*fipsPrivateKey) Export() (N []byte, e int, d, P, Q, dP, dQ, qInv []byte) {
	panic("cryptobackend: not available")
}
