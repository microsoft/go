// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha1

import (
	"crypto/fips140"
	"errors"
	"hash"
)

const fipsOnlyError = "crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode"

// Hash wraps a native SHA-1 hash. Use [New] to initialize it.
type Hash struct {
	*backendHash
}

func (h *Hash) Write(p []byte) (int, error) {
	if fips140.Enforced() {
		return 0, errors.New(fipsOnlyError)
	}
	return h.backendHash.Write(p)
}

func (h *Hash) WriteString(s string) (int, error) {
	if fips140.Enforced() {
		return 0, errors.New(fipsOnlyError)
	}
	return h.backendHash.WriteString(s)
}

func (h *Hash) WriteByte(b byte) error {
	if fips140.Enforced() {
		return errors.New(fipsOnlyError)
	}
	return h.backendHash.WriteByte(b)
}

func (h *Hash) Sum(b []byte) []byte {
	if fips140.Enforced() {
		panic(fipsOnlyError)
	}
	return h.backendHash.Sum(b)
}

// ConstantTimeSum returns the same digest as [Hash.Sum]. It is provided for
// compatibility with crypto/tls; native finalization is not constant-time
// with respect to the input length.
func (h *Hash) ConstantTimeSum(b []byte) []byte {
	return h.Sum(b)
}

func (h *Hash) Clone() (hash.Cloner, error) {
	cloned, err := h.backendHash.Clone()
	if err != nil {
		return nil, err
	}
	return &Hash{cloned.(*backendHash)}, nil
}

// Unwrap returns the native hash implementation unless FIPS 140-only mode is
// enforced, in which case it returns h to preserve the policy checks.
func Unwrap(h *Hash) hash.Hash {
	if fips140.Enforced() {
		return h
	}
	return h.backendHash
}
