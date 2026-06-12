// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package ed25519

type PrivateKey struct{}
type PublicKey struct{}

func (k PrivateKey) Bytes() ([]byte, error) { panic("cryptobackend: not available") }
func (k PublicKey) Bytes() ([]byte, error)  { panic("cryptobackend: not available") }

func Supports() bool                                        { return false }
func GenerateKey() (PrivateKey, error)                      { panic("cryptobackend: not available") }
func NewPrivateKey(priv []byte) (PrivateKey, error)         { panic("cryptobackend: not available") }
func NewPublicKey(pub []byte) (PublicKey, error)            { panic("cryptobackend: not available") }
func NewPrivateKeyFromSeed(seed []byte) (PrivateKey, error) { panic("cryptobackend: not available") }
func Sign(priv PrivateKey, message []byte) ([]byte, error)  { panic("cryptobackend: not available") }
func Verify(pub PublicKey, message, sig []byte) error       { panic("cryptobackend: not available") }
