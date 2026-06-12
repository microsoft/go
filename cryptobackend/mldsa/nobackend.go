// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package mldsa

type Parameters struct{}
type PrivateKey struct{}
type PublicKey struct{}

func MLDSA44() Parameters                                { panic("cryptobackend: not available") }
func MLDSA65() Parameters                                { panic("cryptobackend: not available") }
func MLDSA87() Parameters                                { panic("cryptobackend: not available") }
func (params Parameters) String() string                 { panic("cryptobackend: not available") }
func Supports(params Parameters) bool                    { panic("cryptobackend: not available") }
func SupportsExternalMu() bool                           { panic("cryptobackend: not available") }
func GenerateKey(params Parameters) (*PrivateKey, error) { panic("cryptobackend: not available") }
func NewPrivateKey(params Parameters, seed []byte) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}
func NewPublicKey(params Parameters, publicKey []byte) (*PublicKey, error) {
	panic("cryptobackend: not available")
}
func (key *PrivateKey) Bytes() []byte                { panic("cryptobackend: not available") }
func (key *PrivateKey) Equal(other *PrivateKey) bool { panic("cryptobackend: not available") }
func (key *PrivateKey) Parameters() Parameters       { panic("cryptobackend: not available") }
func (key *PrivateKey) PublicKey() *PublicKey        { panic("cryptobackend: not available") }
func (key *PrivateKey) Sign(message []byte, context string) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (key *PrivateKey) SignExternalMu(mu []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (key *PublicKey) Bytes() []byte               { panic("cryptobackend: not available") }
func (key *PublicKey) Equal(other *PublicKey) bool { panic("cryptobackend: not available") }
func (key *PublicKey) Parameters() Parameters      { panic("cryptobackend: not available") }
func (key *PublicKey) Verify(message, signature []byte, context string) error {
	panic("cryptobackend: not available")
}
func (key *PublicKey) VerifyExternalMu(mu, signature []byte) error {
	panic("cryptobackend: not available")
}
