// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package mldsa

type Parameters struct{}
type backendPrivateKey struct{}
type backendPublicKey struct{}

func MLDSA44() Parameters                { panic("cryptobackend: not available") }
func MLDSA65() Parameters                { panic("cryptobackend: not available") }
func MLDSA87() Parameters                { panic("cryptobackend: not available") }
func (params Parameters) String() string { panic("cryptobackend: not available") }
func Supports(params Parameters) bool    { panic("cryptobackend: not available") }
func supportsExternalMu() bool           { panic("cryptobackend: not available") }
func generateKey(params Parameters) (*backendPrivateKey, error) {
	panic("cryptobackend: not available")
}
func newPrivateKey(params Parameters, seed []byte) (*backendPrivateKey, error) {
	panic("cryptobackend: not available")
}
func newPublicKey(params Parameters, publicKey []byte) (*backendPublicKey, error) {
	panic("cryptobackend: not available")
}
func (key *backendPrivateKey) Bytes() []byte { panic("cryptobackend: not available") }
func (key *backendPrivateKey) Equal(other *backendPrivateKey) bool {
	panic("cryptobackend: not available")
}
func (key *backendPrivateKey) Parameters() Parameters { panic("cryptobackend: not available") }
func (key *backendPrivateKey) PublicKey() *backendPublicKey {
	panic("cryptobackend: not available")
}
func (key *backendPrivateKey) Sign(message []byte, context string) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (key *backendPrivateKey) SignExternalMu(mu []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (key *backendPublicKey) Bytes() []byte { panic("cryptobackend: not available") }
func (key *backendPublicKey) Equal(other *backendPublicKey) bool {
	panic("cryptobackend: not available")
}
func (key *backendPublicKey) Parameters() Parameters { panic("cryptobackend: not available") }
func (key *backendPublicKey) Verify(message, signature []byte, context string) error {
	panic("cryptobackend: not available")
}
func (key *backendPublicKey) VerifyExternalMu(mu, signature []byte) error {
	panic("cryptobackend: not available")
}
