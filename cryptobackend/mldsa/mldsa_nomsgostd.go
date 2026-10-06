// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (!msgostd && !cmd_go_bootstrap) || fips140v1.0

package mldsa

// The v1.0 Go module has no ML-DSA implementation. Standalone builds and source
// importers also need declarations that do not import standard-library internals.
type fipsPrivateKey struct{}
type fipsPublicKey struct{}

func (*fipsPrivateKey) Bytes() []byte              { panic("cryptobackend: not available") }
func (*fipsPrivateKey) PublicKey() *fipsPublicKey  { panic("cryptobackend: not available") }
func (*fipsPrivateKey) Equal(*fipsPrivateKey) bool { panic("cryptobackend: not available") }
func (*fipsPublicKey) Bytes() []byte               { panic("cryptobackend: not available") }
func (*fipsPublicKey) Parameters() string          { panic("cryptobackend: not available") }
func (*fipsPublicKey) Equal(*fipsPublicKey) bool   { panic("cryptobackend: not available") }

func GenerateKey44() (*PrivateKey, error)         { panic("cryptobackend: not available") }
func GenerateKey65() (*PrivateKey, error)         { panic("cryptobackend: not available") }
func GenerateKey87() (*PrivateKey, error)         { panic("cryptobackend: not available") }
func NewPrivateKey44([]byte) (*PrivateKey, error) { panic("cryptobackend: not available") }
func NewPrivateKey65([]byte) (*PrivateKey, error) { panic("cryptobackend: not available") }
func NewPrivateKey87([]byte) (*PrivateKey, error) { panic("cryptobackend: not available") }
func NewPublicKey44([]byte) (*PublicKey, error)   { panic("cryptobackend: not available") }
func NewPublicKey65([]byte) (*PublicKey, error)   { panic("cryptobackend: not available") }
func NewPublicKey87([]byte) (*PublicKey, error)   { panic("cryptobackend: not available") }

func newGoPrivateKey(string, []byte) (*fipsPrivateKey, error) {
	panic("cryptobackend: not available")
}
func Sign(*PrivateKey, []byte, string) ([]byte, error) {
	panic("cryptobackend: not available")
}
func SignExternalMu(*PrivateKey, []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func SignDeterministic(*PrivateKey, []byte, string) ([]byte, error) {
	panic("cryptobackend: not available")
}
func SignExternalMuDeterministic(*PrivateKey, []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func Verify(*PublicKey, []byte, []byte, string) error {
	panic("cryptobackend: not available")
}
