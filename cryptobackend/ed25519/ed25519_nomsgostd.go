// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package ed25519

// Standalone builds and source importers cannot import standard-library internals.
type fipsPrivateKey struct{}
type fipsPublicKey struct{}

func (*fipsPublicKey) Bytes() []byte { panic("cryptobackend: not available") }

func GenerateKey() (*PrivateKey, error) { panic("cryptobackend: not available") }
func NewPrivateKey([]byte) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}
func NewPrivateKeyFromSeed([]byte) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}
func NewPublicKey([]byte) (*PublicKey, error) { panic("cryptobackend: not available") }
func Sign(*PrivateKey, []byte) []byte         { panic("cryptobackend: not available") }
func SignDeterministic(*PrivateKey, []byte) []byte {
	panic("cryptobackend: not available")
}
func SignPH(*PrivateKey, []byte, string) ([]byte, error) {
	panic("cryptobackend: not available")
}
func SignCtx(*PrivateKey, []byte, string) ([]byte, error) {
	panic("cryptobackend: not available")
}
func Verify(*PublicKey, []byte, []byte) error { panic("cryptobackend: not available") }
func VerifyPH(*PublicKey, []byte, []byte, string) error {
	panic("cryptobackend: not available")
}
func VerifyCtx(*PublicKey, []byte, []byte, string) error {
	panic("cryptobackend: not available")
}
func newGoPrivateKey(*[64]byte) *fipsPrivateKey { panic("cryptobackend: not available") }
func newGoPublicKey(*[32]byte) *fipsPublicKey   { panic("cryptobackend: not available") }
