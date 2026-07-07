// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// CryptoPackage describes a Go crypto package referenced by the generated
// documents.
type CryptoPackage struct {
	// ImportPath is the Go import path of the package, e.g. "crypto/aes".
	ImportPath string
	// InUserGuide indicates whether the package has a dedicated section in the
	// FIPS User Guide. When true, the package's section is generated from its
	// entry in userGuideContent (userguide_content.go). The order of the User
	// Guide sections follows the order of the InUserGuide entries in
	// cryptoPackages.
	InUserGuide bool
}

// cryptoPackages is the shared source of truth for the set of Go crypto
// packages referenced by the generated documents. Both
// CrossPlatformCryptography.md and fips/UserGuide.md derive their package links
// from this list, and the generator validates that every package they reference
// is registered here so the two documents cannot drift apart.
//
// The InUserGuide entries appear first, in the order they should be rendered in
// the User Guide. Packages that only appear in CrossPlatformCryptography.md
// (typically newer APIs that the manually-maintained User Guide has not
// documented yet) follow.
var cryptoPackages = []CryptoPackage{
	// User Guide packages, in User Guide order.
	{ImportPath: "crypto/aes", InUserGuide: true},
	{ImportPath: "crypto/cipher", InUserGuide: true},
	{ImportPath: "crypto/des", InUserGuide: true},
	{ImportPath: "crypto/dsa", InUserGuide: true},
	{ImportPath: "crypto/ecdh", InUserGuide: true},
	{ImportPath: "crypto/ecdsa", InUserGuide: true},
	{ImportPath: "crypto/ed25519", InUserGuide: true},
	{ImportPath: "crypto/elliptic", InUserGuide: true},
	{ImportPath: "crypto/hkdf", InUserGuide: true},
	{ImportPath: "crypto/hmac", InUserGuide: true},
	{ImportPath: "crypto/md5", InUserGuide: true},
	{ImportPath: "crypto/mldsa", InUserGuide: true},
	{ImportPath: "crypto/mlkem", InUserGuide: true},
	{ImportPath: "crypto/pbkdf2", InUserGuide: true},
	{ImportPath: "crypto/rand", InUserGuide: true},
	{ImportPath: "crypto/rc4", InUserGuide: true},
	{ImportPath: "crypto/sha1", InUserGuide: true},
	{ImportPath: "crypto/sha256", InUserGuide: true},
	{ImportPath: "crypto/sha3", InUserGuide: true},
	{ImportPath: "crypto/sha512", InUserGuide: true},
	{ImportPath: "crypto/rsa", InUserGuide: true},
	{ImportPath: "crypto/subtle", InUserGuide: true},
	{ImportPath: "crypto/tls", InUserGuide: true},

	// Packages referenced only by CrossPlatformCryptography.md.
	{ImportPath: "crypto/hpke"},
}

// packagesByImportPath indexes cryptoPackages by import path.
var packagesByImportPath = func() map[string]CryptoPackage {
	m := make(map[string]CryptoPackage, len(cryptoPackages))
	for _, p := range cryptoPackages {
		m[p.ImportPath] = p
	}
	return m
}()

// isRegisteredPackage reports whether importPath is a package registered in the
// shared source of truth.
func isRegisteredPackage(importPath string) bool {
	_, ok := packagesByImportPath[importPath]
	return ok
}

// packageLink returns the Markdown link to the pkg.go.dev documentation for the
// given package.
func packageLink(importPath string) string {
	return "https://pkg.go.dev/" + importPath
}

// userGuidePackages returns the registered packages that have a section in the
// User Guide, in the order they should be rendered.
func userGuidePackages() []CryptoPackage {
	var out []CryptoPackage
	for _, p := range cryptoPackages {
		if p.InUserGuide {
			out = append(out, p)
		}
	}
	return out
}
