// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package backend

import (
	"hash"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go-crypto-openssl/osslsetup"
)

// Enabled controls whether FIPS crypto is enabled.
const Enabled = true

func fipsApprovedHash(h hash.Hash) bool { return openssl.FIPSApprovedHash(h) }

func init() {
	// Some distributions, e.g. Azure Linux 3, don't set the `fips=yes` property when running in FIPS mode,
	// but they configure OpenSSL to use a FIPS-compliant provider (in the case of Azure Linux 3, the SCOSSL provider).
	// In these cases, openssl.FIPS would return `false` and openssl.FIPSCapable would return `true`.
	// We don't care about the `fips=yes` property as long as the provider is FIPS-compliant, so use
	// osslsetup.FIPSCapable to determine whether FIPS mode is enabled.
	if err := checkFIPS(func() bool { return osslsetup.FIPSCapable() }); err != nil {
		// This path can be reached for the following reasons:
		// - In OpenSSL 1, the active engine doesn't support FIPS mode.
		// - In OpenSSL 1, the active engine supports FIPS mode, but it is not enabled.
		// - In OpenSSL 3, the provider used by default doesn't match the `fips=yes` query.
		panic("opensslcrypto: " + err.Error() + ": " + osslsetup.VersionText())
	}
}
