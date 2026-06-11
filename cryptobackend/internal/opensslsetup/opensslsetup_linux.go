// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

// opensslsetup is a package that initializes the OpenSSL library.
// It doesn't export any symbol, but blank importing it has the
// side effect of initializing the OpenSSL library.
package opensslsetup

import (
	"syscall"

	"github.com/microsoft/go-crypto-openssl/osslsetup"
)

// knownVersions is a list of supported and well-known libcrypto.so suffixes in decreasing version order.
// FreeBSD library version numbering does not directly align to the version of osslsetup.
// Its preferred search order is 11 -> 111.
var knownVersions = [...]string{"3", "1.1", "11", "111"}

const lcryptoPrefix = "libcrypto.so."

func init() {
	lib := library()
	if err := osslsetup.Init(lib); err != nil {
		panic("opensslcrypto: can't initialize OpenSSL " + lib + ": " + err.Error())
	}
}

// library returns the name of the OpenSSL library to use.
// It first checks the environment variable GO_OPENSSL_VERSION_OVERRIDE.
// If that is not set, it searches a well-known list of library names.
// If no library is found, it returns "libcrypto.so".
func library() string {
	if version, _ := syscall.Getenv("GO_OPENSSL_VERSION_OVERRIDE"); version != "" {
		return lcryptoPrefix + version
	}
	if lib := searchKnownLibrary(); lib != "" {
		return lib
	}
	return lcryptoPrefix[:len(lcryptoPrefix)-1] // no version found, try without version suffix
}

// checkVersion is a variable that holds the osslsetup.CheckVersion function.
// It is initialized in the init function to allow overriding in tests.
var checkVersion = osslsetup.CheckVersion

// searchKnownLibrary returns the name of the highest available FIPS-enabled version of OpenSSL
// using the known library suffixes.
// If no FIPS-enabled version is found, it returns the name of the highest available version.
// If no version is found, it returns an empty string.
func searchKnownLibrary() string {
	var lcryptoFallback string
	for _, v := range knownVersions {
		lcryptoCandidate := lcryptoPrefix + v
		if exists, fips := checkVersion(lcryptoCandidate); exists {
			if fips {
				return lcryptoCandidate
			}
			if lcryptoFallback == "" {
				lcryptoFallback = lcryptoCandidate
			}
		}
	}
	return lcryptoFallback
}
