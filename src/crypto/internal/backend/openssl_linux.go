// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android && !no_openssl && !cmd_go_bootstrap && !msan
// +build linux,!android,!no_openssl,!cmd_go_bootstrap,!msan

// Package openssl provides access to OpenSSLCrypto implementation functions.
// Check the variable Enabled to find out whether OpenSSLCrypto is available.
// If OpenSSLCrypto is not available, the functions in this package all panic.
package backend

import (
	"crypto/internal/boring/sig"
	"syscall"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

// Enabled controls whether FIPS crypto is enabled.
var Enabled = false

func init() {
	if !needFIPS() {
		return
	}
	err := openssl.Init()
	if err != nil {
		panic(err)
	}

	if !openssl.FIPS() {
		if err = openssl.SetFIPS(true); err != nil {
			panic(err)
		}
	}

	Enabled = true
	sig.BoringCrypto()
}

func needFIPS() bool {
	if envFips, ok := syscall.Getenv("GOFIPS"); ok {
		return envFips != "0"
	}
	// TODO: Remove GOLANG_FIPS once our CI uses GOFIPS.
	if envFips, ok := syscall.Getenv("GOLANG_FIPS"); ok {
		return envFips != "0"
	}
	var fd int
	for {
		var err error
		fd, err = syscall.Open("/proc/sys/crypto/fips_enabled", syscall.O_RDONLY, 0)
		if err == nil {
			break
		}
		switch err {
		case syscall.EINTR:
			continue
		case syscall.ENOENT:
			return false
		default:
			// If there is an error reading we could either panic or assume FIPS is not enabled.
			// Panicking would be too disruptive for apps that don't require FIPS.
			// If an app wants to be 100% sure that is running in FIPS mode
			// it should use boring.Enabled() or GOFIPS=1.
			return false
		}
	}
	defer syscall.Close(fd)
	var tmp [1]byte
	syscall.Read(fd, tmp[:])
	// fips_enabled can be either '0' or '1'.
	return tmp[0] != '0'
}

// Unreachable marks code that should be unreachable
// when OpenSSLCrypto is in use. It panics only when
// the system is in FIPS mode.
func Unreachable() {
	if Enabled {
		panic("opensslcrypto: invalid code execution")
	}
}

// provided by runtime to avoid os import
func runtime_arg0() string

func hasSuffix(s, t string) bool {
	return len(s) > len(t) && s[len(s)-len(t):] == t
}

// UnreachableExceptTests marks code that should be unreachable
// when OpenSSLCrypto is in use. It panics.
func UnreachableExceptTests() {
	name := runtime_arg0()
	// If OpenSSLCrypto ran on Windows we'd need to allow _test.exe and .test.exe as well.
	if Enabled && !hasSuffix(name, "_test") && !hasSuffix(name, ".test") {
		println("opensslcrypto: unexpected code execution in", name)
		panic("opensslcrypto: invalid code execution")
	}
}

const RandReader = openssl.RandReader

var NewSHA1 = openssl.NewSHA1
var NewSHA224 = openssl.NewSHA224
var NewSHA256 = openssl.NewSHA256
var NewSHA384 = openssl.NewSHA384
var NewSHA512 = openssl.NewSHA512

var NewHMAC = openssl.NewHMAC

var NewAESCipher = openssl.NewAESCipher

type PublicKeyECDSA = openssl.PublicKeyECDSA
type PrivateKeyECDSA = openssl.PrivateKeyECDSA

var GenerateKeyECDSA = openssl.GenerateKeyECDSA
var NewPrivateKeyECDSA = openssl.NewPrivateKeyECDSA
var NewPublicKeyECDSA = openssl.NewPublicKeyECDSA
var SignECDSA = openssl.SignECDSA
var SignMarshalECDSA = openssl.SignMarshalECDSA
var VerifyECDSA = openssl.VerifyECDSA

type PublicKeyRSA = openssl.PublicKeyRSA
type PrivateKeyRSA = openssl.PrivateKeyRSA

var DecryptRSAOAEP = openssl.DecryptRSAOAEP
var DecryptRSAPKCS1 = openssl.DecryptRSAPKCS1
var DecryptRSANoPadding = openssl.DecryptRSANoPadding
var EncryptRSAOAEP = openssl.EncryptRSAOAEP
var EncryptRSAPKCS1 = openssl.EncryptRSAPKCS1
var EncryptRSANoPadding = openssl.EncryptRSANoPadding
var GenerateKeyRSA = openssl.GenerateKeyRSA
var NewPrivateKeyRSA = openssl.NewPrivateKeyRSA
var NewPublicKeyRSA = openssl.NewPublicKeyRSA
var SignRSAPKCS1v15 = openssl.SignRSAPKCS1v15
var SignRSAPSS = openssl.SignRSAPSS
var VerifyRSAPKCS1v15 = openssl.VerifyRSAPKCS1v15
var VerifyRSAPSS = openssl.VerifyRSAPSS
