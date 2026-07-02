// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package fips140state

import (
	_ "github.com/microsoft/go/cryptobackend/internal/opensslsetup"
	"syscall"

	"github.com/microsoft/go-crypto-openssl/osslsetup"
)

// systemFIPSMode reports whether the system is in FIPS mode.
// It first checks the kernel, and if that is not available, it checks the
// OpenSSL library.
func systemFIPSMode() bool {
	if kernelFIPSMode() {
		return true
	}
	return osslsetup.FIPS()
}

// kernelFIPSMode reports whether the kernel is in FIPS mode.
func kernelFIPSMode() bool {
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
			// it should use fips140.Enabled() or GODEBUG=fips140=1.
			return false
		}
	}
	defer syscall.Close(fd)
	var tmp [1]byte
	n, err := syscall.Read(fd, tmp[:])
	if n != 1 || err != nil {
		// We return false instead of panicing for the same reason as before.
		return false
	}
	// fips_enabled can be either '0' or '1'.
	return tmp[0] == '1'
}
