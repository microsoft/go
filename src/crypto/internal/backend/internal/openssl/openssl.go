// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package openssl

// #include "goopenssl.h"
// #cgo LDFLAGS: -ldl
import "C"
import (
	"errors"
	"math/big"
	"runtime"
	"strings"
)

func Init() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// We must error out if openssl cannot be correctly setup in FIPS mode
	// in order to avoid applications unintentionally running without FIPS.

	if C._goboringcrypto_DLOPEN_OPENSSL() == C.NULL {
		return errors.New("boringcrypto: OpenSSL dlopen failed")
	}

	if C._goboringcrypto_OPENSSL_setup() != 1 {
		return errors.New("boringcrypto: OpenSSL setup failed")
	}

	if C._goboringcrypto_FIPS_mode() != 1 {
		// openssl FIPS mode can be configured from many places:
		// environment variables, config file, kernel parameters, etc.
		// If we reach this point and FIPS mode is not set, force it or panic.
		if C._goboringcrypto_FIPS_mode_set(1) != 1 {
			return NewOpenSSLError("boringcrypto: not in FIPS mode")
		}
	}
	return nil
}

func NewOpenSSLError(msg string) error {
	var b strings.Builder
	var e C.ulong

	b.WriteString(msg)
	b.WriteString("\nopenssl error(s):\n")

	for {
		e = C._goboringcrypto_ERR_get_error()
		if e == 0 {
			break
		}
		var buf [256]byte
		C._goboringcrypto_ERR_error_string_n(e, base(buf[:]), 256)
		b.Write(buf[:])
		b.WriteByte('\n')
	}
	return errors.New(b.String())
}

type fail string

func (e fail) Error() string { return "boringcrypto: " + string(e) + " failed" }

func bigToBN(x *big.Int) *C.GO_BIGNUM {
	raw := x.Bytes()
	return C._goboringcrypto_BN_bin2bn(base(raw), C.size_t(len(raw)), nil)
}

func bnToBig(bn *C.GO_BIGNUM) *big.Int {
	raw := make([]byte, C._goboringcrypto_BN_num_bytes(bn))
	n := C._goboringcrypto_BN_bn2bin(bn, base(raw))
	return new(big.Int).SetBytes(raw[:n])
}

func bigToBn(bnp **C.GO_BIGNUM, b *big.Int) bool {
	if *bnp != nil {
		C._goboringcrypto_BN_free(*bnp)
		*bnp = nil
	}
	if b == nil {
		return true
	}
	raw := b.Bytes()
	bn := C._goboringcrypto_BN_bin2bn(base(raw), C.size_t(len(raw)), nil)
	if bn == nil {
		return false
	}
	*bnp = bn
	return true
}
