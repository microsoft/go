// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android && !no_openssl && !cmd_go_bootstrap && !msan
// +build linux,!android,!no_openssl,!cmd_go_bootstrap,!msan

package boring

// #include "goboringcrypto.h"
// #cgo LDFLAGS: -ldl
import "C"
import (
	"crypto/internal/boring/sig"
	"errors"
	"math/big"
	"os"
	"runtime"
	"strings"
)

// Enabled controls whether FIPS crypto is enabled.
var enabled = false

// When this variable is true, the go crypto API will panic when a caller
// tries to use the API in a non-compliant manner.  When this is false, the
// go crytpo API will allow existing go crypto APIs to be used even
// if they aren't FIPS compliant.  However, all the underlying crypto operations
// will still be done by OpenSSL.
var strictFIPS = false

func init() {
	if os.Getenv("GOLANG_FIPS") != "1" {
		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if C._goboringcrypto_DLOPEN_OPENSSL() == C.NULL {
		panic("boringcrypto: OpenSSL dlopen failed")
	}

	if C._goboringcrypto_OPENSSL_setup() != 1 {
		panic("boringcrypto: OpenSSL setup failed")
	}

	if C._goboringcrypto_FIPS_mode_set(1) != 1 {
		panic(NewOpenSSLError("boringcrypto: not in FIPS mode"))
	}

	enabled = true
	sig.BoringCrypto()
}

var randstub bool

func RandStubbed() bool {
	return randstub
}

func StubOpenSSLRand() {
	if !randstub {
		randstub = true
		C._goboringcrypto_stub_openssl_rand()
	}
}

func RestoreOpenSSLRand() {
	if randstub {
		randstub = false
		C._goboringcrypto_restore_openssl_rand()
	}
}

// Unreachable marks code that should be unreachable
// when BoringCrypto is in use. It panics only when
// the system is in FIPS mode.
func Unreachable() {
	if Enabled() {
		panic("boringcrypto: invalid code execution")
	}
}

// provided by runtime to avoid os import
func runtime_arg0() string

func hasSuffix(s, t string) bool {
	return len(s) > len(t) && s[len(s)-len(t):] == t
}

// UnreachableExceptTests marks code that should be unreachable
// when BoringCrypto is in use. It panics.
func UnreachableExceptTests() {
	name := runtime_arg0()
	// If BoringCrypto ran on Windows we'd need to allow _test.exe and .test.exe as well.
	if Enabled() && !hasSuffix(name, "_test") && !hasSuffix(name, ".test") {
		println("boringcrypto: unexpected code execution in", name)
		panic("boringcrypto: invalid code execution")
	}
}

func PanicIfStrictFIPS(msg string) {
	if os.Getenv("GOLANG_STRICT_FIPS") == "1" || strictFIPS {
		panic(msg)
	}
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
