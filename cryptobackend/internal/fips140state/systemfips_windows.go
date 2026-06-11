// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package fips140state

import (
	"syscall"
	"unsafe"
)

// Don't use github.com/microsoft/go-crypto-winnative here.
// The fips140 package should have minimal dependencies.
// Also, don't directly query the system FIPS mode from the registry,
// there are some no-longer documented legacy entries that can enable FIPS mode,
// and BCryptGetFipsAlgorithmMode supports them all.
var (
	bcrypt = syscall.MustLoadDLL("bcrypt.dll")

	bcryptGetFipsAlgorithmMode = bcrypt.MustFindProc("BCryptGetFipsAlgorithmMode")
)

func systemFIPSMode() bool {
	var enabled uint32
	ret, _, _ := bcryptGetFipsAlgorithmMode.Call(uintptr(unsafe.Pointer(&enabled)))
	if ret != 0 {
		return false
	}
	return enabled != 0
}
