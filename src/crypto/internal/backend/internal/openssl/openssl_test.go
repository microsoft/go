// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android
// +build linux,!android

package openssl

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	err := Init()
	if err != nil {
		fmt.Println("skipping on linux platform without OpenSSL")
		os.Exit(0)
	}
	_ = SetFIPS(true) // Skip the error as we still want to run the tests on machines without FIPS support.
	os.Exit(m.Run())
}
