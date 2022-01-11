// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package openssl

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	err := Init()
	if err != nil {
		fmt.Println("skipping on linux platform without OpenSSL or FIPS support")
		os.Exit(0)
	}
	os.Exit(m.Run())
}
