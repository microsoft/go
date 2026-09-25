// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package drbg

import "github.com/microsoft/go-crypto-openssl/openssl"

const randReader = openssl.RandReader
