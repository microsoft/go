// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import "unsafe"

type randReader int

func (randReader) Read(b []byte) (int, error) {
	// Note: RAND_bytes should never fail; the return value exists only for historical reasons.
	// We check it even so.
	if len(b) > 0 && C._goboringcrypto_RAND_bytes((*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))) == 0 {
		return 0, fail("RAND_bytes")
	}
	return len(b), nil
}

const RandReader = randReader(0)
