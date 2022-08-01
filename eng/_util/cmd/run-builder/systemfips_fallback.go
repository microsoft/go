// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !windows
// +build !windows

package main

import "log"

// enableSystemWideFIPS fallback is a no-op because the current platform either doesn't support or
// doesn't require system-wide FIPS to be enabled to run tests.
func enableSystemWideFIPS() (restore func(), err error) {
	log.Println("Using fallback (no-op) for enableSystemWideFIPS. It either isn't supported on this platform or isn't necessary.")
	return nil, nil
}
