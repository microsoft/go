// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !windows
// +build !windows

package main

// enableSystemWideFIPS is a no-op because the current platform either doesn't support or doesn't
// require system-wide FIPS to be enabled to run tests.
func enableSystemWideFIPS() (restore func(), err error) {
	return nil, nil
}
