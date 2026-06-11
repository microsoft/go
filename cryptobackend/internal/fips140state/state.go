// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fips140state

import (
	"errors"
	"runtime"
	"syscall"
)

var enabled bool

// message is a human-readable message about how [Enabled] was set.
var message string

func init() {
	// TODO: Decide which environment variable to use.
	// See https://github.com/microsoft/go/issues/397.
	enabled, message = detect(fips140GODEBUG, syscall.Getenv, systemFIPSMode)
}

func Enabled() bool {
	return enabled
}

func Check(backendEnabled bool, fips func() bool) error {
	if isRequireFIPS {
		if isSkipFIPSCheck {
			panic("the 'requirefips' build tag is enabled, but it conflicts " +
				"with the 'ms_skipfipscheck' build tag")
		}
		message = "requirefips tag set"
		enabled = true
	}
	if isSkipFIPSCheck || !enabled {
		return nil
	}
	if !backendEnabled {
		if runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
			return errors.New("FIPS mode requested (" + message + ") but no crypto backend is supported on " + runtime.GOOS)
		}
		return errors.New("FIPS mode requested (" + message + ") but no supported crypto backend is enabled")
	}
	if !fips() {
		return errors.New("FIPS mode requested (" + message + ") but not available")
	}
	return nil
}

// detect reports whether FIPS 140 mode should be enabled and returns a
// human-readable message describing how the decision was made.
//
// godebug is the value of the fips140 GODEBUG setting. getenv is used to look
// up the GOFIPS and GOLANG_FIPS environment variables and mirrors the
// semantics of [syscall.Getenv]. systemFIPS reports whether the platform
// indicates that FIPS mode should be enabled (e.g. the Linux kernel FIPS flag).
//
// The inputs are taken as parameters, rather than read directly, to make the
// detection logic easy to test without depending on process state.
func detect(godebug string, getenv func(string) (string, bool), systemFIPS func() bool) (enabled bool, message string) {
	switch godebug {
	case "on", "only", "debug":
		return true, "environment variable GODEBUG=fips140=" + godebug
	case "off":
		// GODEBUG=fips140=off explicitly disables FIPS mode and bypasses
		// the platform-specific FIPS detection (e.g. the Linux kernel FIPS flag).
		// This is the only supported way to skip the platform FIPS detection.
		return false, "environment variable GODEBUG=fips140=off"
	}
	// Only "1" is a meaningful value for GOFIPS and GOLANG_FIPS. Any other
	// value (including "0" and the empty string) is treated as if the
	// variable were unset, to match the documented behavior and to avoid
	// silently bypassing the platform FIPS detection due to a typo or
	// accidental setting. To explicitly disable FIPS mode and skip the
	// platform FIPS detection, use GODEBUG=fips140=off.
	if v, ok := getenv("GOFIPS"); ok && v == "1" {
		return true, "environment variable GOFIPS=1"
	}
	if v, ok := getenv("GOLANG_FIPS"); ok && v == "1" {
		return true, "environment variable GOLANG_FIPS=1"
	}
	if systemFIPS() {
		return true, "system FIPS mode"
	}
	return false, ""
}
