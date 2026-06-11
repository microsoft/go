// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fips140state

import (
	"testing"
)

// fakeEnv returns a getenv function that serves lookups from m, with the
// same (value, ok) semantics as [syscall.Getenv]. A key present in m with an
// empty string value represents a set-but-empty environment variable.
func fakeEnv(m map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := m[key]
		return v, ok
	}
}

// TestDetect exercises the FIPS 140 detection logic in isolation, without
// depending on process environment variables or the host's kernel FIPS
// configuration. This lets us cover combinations that would otherwise be
// impossible to test on a single machine, such as the kernel FIPS flag
// being set or not set for the same test run.
func TestDetect(t *testing.T) {
	tests := []struct {
		name        string
		godebug     string
		env         map[string]string
		systemFIPS  bool
		wantEnabled bool
		wantMessage string
	}{
		// GODEBUG=fips140 takes precedence over everything else.
		{name: "GODEBUG=on", godebug: "on", wantEnabled: true, wantMessage: "environment variable GODEBUG=fips140=on"},
		{name: "GODEBUG=only", godebug: "only", wantEnabled: true, wantMessage: "environment variable GODEBUG=fips140=only"},
		{name: "GODEBUG=debug", godebug: "debug", wantEnabled: true, wantMessage: "environment variable GODEBUG=fips140=debug"},
		{name: "GODEBUG=on beats GOFIPS=0 and kernel FIPS", godebug: "on", env: map[string]string{"GOFIPS": "0"}, systemFIPS: true, wantEnabled: true, wantMessage: "environment variable GODEBUG=fips140=on"},
		{name: "GODEBUG=off beats kernel FIPS", godebug: "off", systemFIPS: true, wantEnabled: false, wantMessage: "environment variable GODEBUG=fips140=off"},
		{name: "GODEBUG=off beats GOFIPS=1", godebug: "off", env: map[string]string{"GOFIPS": "1"}, wantEnabled: false, wantMessage: "environment variable GODEBUG=fips140=off"},

		// GOFIPS=1 enables FIPS when GODEBUG is unset/empty/unrecognized.
		{name: "GOFIPS=1", env: map[string]string{"GOFIPS": "1"}, wantEnabled: true, wantMessage: "environment variable GOFIPS=1"},
		{name: "GOFIPS=1 beats kernel FIPS off", env: map[string]string{"GOFIPS": "1"}, systemFIPS: false, wantEnabled: true, wantMessage: "environment variable GOFIPS=1"},
		{name: "GODEBUG unrecognized, GOFIPS=1", godebug: "bogus", env: map[string]string{"GOFIPS": "1"}, wantEnabled: true, wantMessage: "environment variable GOFIPS=1"},

		// Non-"1" values of GOFIPS are ignored and fall through.
		{name: "GOFIPS=0 falls through to kernel FIPS on", env: map[string]string{"GOFIPS": "0"}, systemFIPS: true, wantEnabled: true, wantMessage: "system FIPS mode"},
		{name: "GOFIPS=0 falls through to kernel FIPS off", env: map[string]string{"GOFIPS": "0"}, systemFIPS: false, wantEnabled: false, wantMessage: ""},
		{name: "GOFIPS empty falls through to kernel FIPS on", env: map[string]string{"GOFIPS": ""}, systemFIPS: true, wantEnabled: true, wantMessage: "system FIPS mode"},
		{name: "GOFIPS=garbage falls through", env: map[string]string{"GOFIPS": "garbage"}, systemFIPS: false, wantEnabled: false, wantMessage: ""},

		// GOLANG_FIPS behaves the same as GOFIPS.
		{name: "GOLANG_FIPS=1", env: map[string]string{"GOLANG_FIPS": "1"}, wantEnabled: true, wantMessage: "environment variable GOLANG_FIPS=1"},
		{name: "GOFIPS=1 beats GOLANG_FIPS=0", env: map[string]string{"GOFIPS": "1", "GOLANG_FIPS": "0"}, wantEnabled: true, wantMessage: "environment variable GOFIPS=1"},
		{name: "GOLANG_FIPS=0 falls through to kernel FIPS on", env: map[string]string{"GOLANG_FIPS": "0"}, systemFIPS: true, wantEnabled: true, wantMessage: "system FIPS mode"},

		// With nothing set, the kernel FIPS flag controls the result.
		{name: "nothing set, kernel FIPS on", systemFIPS: true, wantEnabled: true, wantMessage: "system FIPS mode"},
		{name: "nothing set, kernel FIPS off", systemFIPS: false, wantEnabled: false, wantMessage: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			systemFIPS := func() bool { return tc.systemFIPS }
			gotEnabled, gotMessage := detect(tc.godebug, fakeEnv(tc.env), systemFIPS)
			if gotEnabled != tc.wantEnabled || gotMessage != tc.wantMessage {
				t.Errorf("detect(godebug=%q, env=%v, systemFIPS=%v) = (%v, %q), want (%v, %q)",
					tc.godebug, tc.env, tc.systemFIPS,
					gotEnabled, gotMessage, tc.wantEnabled, tc.wantMessage)
			}
		})
	}
}
