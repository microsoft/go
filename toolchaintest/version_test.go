// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toolchaintest

import (
	"debug/buildinfo"
	"os/exec"
	"strings"
	"testing"
)

func TestMicrosoftVersion(t *testing.T) {
	tt := []struct {
		name       string
		ms_version string
		wantMarker bool
	}{
		{"default", "", false},
		{"0", "0", false},
		{"1", "1", true},
	}
	for _, test := range tt {
		t.Run("ms_version="+test.name, func(t *testing.T) {
			t.Parallel()
			// Check "go version" output.
			cmdVersion, _ := execGoTool(t, false, []string{"GODEBUG=ms_version=" + test.ms_version}, "version")
			if strings.Contains(cmdVersion, "-microsoft") != test.wantMarker {
				t.Errorf("version = %q, want '-microsoft' marker = %v", cmdVersion, test.wantMarker)
			}
		})
	}
}

func TestMicrosoftBuildInfoVersion(t *testing.T) {
	t.Parallel()
	v, msVersion, ok := msReadBuildInfo(t, goToolPath(t))
	if strings.HasSuffix(v, "-microsoft") {
		t.Errorf("buildinfo GoVersion = %q, want no -microsoft suffix", v)
	}
	if !ok {
		t.Errorf("buildinfo doesn't contain microsoft_toolset_version")
	}
	if !strings.Contains(msVersion, "-microsoft") {
		t.Errorf("buildinfo microsoft_toolset_version = %q, want it to contain '-microsoft'", msVersion)
	}
}

func TestMicrosoftEmbedUpstreamVersionLDFlag(t *testing.T) {
	tt := []struct {
		name       string
		ldflag     string
		wantMarker bool
	}{
		{"default", "", false},
		{"upstream", "-ms_upstreamversion=1", false},
		{"ms", "-ms_upstreamversion=0", true},
	}
	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			source := writeFile(t, `
				package main
				func main() {}`)

			out := outPath(t) + ".exe"
			execGoTool(t, false, nil, "build", "-ldflags="+test.ldflag, "-o", out, source)
			v, msVersion, ok := msReadBuildInfo(t, out)
			if strings.Contains(v, "-microsoft") != test.wantMarker {
				t.Errorf("buildinfo GoVersion = %q, want '-microsoft' marker = %v", v, test.wantMarker)
			}
			if !ok {
				t.Errorf("buildinfo doesn't contain microsoft_toolset_version")
			} else if !strings.Contains(msVersion, "-microsoft") {
				t.Errorf("buildinfo microsoft_toolset_version = %q, want it to contain '-microsoft'", msVersion)
			}
		})
	}
}

func TestMicrosoftRuntimeVersion(t *testing.T) {
	tt := []struct {
		name       string
		ms_version string
		wantMarker bool
	}{
		{"default", "", false},
		{"0", "0", false},
		{"1", "1", true},
	}
	for _, test := range tt {
		t.Run("ms_version="+test.name, func(t *testing.T) {
			t.Parallel()
			source := writeFile(t, `
				package main
				import "fmt"
				import "runtime"
				func main() { fmt.Println(runtime.Version())}`)

			out := outPath(t) + ".exe"
			execGoTool(t, false, nil, "build", "-o", out, source)

			cmd := exec.CommandContext(t.Context(), out)
			cmd.Env = []string{"GODEBUG=ms_version=" + test.ms_version}
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("running built program: %v\n%s", err, output)
			}
			runtimeVersion := strings.TrimSpace(string(output))
			if strings.Contains(runtimeVersion, "-microsoft") != test.wantMarker {
				t.Errorf("runtime.Version() = %q, want '-microsoft' marker = %v", runtimeVersion, test.wantMarker)
			}
		})
	}
}

func msReadBuildInfo(t *testing.T, exe string) (mainVersion string, msVersion string, ok bool) {
	t.Helper()

	bi, err := buildinfo.ReadFile(exe)
	if err != nil {
		t.Fatalf("buildinfo.ReadFile(%q): %v", exe, err)
	}
	for _, s := range bi.Settings {
		if s.Key == "microsoft_toolset_version" {
			return bi.GoVersion, s.Value, true
		}
	}
	return bi.GoVersion, "", false
}
