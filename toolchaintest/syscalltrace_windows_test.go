// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toolchaintest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyscalltrace(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "tmp.exe")
	trace := filepath.Join(tmp, "trace.csv")
	source := writeFile(t, `
		package main
		import "syscall"
		func main() {
			syscall.CloseHandle(0)
		}
	`)
	execGoTool(t, false, nil, "build", "-o", bin, source)
	cmd := exec.CommandContext(t.Context(), bin)
	cmd.Env = []string{"MS_GO_SYSCALL_TRACE=" + trace}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running test program: %v\n%s", err, out)
	}
	csv, err := os.ReadFile(trace)
	if err != nil {
		t.Fatalf("reading trace file: %v", err)
	}
	if !strings.Contains(string(csv), "KERNEL32.DLL,CloseHandle\n") {
		t.Errorf("trace file does not contain expected syscall")
	}
}
