// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toolchaintest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSyscalltrace_StaticUpToDate(t *testing.T) {
	t.Parallel()

	goroot, _ := execGoTool(t, false, nil, "env", "GOROOT")
	dir := filepath.Join(goroot, "src", "runtime")
	zout := filepath.Join(t.TempDir(), "tmp.go")
	execGoToolInDir(t, dir, false, nil, "run", "syscalltrace_generate_windows.go", "-output", zout, "os_windows", "syscalltrace_windows")
	want, err := os.ReadFile(zout)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "zsyscalltrace_windows.go"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Error("zsyscalltrace_windows.go is out of date. Run go generate in runtime/syscalltrace_windows.go to update it.")
	}
}
