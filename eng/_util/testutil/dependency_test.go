// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testutil

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const nonMinimalDepsFilename = "nonminimaldeps.go"

func TestMinimalCommandDependencies(t *testing.T) {
	cmdList := combinedOutput(t, exec.Command("go", "list", "../cmd/..."))
	cmdPackages := strings.Fields(cmdList)
	if len(cmdPackages) == 0 {
		t.Fatalf("no commands found")
	}

	stdPackages := combinedOutput(t, exec.Command("go", "list", "std"))
	stdPackageMap := make(map[string]struct{})
	for _, stdPackage := range strings.Fields(stdPackages) {
		stdPackageMap[stdPackage] = struct{}{}
	}

	for _, cmdPackage := range cmdPackages {
		cmdPackage := cmdPackage
		localPackage := strings.TrimPrefix(cmdPackage, "github.com/microsoft/go/_util/")

		t.Run(localPackage, func(t *testing.T) {
			t.Parallel()

			if _, err := os.Stat(filepath.Join("..", localPackage, nonMinimalDepsFilename)); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					// This package should have minimal deps. We need to check.
				} else {
					t.Fatalf("Failed to check whether to expect minimal deps for %q: %v", cmdPackage, err)
				}
			} else {
				t.Logf("Skipping scan of %q (known to have non-minimal deps)", cmdPackage)
				return
			}

			depsString := combinedOutput(t, exec.Command("go", "list", "-f", `{{ join .Deps " " }}`, cmdPackage))

			for _, dep := range strings.Fields(depsString) {
				// Anything in the standard library is ok. Note: this uses the running version of
				// Go, so introducing super new dependencies might seem to succeed locally with a
				// new Go but fail in CI.
				if _, ok := stdPackageMap[dep]; ok {
					continue
				}
				// Allow some packages even in minimal mode.
				if strings.HasPrefix(dep, "github.com/microsoft/go/_util/") ||
					strings.HasPrefix(dep, "github.com/microsoft/go-infra/") ||
					strings.HasPrefix(dep, "golang.org/x/") {

					continue
				}
				t.Errorf("error: depends on %q", dep)
			}
		})
	}
}

func combinedOutput(t *testing.T, c *exec.Cmd) string {
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("error running %v: %v, output:\n%s", c, err, out)
	}
	return string(out)
}
