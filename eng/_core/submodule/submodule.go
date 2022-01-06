// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package submodule

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Init initializes and updates the submodule, but does not clean it. This func offers more options
// for initialization than Reset. If origin is defined, fetch the submodule from there instead of
// the default defined in '.gitmodules'. If fetchBearerToken is nonempty, use it as a bearer token
// during the fetch. If shallow is true, clone the submodule with depth 1.
func Init(rootDir, origin, fetchBearerToken string, shallow bool) error {
	// Update the submodule commit, and initialize if it hasn't been done already.
	command := []string{"git"}
	if origin != "" {
		command = append(command, "-c", "submodule.go.url="+origin)
	}
	if fetchBearerToken != "" {
		command = append(command, "-c", "http.extraheader=AUTHORIZATION: bearer "+fetchBearerToken)
	}
	command = append(command, "submodule", "update", "--init")
	if shallow {
		command = append(command, "--depth", "1")
	}

	if err := run(rootDir, command...); err != nil {
		return err
	}
	return nil
}

// Reset updates the submodule (with '--init'), resets all changes, and cleans all untracked files.
func Reset(rootDir string) error {
	goDir := filepath.Join(rootDir, "go")

	// Update the submodule commit, and initialize if it hasn't been done already.
	if err := run(rootDir, "git", "submodule", "update", "--init"); err != nil {
		return err
	}

	// Find toplevel directories (Git working tree roots) for the outer repo and what we expect to
	// be the Go submodule. If the toplevel directory is the same for both, make sure not to clean!
	// The submodule likely wasn't set up properly, and cleaning could result in unexpectedly losing
	// work in the outer repo when the command spills over.
	rootToplevel, err := getToplevel(rootDir)
	if err != nil {
		return err
	}
	goToplevel, err := getToplevel(goDir)
	if err != nil {
		return err
	}

	if rootToplevel == goToplevel {
		return fmt.Errorf("go submodule (%v) toplevel is the same as root (%v) toplevel: %v", goDir, rootDir, goToplevel)
	}

	// Reset the index and working directory. This doesn't clean up new untracked files.
	if err := run(goDir, "git", "reset", "--hard"); err != nil {
		return err
	}
	// Delete untracked files detected by Git. Deliberately leave files that are ignored in
	// '.gitignore': these files shouldn't interfere with the build process and could be used for
	// incremental builds.
	if err := run(goDir, "git", "clean", "-df"); err != nil {
		return err
	}
	return nil
}

func getToplevel(dir string) (string, error) {
	c := exec.Command("git", "rev-parse", "--show-toplevel")
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func run(dir string, args ...string) error {
	c := exec.Command(args[0], args[1:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Dir = dir
	return runCmd(c)
}

func runCmd(cmd *exec.Cmd) error {
	fmt.Printf("---- Running command: %v\n", cmd.Args)
	return cmd.Run()
}
