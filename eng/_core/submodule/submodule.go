// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package submodule

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/microsoft/go-infra/executil"
	"github.com/microsoft/go-infra/xcryptofork"
)

// Init initializes and updates the submodule, but does not clean it. This func offers more options
// for initialization than Reset. If origin is defined, fetch the submodule from there instead of
// the default defined in '.gitmodules'. If fetchBearerToken is nonempty, use it as a bearer token
// during the fetch. If shallow is true, clone the submodule with depth 1.
func Init(rootDir string, internal bool, fetchBearerToken string, shallow bool) error {
	// Update the submodule commit, and initialize if it hasn't been done already.
	command := []string{"git"}
	if internal {
		var err error
		command, err = appendURLInternalGitConfigArgs(rootDir, command)
		if err != nil {
			return err
		}
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

	if err := assertSubmoduleInitialized(rootDir, goDir); err != nil {
		return err
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

// GenerateMSMod creates the _ms_mod directory with x/crypto fork and generates
// the crypto backend proxies based on the backends currently in the Go
// submodule source tree.
func GenerateMSMod(rootDir string) error {
	cryptoSrcDir := filepath.Join(rootDir, "modules", "golang.org", "x", "crypto")
	if err := assertSubmoduleInitialized(rootDir, cryptoSrcDir); err != nil {
		return err
	}
	goDir := filepath.Join(rootDir, "go")
	if err := assertSubmoduleInitialized(rootDir, goDir); err != nil {
		return err
	}
	// Target directory for the x/crypto fork.
	cryptoDir := filepath.Join(goDir, "_ms_mod", "golang.org", "x", "crypto")
	// Clean it up. No prompt: there shouldn't be any need to do dev work in
	// this directory.
	if err := os.RemoveAll(cryptoDir); err != nil {
		return err
	}
	if err := os.MkdirAll(cryptoDir, 0o777); err != nil {
		return err
	}
	if err := xcryptofork.GitCheckoutTo(cryptoSrcDir, cryptoDir); err != nil {
		return err
	}
	// Generate the backend proxies and the nobackend file based on the backends
	// in the active Go tree. The placeholder in x/crypto is ignored: it's only
	// there so the x/crypto fork will compile outside this context.
	backendDir := filepath.Join(goDir, "src", "crypto", "internal", "backend")
	backends, err := xcryptofork.FindBackendFiles(backendDir)
	if err != nil {
		return fmt.Errorf("failed to find backend files in %q: %v", backendDir, err)
	}
	proxyDir := filepath.Join(cryptoDir, "internal", "backend")
	if err := os.RemoveAll(proxyDir); err != nil {
		return err
	}
	// First, find the nobackend. It defines the API for the backend proxies.
	const nobackendBase = "nobackend.go"
	var backendAPI *xcryptofork.BackendFile
	for _, b := range backends {
		if filepath.Base(b.Filename) == nobackendBase {
			if err := b.APITrim(); err != nil {
				return fmt.Errorf("failed to trim %q into an API for proxies: %v", b.Filename, err)
			}
			// If someone uses the x/crypto fork but doesn't use a backend, they
			// will need this nobackend.go for their build to succeed.
			if err := writeBackend(b, filepath.Join(proxyDir, nobackendBase)); err != nil {
				return fmt.Errorf("failed to write API based on %q: %v", b.Filename, err)
			}
			backendAPI = b
			break
		}
	}
	if backendAPI == nil {
		return fmt.Errorf("%q not found in %v", nobackendBase, backendDir)
	}
	// Create a proxy for each backend.
	for _, b := range backends {
		if b == backendAPI {
			continue
		}
		proxy, err := b.ProxyAPI(backendAPI)
		if err != nil {
			return fmt.Errorf("failed to turn %q into a proxy: %v", b.Filename, err)
		}
		if err := writeBackend(proxy, filepath.Join(proxyDir, filepath.Base(b.Filename))); err != nil {
			return fmt.Errorf("failed to write proxy based on %q: %v", b.Filename, err)
		}
	}
	return nil
}

func RemoveMSMod(rootDir string) error {
	msMod := filepath.Join(rootDir, "go", "_ms_mod")
	entries, err := os.ReadDir(msMod)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if err := os.RemoveAll(filepath.Join(msMod, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func writeBackend(b xcryptofork.FormattedWriterTo, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	apiFile, err := os.Create(path)
	if err != nil {
		return err
	}
	err = b.Format(apiFile)
	if err2 := apiFile.Close(); err == nil {
		err = err2
	}
	return err
}

func appendURLInternalGitConfigArgs(rootDir string, args []string) ([]string, error) {
	cmd := exec.Command(
		"git", "config",
		"-f", ".gitmodules",
		"-z", // Null char separator: avoid confusion with newlines in values.
		"--get-regexp", `submodule\..*\.urlInternal`)
	cmd.Dir = rootDir
	out, err := executil.CombinedOutput(cmd)
	if err != nil {
		return nil, err
	}
	pairs := strings.Split(out, "\x00")
	for _, pair := range pairs {
		key, value, ok := strings.Cut(pair, "\n")
		if !ok {
			return nil, fmt.Errorf("invalid key-value pair: %v", pair)
		}
		args = append(args, "-c", strings.TrimSuffix(key, "Internal")+"="+value)
	}
	return args, nil
}

// assertSubmoduleInitialized runs a basic check to ensure the submodule within
// the specified root repo is initialized. It finds toplevel directories (Git
// working tree roots) for the outer repo and what we expect to be the Go
// submodule. If the toplevel directory is the same for both, the submodule
// likely wasn't set up properly, and (e.g.) cleaning the submodule dir could
// result in unexpectedly losing work in the rootDir when the command spills
// over and affects the outer repo.
//
// There may be other ways to check whether the submodule is initialized, but
// this check at the very least helps at the most painful potential symptom of
// an uninitialized submodule: lost work.
func assertSubmoduleInitialized(rootDir, submoduleRootDir string) error {
	rootToplevel, err := getToplevel(rootDir)
	if err != nil {
		return err
	}
	submoduleToplevel, err := getToplevel(submoduleRootDir)
	if err != nil {
		return err
	}
	if rootToplevel == submoduleToplevel {
		return fmt.Errorf("go submodule (%v) toplevel is the same as root (%v) toplevel: %v", submoduleToplevel, rootDir, submoduleToplevel)
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
