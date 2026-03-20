// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/microsoft/go-infra/patch"
	"github.com/microsoft/go-infra/submodule"
)

const description = `
This command refreshes the Go submodule: initializes it, resets the content, and
applies patches to the stage by default, or optionally as commits.
`

var (
	commits          = flag.Bool("commits", false, "Apply the patches as commits.")
	skipPatch        = flag.Bool("skip-patch", false, "Skip applying patches.")
	take             = flag.Int("take", -1, "Only apply the first N patches. -1 means apply all.")
	origin           = flag.String("origin", "", "Use this origin instead of the default defined in '.gitmodules' to fetch the repository.")
	shallow          = flag.Bool("shallow", false, "Clone the submodule with depth 1.")
	fetchBearerToken = flag.String("fetch-bearer-token", "", "Use this bearer token to fetch the submodule repository.")
)

func main() {
	repoRootDir, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	help := flag.Bool("h", false, "Print this help message.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", description)
	}

	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

	if err := refresh(repoRootDir); err != nil {
		panic(err)
	}
}

func refresh(rootDir string) error {
	if err := submodule.Init(rootDir, *origin, *fetchBearerToken, *shallow); err != nil {
		return err
	}

	config, err := patch.FindAncestorConfig(rootDir)
	if err != nil {
		return err
	}

	if err := submodule.Reset(rootDir, filepath.Join(config.RootDir, config.SubmoduleDir), true); err != nil {
		return err
	}

	if *skipPatch {
		return nil
	}

	mode := patch.ApplyModeIndex
	if *commits {
		mode = patch.ApplyModeCommits
	}

	if *take >= 0 {
		// The patch API applies all patches in a directory. To apply only the
		// first N, copy them into a temporary directory and point the config there.
		patchesDir := filepath.Join(config.RootDir, config.PatchesDir)
		matches, err := filepath.Glob(filepath.Join(patchesDir, "*.patch"))
		if err != nil {
			return err
		}
		slices.Sort(matches)
		if *take > len(matches) {
			return fmt.Errorf("-take %d exceeds number of patches (%d)", *take, len(matches))
		}
		tmpDir, err := os.MkdirTemp("", "patches-take-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpDir)
		for _, src := range matches[:*take] {
			if err := copyFile(src, filepath.Join(tmpDir, filepath.Base(src))); err != nil {
				return err
			}
		}
		relTmpDir, err := filepath.Rel(config.RootDir, tmpDir)
		if err != nil {
			return err
		}
		config.PatchesDir = relTmpDir
	}

	if err := patch.Apply(config, mode); err != nil {
		return err
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	return errors.Join(copyErr, out.Close())
}
