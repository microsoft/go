// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/microsoft/go/_core/patch"
	"github.com/microsoft/go/_core/submodule"
)

const description = `
This command refreshes the Go submodule: initializes it, resets the content, and
applies patches to the stage by default, or optionally as commits.
`

var commits = flag.Bool("commits", false, "Apply the patches as commits.")
var skipPatch = flag.Bool("skip-patch", false, "Skip applying patches.")
var internal = flag.Bool("internal", false, "Use the .gitmodules urlInternal instead of url to clone submodules.")
var shallow = flag.Bool("shallow", false, "Clone the submodule with depth 1.")
var fetchBearerToken = flag.String("fetch-bearer-token", "", "Use this bearer token to fetch the submodule repository.")

func main() {
	repoRootDir, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	var help = flag.Bool("h", false, "Print this help message.")

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
	if err := submodule.Init(rootDir, *internal, *fetchBearerToken, *shallow); err != nil {
		return err
	}

	if err := submodule.Reset(rootDir); err != nil {
		return err
	}

	if *skipPatch {
		return nil
	}

	mode := patch.ApplyModeIndex
	if *commits {
		mode = patch.ApplyModeCommits
	}

	if err := patch.Apply(rootDir, mode); err != nil {
		return err
	}
	return nil
}
