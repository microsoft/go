// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/microsoft/go/_core/archive"
)

const description = `
This command creates a source archive of the Go submodule at HEAD.
`

func main() {
	output := flag.String("o", "", "The path of the archive file to create, including extension. Default: a tar.gz file including build number in 'eng/artifacts/bin'.")
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

	repoRootDir, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	goRootDir := filepath.Join(repoRootDir, "go")

	if err := archive.CreateFromSource(goRootDir, *output); err != nil {
		panic(err)
	}
}
