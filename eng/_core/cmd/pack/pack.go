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
This command packs a built Go directory into an archive file and produces a
checksum file for the archive. It filters out the files that aren't necessary.

Pack does not support packing cross-compiled Go directories. Use the "-pack"
argument with the build command for this, instead. The Pack command is intended
to repackage an extracted Go archive that was already in the correct format.
To re-run pack quickly on a cross-compiled build, use "build -skipbuild -pack".
`

func main() {
	repoRootDir, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	goRootDir := filepath.Join(repoRootDir, "go")

	source := flag.String("source", goRootDir, "The path of the Go directory to archive.")
	output := flag.String("o", "", "The path of the archive file to create. Format depends on extension. Default: a GOOS/GOARCH-dependent archive file in 'eng/artifacts/bin'.")

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

	if err := archive.CreateFromBuild(*source, *output); err != nil {
		panic(err)
	}
}
