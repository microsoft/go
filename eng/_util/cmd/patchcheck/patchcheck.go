// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/microsoft/go/_util/internal/patchcheck"
)

var description = `
This command checks the patch files in the patches/ directory for common issues.
`

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", description)
	}

	flag.Parse()

	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func run() error {
	issues, err := patchcheck.FindPatchIssues()
	if err != nil {
		return err
	}
	if len(issues) == 0 {
		fmt.Println("Patches are happy!")
		return nil
	}
	for _, issue := range issues {
		fmt.Printf("%s: %s\n", issue.PatchFile, issue.Message)
	}
	return fmt.Errorf("found %d patch issue(s)", len(issues))
}
