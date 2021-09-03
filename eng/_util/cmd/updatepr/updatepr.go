// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/microsoft/go-docker/eng/_util/buildmodel"
)

const description = `
Example: Create a temporary repo and create a commit that updates the repo to use the build listed
in the asset manifest:

  pwsh eng/run.ps1 updatepr -manifest /home/me/downloads/assets.json

This command runs the 'update' command, then submits a PR on GitHub to the target repository.

It may be useful to specify Git addresses like 'git@github.com:microsoft/go' to
use SSH authentication.

This script creates a temporary copy of the repository in 'eng/artifacts/' by
default. This avoids trampling changes in the user's clone.`

func main() {
	uf := buildmodel.CreateBoundUpdateFlags()
	pf := buildmodel.CreateBoundPRFlags()

	buildmodel.ParseBoundFlags("updatepr", description)

	if err := buildmodel.SubmitUpdatePR(uf, pf); err != nil {
		panic(err)
	}

	fmt.Println("\nSuccess.")
}
