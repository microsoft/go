// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/microsoft/go-docker/eng/_util/buildmodel"
)

const description = `
Example: Update the files in the repo based on a build output manifest:

  pwsh eng/run.ps1 update -manifest /home/me/downloads/assets.json

This command updates the checked-in files in this repository to make the repo
build Docker images that contain a new build of Go.

The 'src/microsoft/versions.json' file is the single source of truth for the
version of Go included in the Go Docker images. This command will optionally
update the versions.json file, then it regenerates other files like
'manifest.json' and the Dockerfiles to conform.`

func main() {
	f := buildmodel.CreateBoundUpdateFlags()

	buildmodel.ParseBoundFlags("update", description)

	if err := buildmodel.RunUpdateHere(f); err != nil {
		panic(err)
	}

	fmt.Println("\nSuccess.")
}
