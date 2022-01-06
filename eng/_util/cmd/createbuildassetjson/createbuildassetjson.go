// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/microsoft/go-infra/buildmodel"
)

const description = `
This command creates a build asset JSON file for a given Go build, where all assets are in a flat
directory on disk. Downstream repos (in particular Go Docker) can use this summary file to point at
new builds of Go automatically.
`

func main() {
	f := buildmodel.BindBuildAssetJSONFlags()

	buildmodel.ParseBoundFlags(description)

	if err := buildmodel.GenerateBuildAssetJSON(f); err != nil {
		panic(err)
	}

	fmt.Println("\nSuccess.")
}
