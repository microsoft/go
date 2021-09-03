// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
)

func main() {
	// The caller may have run 'eng/run.ps1 build' by mistake. They might not realize the
	// microsoft/go and microsoft/go-docker infrastructure works differently. Print a message to
	// make it obvious what they need to do next to get a build going.
	fmt.Println("----------")
	fmt.Println("'eng/run.ps1' is for utilities, not for building the Docker images: the build process isn't implemented in Go.")
	fmt.Println("Use 'eng/build.ps1' instead.")
}
