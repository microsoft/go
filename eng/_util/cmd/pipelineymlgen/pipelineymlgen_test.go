// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestGoInfraPipelineGenReproducible(t *testing.T) {
	cmd := exec.Command("go", "run", "github.com/microsoft/go-infra/cmd/pipelineymlgen", "-exit-code", "-r", "../../../../eng/pipeline")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pipelineymlgen reproduciblility check failed: %v\nOutput:\n%s\nRun 'pwsh eng/run.ps1 pipelineymlgen' if differences are expected.", err, out)
	}
}

func TestAzureLinux4Coverage(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("../../../../eng/pipeline", path))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	var azureLinux3, azureLinux4 []string
	for line := range strings.SplitSeq(read("stages/go-builder-matrix-stages.yml"), "\n") {
		if strings.Contains(line, "distro: azurelinux3") {
			azureLinux3 = append(azureLinux3, strings.ReplaceAll(strings.TrimSpace(line), "azurelinux3", "azurelinux4"))
		}
		if strings.Contains(line, "distro: azurelinux4") {
			azureLinux4 = append(azureLinux4, strings.TrimSpace(line))
		}
	}
	if len(azureLinux4) != 5 || !slices.Equal(azureLinux3, azureLinux4) {
		t.Fatalf("Azure Linux 4 jobs must match all five Azure Linux 3 configurations:\nwant %v\ngot %v", azureLinux3, azureLinux4)
	}

	routing := read("stages/run-stage.yml")
	if !strings.Contains(routing, "${{ elseif eq(parameters.builder.distro, 'azurelinux4') }}:\n                container: azurelinux4") {
		t.Fatal("Azure Linux 4 jobs must select the azurelinux4 container")
	}

	const image = "mcr.microsoft.com/microsoft-go/infra-images:azurelinux-4.0-amd64-default"
	for _, path := range []string{
		"data/containers.yml",
		"pr-pipeline.yml",
		"pr-outerloop-pipeline.yml",
		"rolling-innerloop-pipeline.yml",
		"rolling-pipeline.yml",
	} {
		t.Run(path, func(t *testing.T) {
			data := read(path)
			if strings.Count(data, "image: "+image) != 1 {
				t.Fatal("expected exactly one Azure Linux 4 amd64 image resource")
			}
			if !strings.Contains(data, "azurelinux4:") && !strings.Contains(data, "container: azurelinux4") {
				t.Fatal("missing azurelinux4 container resource")
			}
		})
	}
}
