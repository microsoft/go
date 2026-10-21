// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

func TestPipelineArtifactsRetrySafe(t *testing.T) {
	for _, file := range []string{
		"run-stage.yml",
		"sign-stage.yml",
		"internal-publish-stage.yml",
		"public-publish-stages.yml",
	} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../../../eng/pipeline/stages", file))
			if err != nil {
				t.Fatal(err)
			}
			var doc yaml.Node
			if err := yaml.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			var outputs int
			var visit func(*yaml.Node)
			visit = func(node *yaml.Node) {
				if node.Kind == yaml.MappingNode {
					fields := make(map[string]string)
					for i := 0; i < len(node.Content); i += 2 {
						fields[node.Content[i].Value] = node.Content[i+1].Value
					}
					if fields["output"] == "pipelineArtifact" {
						outputs++
						artifact, condition := fields["artifact"], fields["condition"]
						if condition != "succeeded()" {
							if condition != "always()" ||
								!strings.Contains(artifact, "$(System.StageAttempt)") ||
								!strings.Contains(artifact, "$(System.JobAttempt)") {
								t.Errorf("artifact %q must only publish on success or use a diagnostic name unique to both stage and job attempts", artifact)
							}
						}
					}
				}
				for _, child := range node.Content {
					visit(child)
				}
			}
			visit(&doc)
			if outputs == 0 {
				t.Fatal("no pipeline artifact outputs found")
			}
		})
	}
}

func TestGoInfraPipelineGenReproducible(t *testing.T) {
	cmd := exec.Command("go", "run", "github.com/microsoft/go-infra/cmd/pipelineymlgen", "-exit-code", "-r", "../../../../eng/pipeline")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pipelineymlgen reproduciblility check failed: %v\nOutput:\n%s\nRun 'pwsh eng/run.ps1 pipelineymlgen' if differences are expected.", err, out)
	}
}
