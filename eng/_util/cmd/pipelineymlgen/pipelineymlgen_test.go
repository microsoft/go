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

func TestGoInfraPipelineGenReproducible(t *testing.T) {
	cmd := exec.Command("go", "run", "github.com/microsoft/go-infra/cmd/pipelineymlgen", "-exit-code", "-r", "../../../../eng/pipeline")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pipelineymlgen reproduciblility check failed: %v\nOutput:\n%s\nRun 'pwsh eng/run.ps1 pipelineymlgen' if differences are expected.", err, out)
	}
}

func TestSigningPlatformContext(t *testing.T) {
	root := "../../../../eng/pipeline"
	read := func(path string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	var variables struct {
		Variables []struct {
			Name  string
			Value string
		}
	}
	if err := yaml.Unmarshal(read("variables/pipeline.yml"), &variables); err != nil {
		t.Fatal(err)
	}
	var platforms string
	for _, variable := range variables.Variables {
		if variable.Name == "GoSigningPlatforms" {
			platforms = variable.Value
		}
	}
	if platforms != "linux,windows,darwin" {
		t.Fatalf("GoSigningPlatforms = %q, want linux,windows,darwin", platforms)
	}

	for _, path := range []string{
		"stages/sign-stages.yml",
		"stages/internal-publish-stage.yml",
		"stages/public-publish-stages.yml",
		"steps/download-signed-binaries-task.yml",
	} {
		t.Run(path, func(t *testing.T) {
			data := read(path)
			if strings.Contains(string(data), "variables['GoSigningPlatforms']") {
				t.Fatal("template reads a custom root variable instead of ctx")
			}
			if !strings.Contains(string(data), "${{ each platform in split(parameters.ctx['GoSigningPlatforms'], ',') }}") {
				t.Fatal("missing platform loop using the explicit ctx parameter")
			}
			var template struct {
				Parameters []struct {
					Name string
					Type string
				}
			}
			if err := yaml.Unmarshal(data, &template); err != nil {
				t.Fatal(err)
			}
			for _, parameter := range template.Parameters {
				if parameter.Name == "ctx" && parameter.Type == "object" {
					return
				}
			}
			t.Fatal("missing required ctx object parameter")
		})
	}

	paths, err := filepath.Glob(filepath.Join(root, "stages", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	callers := make(map[string]int)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document yaml.Node
		if err := yaml.Unmarshal(data, &document); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		var visit func(*yaml.Node)
		visit = func(node *yaml.Node) {
			if node.Kind == yaml.MappingNode {
				var template string
				var parameters *yaml.Node
				for i := 0; i < len(node.Content); i += 2 {
					switch node.Content[i].Value {
					case "template":
						template = node.Content[i+1].Value
					case "parameters":
						parameters = node.Content[i+1]
					}
				}
				if filepath.Base(template) == "download-signed-binaries-task.yml" {
					callers[filepath.Base(path)]++
					forwarded := false
					if parameters != nil {
						for i := 0; i < len(parameters.Content); i += 2 {
							if parameters.Content[i].Value == "ctx" && parameters.Content[i+1].Value == "${{ parameters.ctx }}" {
								forwarded = true
							}
						}
					}
					if !forwarded {
						t.Errorf("%s: signed artifact download does not forward ctx", path)
					}
				}
			}
			for _, child := range node.Content {
				visit(child)
			}
		}
		visit(&document)
	}
	for path, want := range map[string]int{
		"internal-publish-stage.yml": 2,
		"public-publish-stages.yml":  2,
		"run-codeql.yml":             1,
	} {
		if callers[path] != want {
			t.Errorf("%s: found %d signed artifact download calls, want %d", path, callers[path], want)
		}
	}
}
