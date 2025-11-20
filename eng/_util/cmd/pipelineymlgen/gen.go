// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// Generate the Azure Pipelines YAML from .gen.yml files for this repo. Normally
// this would be done from eng/ or eng/pipeline, but in this repo we don't have
// a Go module containing that directory.

//go:generate go run github.com/microsoft/go-infra/cmd/pipelineymlgen -r ../../../../eng/pipeline
