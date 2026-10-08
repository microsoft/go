// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toolchaintest

import (
	"go/build"
	"reflect"
	"testing"
)

// Check that the systemcrypto tag works and collects AllTags correctly.
// This is based on the TestAllTags test.
func TestCryptoBackendAllTags(t *testing.T) {
	ctxt := build.Default
	// Remove tool tags so these tests behave the same regardless of the
	// goexperiments that happen to be set during the run.
	ctxt.ToolTags = []string{}
	ctxt.GOARCH = "amd64"
	ctxt.GOOS = "linux"
	ctxt.BuildTags = []string{"goexperiment.systemcrypto"}

	p, err := ctxt.ImportDir("testdata/backendtags_system", 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"goexperiment.systemcrypto"}
	if !reflect.DeepEqual(p.AllTags, want) {
		t.Errorf("AllTags = %v, want %v", p.AllTags, want)
	}
	wantFiles := []string{"main.go", "systemcrypto.go"}
	if !reflect.DeepEqual(p.GoFiles, wantFiles) {
		t.Errorf("GoFiles = %v, want %v", p.GoFiles, wantFiles)
	}

	// Test without systemcrypto - only main.go should be included
	ctxt.BuildTags = []string{}
	p, err = ctxt.ImportDir("testdata/backendtags_system", 0)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"goexperiment.systemcrypto"}
	if !reflect.DeepEqual(p.AllTags, want) {
		t.Errorf("AllTags = %v, want %v", p.AllTags, want)
	}
	wantFiles = []string{"main.go"}
	if !reflect.DeepEqual(p.GoFiles, wantFiles) {
		t.Errorf("GoFiles = %v, want %v", p.GoFiles, wantFiles)
	}
}
