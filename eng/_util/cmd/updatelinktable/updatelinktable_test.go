// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/microsoft/go/_util/internal/docutil"
)

func TestUpdateLinkTableReproducible(t *testing.T) {
	checkedInPath := filepath.Join("..", "..", "..", "..", docPath)
	checkedIn, err := docutil.ReadGenerated("testdata/generated-doc-link.md", checkedInPath)
	if err != nil {
		t.Fatalf("Failed to read checked-in document at %q: %v", checkedInPath, err)
	}

	// Normalize Git-checked-out line endings to LF for comparison.
	actual := strings.ReplaceAll(string(checkedIn), "\r\n", "\n")
	_, after, ok := strings.Cut(actual, beginMark)
	if !ok {
		t.Fatalf("Start marker %q not found in %q", beginMark, checkedInPath)
	}
	table, _, ok := strings.Cut(after, endMark)
	if !ok {
		t.Fatalf("End marker %q not found after start marker in %q", endMark, checkedInPath)
	}

	generated, _ := data()
	if table != "\n\n"+generated+"\n\n" {
		t.Errorf("Generated document does not match checked-in document. Run this command to update:\n  pwsh eng/run.ps1 updatelinktable")
	}
}
