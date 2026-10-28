// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/microsoft/go/_util/internal/docutil"
)

func TestUpdateCryptoDocsReproducible(t *testing.T) {
	checkedInPath := filepath.Join("..", "..", "..", "..", *docPath)
	checkedIn, err := os.ReadFile(checkedInPath)
	if err != nil {
		t.Fatalf("Failed to read checked-in document at %q: %v", checkedInPath, err)
	}
	skipIfCopiedDocument(t, checkedIn)

	generated, err := generate()
	if err != nil {
		t.Fatalf("Failed to generate document: %v", err)
	}

	// Normalize Git-checked-out line endings to LF for comparison.
	actual := strings.ReplaceAll(string(checkedIn), "\r\n", "\n")

	if actual != generated {
		t.Errorf("Generated document does not match checked-in document. Run this command to update:\n  pwsh eng/run.ps1 updatecryptodocs")
	}
}

func skipIfCopiedDocument(t *testing.T, contents []byte) {
	t.Helper()
	if docutil.IsCopied(contents) {
		t.Skip("Document is maintained by automatic copying, not local regeneration.")
	}
}
