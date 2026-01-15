// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateCryptoDocsReproducible(t *testing.T) {
	checkedInPath := filepath.Join("..", "..", "..", "..", *docPath)
	checkedIn, err := os.ReadFile(checkedInPath)
	if err != nil {
		t.Fatalf("Failed to read checked-in document at %q: %v", checkedInPath, err)
	}

	generated, err := generate()
	if err != nil {
		t.Fatalf("Failed to generate document: %v", err)
	}

	if string(checkedIn) != generated {
		t.Errorf("Generated document does not match checked-in document. Run this command to update:\n  pwsh eng/run.ps1 updatecryptodocs")
	}
}
