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

func TestUpdateUserGuideReproducible(t *testing.T) {
	checkedInPath := filepath.Join("..", "..", "..", "..", *userGuidePath)
	checkedIn, err := os.ReadFile(checkedInPath)
	if err != nil {
		t.Fatalf("Failed to read checked-in document at %q: %v", checkedInPath, err)
	}
	skipIfCopiedDocument(t, checkedIn)

	generated, err := generateUserGuide()
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

func TestUserGuideX509Coverage(t *testing.T) {
	generated, err := generateUserGuide()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[crypto/x509](#cryptox509)",
		"### [crypto/x509](https://pkg.go.dev/crypto/x509)",
	} {
		if !strings.Contains(generated, want) {
			t.Errorf("User Guide missing %q", want)
		}
	}
	for _, name := range []string{
		"CreateCertificate",
		"CreateCertificateRequest",
		"CreateRevocationList",
		"Certificate.CreateCRL",
		"Certificate.CheckSignature",
		"Certificate.CheckSignatureFrom",
		"CertificateRequest.CheckSignature",
		"RevocationList.CheckSignatureFrom",
		"Certificate.CheckCRLSignature",
		"Certificate.Verify",
		"EncryptPEMBlock",
		"DecryptPEMBlock",
	} {
		want := "#### func [" + name + "](https://pkg.go.dev/crypto/x509#" + name + ")"
		if !strings.Contains(generated, want) {
			t.Errorf("User Guide missing x509 API heading %q", name)
		}
		if !strings.Contains(generated, "[func "+name+"](#"+slug("func "+name)+")") {
			t.Errorf("User Guide missing x509 table-of-contents entry %q", name)
		}
	}
}
