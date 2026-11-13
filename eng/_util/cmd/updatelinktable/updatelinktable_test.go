// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"strings"
	"testing"

	"github.com/microsoft/go/_util/supportdata"
)

func TestWindowsArchiveSignatures(t *testing.T) {
	table, branches := data()
	for i, version := range supported {
		for platform := range version.Platforms {
			if !strings.HasPrefix(platform, "windows-") {
				continue
			}
			t.Run(version.Number+"/"+platform, func(t *testing.T) {
				name := "go" + version.Number + "." + platform + ".zip"
				url := baseURL + name
				var artifact *supportdata.LatestLink
				for _, file := range branches[i].Files {
					if file.Filename == name && file.Kind == supportdata.Archive {
						artifact = file
						break
					}
				}
				if artifact == nil {
					t.Fatalf("Windows archive %q missing from branch metadata", name)
				}
				if artifact.URL != url || artifact.ChecksumURL != url+".sha256" {
					t.Errorf("archive or checksum URL changed: URL = %q, ChecksumURL = %q", artifact.URL, artifact.ChecksumURL)
				}
				if want := url + ".sig"; artifact.SignatureURL != want {
					t.Errorf("SignatureURL = %q, want %q", artifact.SignatureURL, want)
				}
				if link := "[" + signatureMsg + "](" + url + ".sig)"; !strings.Contains(table, link) {
					t.Errorf("download table missing signature link %q", link)
				}
			})
		}
	}
}
