// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package patchcheck

import (
	"testing"
)

func TestFindPatchIssues(t *testing.T) {
	issues, err := FindPatchIssues()
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range issues {
		t.Errorf("%s: %s", issue.PatchFile, issue.Message)
	}
}
