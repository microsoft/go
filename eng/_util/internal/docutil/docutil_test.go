// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package docutil

import (
	"strings"
	"testing"
)

func TestIsCopied(t *testing.T) {
	const prefix = "<!--\nDO NOT EDIT THIS COPY.\nLocal edits will be overwritten."
	for _, tt := range []struct {
		name     string
		contents string
		want     bool
	}{
		{"copy", prefix + "\n-->\nCopied document.\n", true},
		{"copy_crlf", strings.ReplaceAll(prefix+"\n-->\nCopied document.\n", "\n", "\r\n"), true},
		{"prefix_only", prefix, true},
		{"empty", "", false},
		{"local", "Generated document.\n", false},
		{"partial_prefix", "<!--\nDO NOT EDIT THIS COPY.\n", false},
		{"prefix_in_body", "Generated document.\n" + prefix, false},
		{"leading_newline", "\n" + prefix, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCopied([]byte(tt.contents)); got != tt.want {
				t.Errorf("IsCopied() = %v, want %v", got, tt.want)
			}
		})
	}
}
