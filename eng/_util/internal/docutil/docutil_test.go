// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package docutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadGeneratedWrongSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "generated-doc-link.md")
	for _, name := range []string{"doc.md", "other.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("Generated document.\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("other.md", link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("Cannot create symlink: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := ReadGenerated(link, filepath.Join(dir, "doc.md")); err == nil {
		t.Fatal("ReadGenerated accepted a symlink to the wrong document")
	}
}

func TestReadGeneratedPlaceholder(t *testing.T) {
	root := t.TempDir()
	linkDir := filepath.Join(root, "generator")
	if err := os.Mkdir(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "generated-doc-link.md")
	doc := filepath.Join(root, "doc.md")
	if err := os.WriteFile(doc, []byte("Generated document.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name        string
		placeholder string
		wantErr     bool
	}{
		{"matching target", "../doc.md", false},
		{"wrong target", "../other.md", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(link, []byte(tt.placeholder), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := ReadGenerated(link, doc)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ReadGenerated accepted a placeholder for the wrong document")
				}
				return
			}
			if err != nil || string(got) != "Generated document.\n" {
				t.Fatalf("ReadGenerated = %q, %v; want document contents", got, err)
			}
		})
	}
}

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
