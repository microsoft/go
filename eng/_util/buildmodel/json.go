// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildmodel

import (
	"encoding/json"
	"os"
)

// This file contains JSON read/write utils and JSON models used for Go Docker build/auto-update.

// ReadJSONFile reads one JSON value from the specified file.
func ReadJSONFile(path string, i interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	d := json.NewDecoder(f)
	if err := d.Decode(i); err != nil {
		return err
	}
	return nil
}

// WriteJSONFile writes the specified value to a file as indented JSON with a trailing newline.
func WriteJSONFile(path string, i interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	d := json.NewEncoder(f)
	d.SetIndent("", "  ")
	if err := d.Encode(i); err != nil {
		return err
	}
	return nil
}

// --- src/microsoft/versions.json

// VersionsJSON is the root of a 'versions.json' file. It maps a 'major.minor' key to the details of
// that version.
//
// Note: this type is an alias of a map, so it's essentially a pointer. Use VersionsJSON, not
// *VersionsJSON. The 'versions.json' file is also used by upstream infrastructure, so this model is
// designed to be compatible with it.
type VersionsJSON map[string]*MajorMinorVersion

// MajorMinorVersion contains information about a major.minor version.
type MajorMinorVersion struct {
	// Arches is the list of architectures that should be built.
	Arches map[string]*Arch `json:"arches"`
	// Variants lists OS variants that should be built. It must be provided in dependency order.
	Variants []string `json:"variants"`
	// Version is the current major.minor.patch version of this major.minor version.
	Version string `json:"version"`

	// Revision extends the upstream model by adding the Microsoft revision of the Go version. The
	// Microsoft build might get new versions that aren't associated with an upstream version bump.
	Revision string `json:"revision"`

	// PreferredMajor extends the upstream model by marking this major version as "preferred" over
	// other major versions. This is used when generating the manifest to create the "latest" tags.
	PreferredMajor bool `json:"preferredMajor,omitempty"`
	// PreferredMinor extends the upstream model by marking this minor version as "preferred" over
	// other minor versions. For example, if "1.42" is preferred, this would generate a "1" tag in
	// the manifest that people can use to pull "1.42" rather than "1.41".
	PreferredMinor bool `json:"preferredMinor,omitempty"`
	// PreferredVariant extends the upstream model and specifies the variant that should be
	// "preferred" in the tagging structure. For example, if buster is preferred over stretch, the
	// generated "1.16.6" tag will point at a buster image.
	PreferredVariant string `json:"preferredVariant,omitempty"`
}

// Arch points at the publicly accessible artifacts for a specific OS/arch.
type Arch struct {
	Env       ArchEnv `json:"env"`
	SHA256    string  `json:"sha256"`
	Supported bool    `json:"supported,omitempty"`
	URL       string  `json:"url"`
}

type ArchEnv struct {
	GOARCH string
	GOOS   string
}

// --- manifest.json

// Manifest is the root of a 'manifest.json' file. This implementation in Go only contains the
// subset of syntax that we actually use in the Go Docker repository.
//
// For more details about this model, see the dotnet/docker-tools C# implementation:
// https://github.com/dotnet/docker-tools/blob/main/src/Microsoft.DotNet.ImageBuilder/src/Models/Manifest/Manifest.cs
type Manifest struct {
	Readme    string                 `json:"readme"`
	Registry  string                 `json:"registry"`
	Variables map[string]interface{} `json:"variables"`
	Includes  []string               `json:"includes"`
	Repos     []*Repo                `json:"repos"`
}

// Repo is a Docker repository: the 'oss/go/microsoft/golang' part of a tag name.
type Repo struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Images []*Image `json:"images"`
}

// Image represents the build for a given version of Go. It contains the set of tags for this
// version, which may include multiple images for various OS/architectures.
type Image struct {
	ProductVersion string         `json:"productVersion"`
	SharedTags     map[string]Tag `json:"sharedTags"`
	Platforms      []*Platform    `json:"platforms"`
}

// Platform is one OS+arch combination, and it maps to a specific Dockerfile in the Git repo.
type Platform struct {
	BuildArgs map[string]string `json:"buildArgs,omitempty"`

	Dockerfile string `json:"dockerfile"`
	OS         string `json:"os"`
	OSVersion  string `json:"osVersion"`
	// Tags is a map of tag names to Tag metadata.
	Tags map[string]Tag `json:"tags"`
}

// Tag is the metadata about a tag. Intentionally empty: we don't use any metadata yet.
type Tag struct{}

// --- assets.json

// BuildAssets is the root of a file that describes the output of a Go build. We use this file to
// update to that build. This file's structure is controlled by our team, so we can choose to reuse
// parts of other files' schema to keep it simple.
type BuildAssets struct {
	// Branch that produced this build. This is not used for auto-update.
	Branch string `json:"branch"`
	// BuildID is a link to the build that produced these assets. It is not used for auto-update.
	BuildID string `json:"buildId"`

	// Version of the build, as 'major.minor.patch-revision'.
	Version string `json:"version"`
	// Arches is the list of artifacts that was produced for this version, typically one per target
	// os/architecture. The name "Arches" is shared with the versions.json format.
	Arches []*Arch `json:"arches"`
}
