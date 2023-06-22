// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package supportdata

type Branch struct {
	// Version of the branch not including patch version, e.g. "1.20".
	Version string `json:"version,omitempty"`
	// Stable is true if this is a stable release.
	Stable bool `json:"stable,omitempty"`
	// LatestStable is true if this is the most recent stable release.
	LatestStable bool `json:"latestStable,omitempty"`
	// PreviousStable is true if this is the stable release just before the
	// latest stable one.
	PreviousStable bool `json:"previousStable,omitempty"`
	// Files is the list of "latest X" links for each artifact X.
	Files []*LatestLink `json:"files,omitempty"`
}

type ArtifactKind string

const (
	Archive   ArtifactKind = "archive"
	Installer ArtifactKind = "installer"
	Source    ArtifactKind = "source"
)

type LatestLink struct {
	Filename string       `json:"filename"`
	OS       string       `json:"os"`
	Arch     string       `json:"arch"`
	Version  string       `json:"version"`
	Kind     ArtifactKind `json:"kind"`
	// URL is the aka.ms link that downloads the latest patch version of this
	// artifact.
	//
	// Note that downloading URL then ChecksumURL may result in a race condition
	// because the aka.ms URLs may be updated to point to a new build between
	// the two downloads.
	URL string `json:"url,omitempty"`
	// ChecksumURL is the aks.ms link that downloads the latest checksum file
	// associated with this artifact (if any).
	ChecksumURL string `json:"checksumURL,omitempty"`
	// SignatureURL is the aks.ms link that downloads the latest signature file
	// associated with this artifact (if any).
	SignatureURL string `json:"signatureURL,omitempty"`
}
