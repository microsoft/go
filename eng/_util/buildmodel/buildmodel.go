// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildmodel

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// GenerateManifest takes a 'versions.json' model and generates a 'manifest.json' model that would
// build and tag all versions specified. Slices in the generated model are sorted for diff
// stability. Map stability is handled by the Go JSON library when the model is serialized.
func GenerateManifest(versions VersionsJSON) Manifest {
	sortedMajorMinorKeys := make([]string, 0, len(versions))
	for key := range versions {
		sortedMajorMinorKeys = append(sortedMajorMinorKeys, key)
	}
	sort.Strings(sortedMajorMinorKeys)

	var images []*Image

	for _, majorMinor := range sortedMajorMinorKeys {
		v := versions[majorMinor]

		// The key is always a major.minor version. Split out the major part.
		major, _, _, _ := parseVersion(majorMinor)

		for _, variant := range v.Variants {
			os := "linux"
			osVersion := variant
			if strings.HasPrefix(variant, "windows/") {
				os = "windows"
				osVersion = strings.TrimPrefix(variant, "windows/")
			}

			// If the versions.json doesn't specify a revision, default to "1". (1 is the
			// default/initial revision for Deb/RPM packages, and we may as well follow that.)
			if v.Revision == "" {
				v.Revision = "1"
			}

			// The main tag that is shared by all architectures.
			mainSharedTag := v.Version + "-" + v.Revision + "-" + osVersion

			sharedTags := map[string]Tag{
				mainSharedTag: {},
				// Revisionless tag.
				v.Version + "-" + osVersion: {},
				// We only maintain one patch version, so it's always preferred. Add major.minor tag.
				majorMinor + "-" + osVersion: {},
			}

			// If this is a preferred major.minor version, create major-only tag.
			if v.PreferredMinor {
				sharedTags[major+"-"+osVersion] = Tag{}
			}
			// If this is the preferred major version, create versionless tag.
			if v.PreferredMajor {
				sharedTags[osVersion] = Tag{}
			}

			// If this is the preferred variant, create tags without the variant (OS) part.
			if v.PreferredVariant == variant {
				sharedTags[v.Version+"-"+v.Revision] = Tag{}
				sharedTags[v.Version] = Tag{}
				sharedTags[majorMinor] = Tag{}

				if v.PreferredMinor {
					sharedTags[major] = Tag{}
				}
				if v.PreferredMajor {
					sharedTags["latest"] = Tag{}
				}
			}

			var buildArgs map[string]string
			// The nanoserver Dockerfile requires some args so it can be connected properly to its
			// dependency, windowsservercore.
			if strings.Contains(osVersion, "nanoserver") {
				buildArgs = map[string]string{
					// nanoserver doesn't have good download capability, so it copies the Go install
					// from the windowsservercore image.
					"DOWNLOADER_TAG": v.Version + "-" + v.Revision + "-windowsservercore-1809-amd64",
					// The nanoserver Dockerfile needs to know what repository we're building for so
					// it can figure out the windowsservercore tag's full name.
					"REPO": "$(Repo:golang)",
				}
			}

			images = append(images, &Image{
				ProductVersion: majorMinor,
				SharedTags:     sharedTags,
				Platforms: []*Platform{
					{
						Dockerfile: "src/microsoft/" + majorMinor + "/" + variant,
						OS:         os,
						OSVersion:  osVersion,

						BuildArgs: buildArgs,

						Tags: map[string]Tag{
							// We only build amd64 at the moment. The way to implement other
							// architectures in the future is to add more Platform entries.
							mainSharedTag + "-amd64": {},
						},
					},
				},
			})
		}
	}

	return Manifest{
		Readme:    "README.md",
		Registry:  "mcr.microsoft.com",
		Variables: map[string]interface{}{},
		Includes:  []string{},
		Repos: []*Repo{
			{
				ID:     "golang",
				Name:   "oss/go/golang/alpha",
				Images: images,
			},
		},
	}
}

// NoMajorMinorUpgradeMatchError indicates that while running UpdateVersions, the input assets file
// didn't match any major.minor versions and no update could be performed.
var NoMajorMinorUpgradeMatchError = errors.New("no match found in existing versions.json file")

// UpdateVersions takes a build asset file containing a list of build outputs and updates a
// versions.json model to consume the new build.
func UpdateVersions(assets *BuildAssets, versions VersionsJSON) error {
	major, minor, patch, revision := parseVersion(assets.Version)

	key := major + "." + minor
	if v, ok := versions[key]; ok {
		v.Version = major + "." + minor + "." + patch
		v.Revision = revision
		// Look through the asset arches, find an arch in the versions file that matches each asset,
		// and update its info.
		for _, arch := range assets.Arches {
			// The versions file has a map of "GOOS-GOARCH" keys, but the key omits "linux-" if
			// included. This is upstream behavior we are conforming to.
			archKey := arch.Env.GOOS + "-"
			if archKey == "linux-" {
				archKey = ""
			}
			archKey += arch.Env.GOARCH

			if match, ok := v.Arches[archKey]; ok {
				// Copy over the previous value of keys that aren't specific to an asset, but
				// actually indicate the state of the Dockerfile. All other values come from the new
				// asset's data.
				arch.Supported = match.Supported
			}
			// Copy the asset data into the versions file whether it's a new arch or not.
			v.Arches[archKey] = arch
		}
	} else {
		return fmt.Errorf("%v: %w", key, NoMajorMinorUpgradeMatchError)
	}
	return nil
}

// parseVersion parses a "major.minor.patch-revision" version string into each part. If a part
// doesn't exist, it defaults to "0".
func parseVersion(v string) (string, string, string, string) {
	dashParts := strings.Split(v, "-")
	majorMinorPatch := dashParts[0]
	revision := "0"
	if len(dashParts) > 1 {
		revision = dashParts[1]
	}

	dotParts := strings.Split(majorMinorPatch, ".")
	major := dotParts[0]
	minor := "0"
	if len(dotParts) > 1 {
		minor = dotParts[1]
	}
	patch := "0"
	if len(dotParts) > 2 {
		patch = dotParts[2]
	}

	return major, minor, patch, revision
}
