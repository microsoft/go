// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

// The User Guide is assembled from narrative prose (the small intro sections,
// embedded below) and structured content (userguide_content.go). The package
// sections, API entries, and Markdown scaffolding (headings, anchors, code
// fences, requirement lists, and <details> implementation blocks) are all
// generated from the structures so the document is never hand-formatted. The
// package ordering is driven by the shared cryptoPackages registry so that the
// User Guide and CrossPlatformCryptography.md stay in sync.

//go:embed userguide_preamble.md
var userGuidePreamble string

//go:embed userguide_using.md
var userGuideUsing string

// ugBackend describes how a single crypto backend implements an API. Body is
// the Markdown rendered inside the backend's collapsible <details> block.
type ugBackend struct {
	Name string
	Body string
}

// openssl and cng construct ugBackend entries for the two backends that appear
// throughout the content, so the data avoids repeating the backend names.
func openssl(body string) ugBackend { return ugBackend{Name: "OpenSSL", Body: body} }
func cng(body string) ugBackend     { return ugBackend{Name: "CNG", Body: body} }

// ugImpl describes the "Implementation" section of a package or API entry. Text
// is optional prose rendered before the per-backend details; Backends is the
// optional list of per-backend implementations.
type ugImpl struct {
	Text     string
	Backends []ugBackend
}

// ugRequirements describes the "Requirements" section of an API entry. Items is
// rendered as a bullet list; Text is used for the rare cases where the
// requirements are expressed as prose instead of a list. Exactly one of the two
// is populated.
type ugRequirements struct {
	Items []string
	Text  string
}

// ugEntry describes a single documented API (a function or variable) within a
// package section.
type ugEntry struct {
	// Kind is "func" or "var".
	Kind string
	// Name is the API name as it appears in the heading, e.g. "NewCipher" or
	// "PrivateKey.ECDH".
	Name string
	// Anchor is the fragment of the pkg.go.dev link (the part after '#'). When
	// empty it defaults to Name.
	Anchor string
	// Signature is the Go signature rendered in a ```go code block. Optional.
	Signature string
	// Doc is the prose description. Optional.
	Doc string
	// Requirements is the optional requirements section.
	Requirements *ugRequirements
	// Impl is the optional implementation section.
	Impl *ugImpl
}

// ugPackage describes a package section of the User Guide.
type ugPackage struct {
	// Import is the package import path, e.g. "crypto/aes".
	Import string
	// Doc is the package's prose description.
	Doc string
	// Impl is an optional package-level implementation section (used when the
	// implementation notes apply to the whole package rather than a single API).
	Impl *ugImpl
	// Entries are the documented APIs of the package.
	Entries []ugEntry
}

// ugLink is a Markdown link-reference definition.
type ugLink struct {
	Name string
	URL  string
}

// headingRE matches a Markdown ATX heading (levels 1-4).
var headingRE = regexp.MustCompile(`^(#{1,4}) (.*)$`)

// linkRE matches an inline Markdown link, e.g. "[text](url)".
var linkRE = regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`)

func normalizeNewlines(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

// joinBlocks joins non-empty blocks with a blank line between them.
func joinBlocks(blocks ...string) string {
	var nonEmpty []string
	for _, b := range blocks {
		if b != "" {
			nonEmpty = append(nonEmpty, b)
		}
	}
	return strings.Join(nonEmpty, "\n\n")
}

// renderImpl renders an implementation section.
func renderImpl(impl *ugImpl) string {
	var inner []string
	if impl.Text != "" {
		inner = append(inner, impl.Text)
	}
	for _, b := range impl.Backends {
		inner = append(inner, fmt.Sprintf("<details><summary>%s (click for details)</summary>\n\n%s\n\n</details>", b.Name, b.Body))
	}
	return joinBlocks("**Implementation**", joinBlocks(inner...))
}

// renderRequirements renders a requirements section.
func renderRequirements(req *ugRequirements) string {
	var body string
	if len(req.Items) > 0 {
		items := make([]string, len(req.Items))
		for i, it := range req.Items {
			items[i] = "- " + it
		}
		body = strings.Join(items, "\n")
	} else {
		body = req.Text
	}
	return joinBlocks("**Requirements**", body)
}

// renderEntry renders a single API entry.
func renderEntry(importPath string, e ugEntry) string {
	anchor := e.Anchor
	if anchor == "" {
		anchor = e.Name
	}
	link := fmt.Sprintf("https://pkg.go.dev/%s#%s", importPath, anchor)
	blocks := []string{fmt.Sprintf("#### %s [%s](%s)", e.Kind, e.Name, link)}
	if e.Signature != "" {
		blocks = append(blocks, fmt.Sprintf("```go\n%s\n```", e.Signature))
	}
	if e.Doc != "" {
		blocks = append(blocks, e.Doc)
	}
	if e.Requirements != nil {
		blocks = append(blocks, renderRequirements(e.Requirements))
	}
	if e.Impl != nil {
		blocks = append(blocks, renderImpl(e.Impl))
	}
	return joinBlocks(blocks...)
}

// renderPackage renders a package section.
func renderPackage(p ugPackage) string {
	blocks := []string{fmt.Sprintf("### [%s](%s)", p.Import, packageLink(p.Import))}
	if p.Doc != "" {
		blocks = append(blocks, p.Doc)
	}
	if p.Impl != nil {
		blocks = append(blocks, renderImpl(p.Impl))
	}
	for _, e := range p.Entries {
		blocks = append(blocks, renderEntry(p.Import, e))
	}
	return joinBlocks(blocks...)
}

// renderLinkGroups renders the trailing link-reference definitions.
func renderLinkGroups(groups [][]ugLink) string {
	rendered := make([]string, len(groups))
	for i, g := range groups {
		lines := make([]string, len(g))
		for j, l := range g {
			lines[j] = fmt.Sprintf("[%s]: %s", l.Name, l.URL)
		}
		rendered[i] = strings.Join(lines, "\n")
	}
	return strings.Join(rendered, "\n\n")
}

// tableOfContents generates a Markdown nested list linking to every heading in
// the document, replicating the GitHub anchor slugging (including duplicate
// suffixes) so it matches the anchors used by the rendered page.
func tableOfContents(document string) string {
	seen := make(map[string]int)
	var lines []string
	inFence := false
	for _, line := range strings.Split(document, "\n") {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		m := headingRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		level := len(m[1])
		text := strings.TrimSpace(stripLinks(m[2]))
		anchor := slug(text)
		if n, ok := seen[anchor]; ok {
			seen[anchor] = n + 1
			anchor = fmt.Sprintf("%s-%d", anchor, n+1)
		} else {
			seen[anchor] = 0
		}
		indent := strings.Repeat("  ", level-1)
		lines = append(lines, fmt.Sprintf("%s- [%s](#%s)", indent, displayText(text), anchor))
	}
	return strings.Join(lines, "\n")
}

// stripLinks replaces Markdown links with their link text.
func stripLinks(s string) string {
	return linkRE.ReplaceAllString(s, "$1")
}

// displayText escapes characters that Markdown would otherwise interpret when
// the text is used as link text in the table of contents.
func displayText(s string) string {
	return strings.ReplaceAll(s, "_", "\\_")
}

// slug converts heading text into a GitHub-style anchor slug.
func slug(text string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(text) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// generateUserGuide assembles the FIPS User Guide document.
func generateUserGuide() (string, error) {
	// Drive the package ordering from the shared registry so that the User
	// Guide and CrossPlatformCryptography.md cannot drift apart, and validate
	// that the structured content covers exactly the registered packages.
	contentByImport := make(map[string]ugPackage, len(userGuideContent))
	for _, p := range userGuideContent {
		if _, dup := contentByImport[p.Import]; dup {
			return "", fmt.Errorf("duplicate User Guide content for package %q", p.Import)
		}
		pkg, ok := packagesByImportPath[p.Import]
		if !ok {
			return "", fmt.Errorf("package %q has User Guide content but is not registered in cryptoPackages", p.Import)
		}
		if !pkg.InUserGuide {
			return "", fmt.Errorf("package %q has User Guide content but is not marked InUserGuide", p.Import)
		}
		contentByImport[p.Import] = p
	}

	var sections []string
	for _, reg := range userGuidePackages() {
		p, ok := contentByImport[reg.ImportPath]
		if !ok {
			return "", fmt.Errorf("package %q is marked InUserGuide but has no content in userGuideContent", reg.ImportPath)
		}
		sections = append(sections, renderPackage(p))
	}

	preamble := strings.TrimRight(normalizeNewlines(userGuidePreamble), "\n")
	using := strings.TrimRight(normalizeNewlines(userGuideUsing), "\n")
	links := renderLinkGroups(userGuideLinkGroups)

	// Build the document once without the table of contents so we can scan its
	// headings, then insert the generated table of contents.
	blocks := append([]string{preamble, using}, sections...)
	blocks = append(blocks, links)
	toc := tableOfContents(joinBlocks(blocks...))

	docBlocks := append([]string{preamble, toc, using}, sections...)
	docBlocks = append(docBlocks, links)

	var b strings.Builder
	fmt.Fprintln(&b, "<!-- This file is generated by eng/_util/cmd/updatecryptodocs. DO NOT EDIT. -->")
	fmt.Fprintln(&b)
	fmt.Fprint(&b, joinBlocks(docBlocks...))
	fmt.Fprintln(&b)
	return b.String(), nil
}
