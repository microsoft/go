---
description: "Use when reviewing, editing, or creating Git patch files in the patches/ directory. Covers patch consistency rules, vendor constraints, naming conventions, and Go file build tag guidelines. Apply during code review and pull request review of patch changes."
applyTo: "patches/*.patch"
---

# Patch consistency review

## Project context

The `patches/` directory contains `git format-patch` files that are applied on top of the upstream Go source tree, which is in the `go/` submodule. Each patch is prefixed with a sequence number and a short description of its purpose, e.g. `0001-Vendor-external-dependencies.patch`, `0004-Use-crypto-backends.patch`. The patches are applied in order, and each one should be self-contained to a single logical concern and describe that concern in the commit message.

## Rules to check

### Vendor changes must be in the vendor patch

If the diff adds, modifies, or removes any file under a `vendor/` directory path, verify:
- The change is in `0001-Vendor-external-dependencies.patch` only. No other patch should touch vendor files
- The corresponding `go.mod`, `go.sum`, and `modules.txt` changes are included in the same patch
- The vendor patch doesn't include changes other than `vendor/` files, related module files, and `src/crypto/deps_ignore.go`

### Patch naming convention

New or renamed patch files must follow the `NNNN-Short-Description.patch` pattern (zero-padded four-digit prefix, hyphen-separated description) consistent with existing patches in the directory.

### No redundant or misplaced changes

- A new patch should not duplicate changes already covered by an existing patch
- Changes should be in the patch whose description matches the concern. For example, crypto backend changes belong in the crypto backend patch, not in the vendor patch or a new unrelated patch
- If an existing patch already covers the area being changed, the change should amend that patch rather than create a new one

### Go file OS/arch constraints

When a patch adds or modifies a Go file that targets a specific OS or architecture, prefer the filename suffix convention (`_linux.go`, `_windows.go`, `_darwin.go`) over adding OS/arch constraints in `//go:build` tags. If the filename suffix already implies the OS/arch, the build tag should not repeat it.

- Preferred: `foo_linux.go` with `//go:build goexperiment.systemcrypto`
- Avoid: `foo.go` with `//go:build goexperiment.systemcrypto && linux`

### No extraneous blank lines

Patches should not introduce unnecessary blank lines between functions, at the end of files, or between import groups. Whitespace should be consistent with the surrounding code in the Go source tree.

## How to review

1. **Identify which patch(es) changed**: Check the PR's modified files for `patches/*.patch`
2. **Analyze the intent**: Read the patch diff to understand what feature or fix is being implemented
3. **Cross-reference other patches**: Check if other patches in the directory touch the same source files or implement related functionality. Compare method signatures, behavior, and documentation for consistency
4. **Flag inconsistencies**: Be specific about which patches need updates and what changes would bring them into alignment
5. **If no issues**: Include the message "Patches are happy!" in the review conclusion if no consistency issues are found.

## Review tone

- Frame feedback as suggestions for maintaining consistency, not demands
- Focus on consistency across the patch set, not general code quality
- Skip trivial differences like comment styles or variable naming
- Only comment when there are actual consistency issues to flag
