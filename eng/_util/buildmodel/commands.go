// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildmodel

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/microsoft/go-docker/eng/_util/gitpr"
)

// ParseBoundFlags parses all flags that have been registered with the flag package. This function
// handles '-help' and validates no unhandled args were passed, so may exit rather than returning.
func ParseBoundFlags(name, description string) {
	var help = flag.Bool("h", false, "Print this help message.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "\nUsage of '%s' utility:\n", name)
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n\n", description)
	}

	flag.Parse()

	if len(flag.Args()) > 0 {
		fmt.Printf("Non-flag argument(s) provided but not accepted: %v\n", flag.Args())
		flag.Usage()
		os.Exit(1)
	}

	if *help {
		flag.Usage()
		// We're exiting early, successfully. All we were asked to do is print usage info.
		os.Exit(0)
	}
}

// UpdateFlags is a list of flags used for an update command.
type UpdateFlags struct {
	manifest        *string
	skipDockerfiles *bool
}

// CreateBoundUpdateFlags creates UpdateFlags with the 'flag' package, registering them for
// ParseBoundFlags.
func CreateBoundUpdateFlags() *UpdateFlags {
	return &UpdateFlags{
		manifest: flag.String("manifest", "", "The build asset manifest describing the Go build to update to."),

		skipDockerfiles: flag.Bool("skip-dockerfiles", false, "If set, don't touch Dockerfiles.\nUpdating Dockerfiles requires bash/awk/jq, so when developing on Windows, skipping may be useful."),
	}
}

// RunUpdateHere executes RunUpdate, passing the current working directory as the Go Docker
// repository root. This allows devs to easily test out auto-update code locally.
func RunUpdateHere(f *UpdateFlags) error {
	return RunUpdate(getwd(), f)
}

// RunUpdate runs an auto-update process in the given Go Docker repository using the given update
// options. It finds the 'versions.json' and 'manifest.json' files, updates them appropriately, and
// optionally regenerates the Dockerfiles.
func RunUpdate(repoRoot string, f *UpdateFlags) error {
	var versionsJsonPath = filepath.Join(repoRoot, "src", "microsoft", "versions.json")
	var manifestJsonPath = filepath.Join(repoRoot, "manifest.json")

	var dockerfileUpdateScript = filepath.Join(repoRoot, "eng", "update-dockerfiles.sh")

	if !*f.skipDockerfiles {
		missingTools := false
		for _, requiredCmd := range []string{"bash", "jq", "awk"} {
			if _, err := exec.LookPath(requiredCmd); err != nil {
				fmt.Printf("Unable to find '%s' in PATH. It is required to run 'eng/update-dockerfiles.sh'.\n", requiredCmd)
				fmt.Printf("Error: %s\n", err)
				missingTools = true
			}
		}
		if missingTools {
			return fmt.Errorf("missing required tools to generate Dockerfiles. Make sure the tools are in PATH and try again, or pass '-skip-dockerfiles' to the command")
		}
	}

	versions := VersionsJSON{}
	if err := ReadJSONFile(versionsJsonPath, &versions); err != nil {
		return err
	}

	if *f.manifest != "" {
		assets := &BuildAssets{}
		if err := ReadJSONFile(*f.manifest, &assets); err != nil {
			return err
		}
		if err := UpdateVersions(assets, versions); err != nil {
			return err
		}
		if err := WriteJSONFile(versionsJsonPath, &versions); err != nil {
			return err
		}
	}

	fmt.Printf("Generating '%v' based on '%v'...\n", manifestJsonPath, versionsJsonPath)

	manifest := GenerateManifest(versions)
	if err := WriteJSONFile(manifestJsonPath, &manifest); err != nil {
		return err
	}

	if !*f.skipDockerfiles {
		fmt.Println("Generating Dockerfiles...")
		if err := run(exec.Command("bash", dockerfileUpdateScript)); err != nil {
			return err
		}
	}
	return nil
}

// PRFlags is a list of flags used to submit a PR. It should normally be set up at the same time as
// UpdateFlags, to update the repo and then submit a PR.
type PRFlags struct {
	dryRun     *bool
	tempGitDir *string
	branch     *string

	origin *string
	to     *string

	githubPAT         *string
	githubPATReviewer *string
}

// CreateBoundPRFlags creates PRFlags with the 'flag' package, registering them for ParseBoundFlags.
func CreateBoundPRFlags() *PRFlags {
	var artifactsDir = filepath.Join(getwd(), "eng", "artifacts")
	return &PRFlags{
		dryRun:     flag.Bool("n", false, "Enable dry run: do not push, do not submit PR."),
		tempGitDir: flag.String("temp-git-dir", filepath.Join(artifactsDir, "sync-upstream-temp-repo"), "Location to create the temporary Git repo. Must not exist."),
		branch:     flag.String("branch", "", "Branch to submit PR into. Required, if origin is provided."),

		origin: flag.String("origin", "", "Submit PR to this repo. \n[Need fetch Git permission.]"),
		to:     flag.String("to", "", "Push PR branch to this Git repository. Defaults to the same repo as 'origin' if not set.\n[Need push Git permission.]"),

		githubPAT:         flag.String("github-pat", "", "Submit the PR with this GitHub PAT, if specified."),
		githubPATReviewer: flag.String("github-pat-reviewer", "", "Approve the PR and turn on auto-merge with this PAT, if specified. Required, if github-pat specified."),
	}
}

// SubmitUpdatePR runs an auto-update in a temp Git repo. If GitHub credentials are provided,
// submits the resulting commit as a GitHub PR, approves with a second account, and enables the
// GitHub auto-merge feature.
func SubmitUpdatePR(uf *UpdateFlags, pf *PRFlags) error {
	if _, err := os.Stat(*pf.tempGitDir); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("temporary Git dir already exists: %v", *pf.tempGitDir)
	}

	if *pf.origin == "" {
		fmt.Println("Origin not specified. Continuing to update files in temporary Git dir, but will not submit PR.")
	} else {
		if *pf.branch == "" {
			return fmt.Errorf("origin is specified, but no base branch is specified")
		}
	}

	if *pf.to == "" {
		pf.to = pf.origin
	}

	b := gitpr.PRBranch{
		Name:    *pf.branch,
		Purpose: "auto-update",
	}
	// Clone from the local repo into the fresh clone to initialize it with all the Git data we
	// already have. This avoids downloading everything from scratch when we fetch origin. Most of
	// the time, we're running in infrastructure, and the local clone is fresh, so this is
	// worthwhile. (Git is also smart enough to use symlinks for a local->local clone, when
	// possible.)
	runOrPanic(exec.Command("git", "clone", getwd(), *pf.tempGitDir))

	// runGitOrPanic runs "git {args}" in the temp git dir, and panics on failure.
	runGitOrPanic := func(args ...string) {
		c := exec.Command("git", args...)
		c.Dir = *pf.tempGitDir
		runOrPanic(c)
	}

	// If the caller gave an origin, fetch the base branch. Otherwise, keep what the "git clone"
	// gave us (the last commit of the current checked-out branch) and make an update on top.
	if *pf.origin != "" {
		// Fetch the base branch into the PR branch ref and check out the ref.
		runGitOrPanic("fetch", "--no-tags", *pf.origin, b.BaseBranchFetchRefspec())
		runGitOrPanic("checkout", b.PRBranch())
	}

	// Make changes to the files ins the temp repo.
	if err := RunUpdate(*pf.tempGitDir, uf); err != nil {
		return err
	}

	runGitOrPanic("commit", "-a", "-m", "Update dependencies in "+b.Name)

	if *pf.origin != "" {
		// Force push the update commit, to make sure the update branch is fresh. The branch might
		// hold an old update with bad changes that was rejected or caused PR validation to fail.
		// This isn't necessarily ideal, and may change. https://github.com/microsoft/go/issues/68
		args := []string{"push", "--force", *pf.origin, b.PRPushRefspec()}
		if *pf.dryRun {
			// Show what would be pushed, but don't actually push it.
			args = append(args, "-n")
		}
		runGitOrPanic(args...)
	}

	// Find reasons to skip all the PR submission code. The caller might intentionally be in one of
	// these cases, so it's not necessarily an error. For example, they can take the commit we
	// generated and submit their own PR later.
	skipReason := ""
	switch {
	case *pf.dryRun:
		skipReason = "Dry run"
	case *pf.origin == "":
		skipReason = "No origin specified"
	case *pf.githubPAT == "":
		skipReason = "github-pat not provided"
	case *pf.githubPATReviewer == "":
		skipReason = "github-pat-reviewer not provided"
	}
	if skipReason != "" {
		fmt.Printf("---- %s: skipping submitting PR for %v\n", skipReason, b.Name)
		return nil
	}

	githubUser := gitpr.GetUsername(*pf.githubPAT)
	fmt.Printf("---- User for github-pat is: %v\n", githubUser)

	parsedOrigin, err := gitpr.ParseRemoteURL(*pf.origin)
	if err != nil {
		return err
	}
	fmt.Printf("---- PR for %v: Submitting...\n", b.Name)

	// POST the PR. The call returns success if the PR is created or if we receive a specific error
	// message back from GitHub saying the PR is already created.
	p, err := gitpr.PostGitHub(parsedOrigin.GetOwnerSlashRepo(), b.CreateGitHubPR(githubUser), *pf.githubPAT)
	fmt.Printf("%+v\n", p)

	if err != nil {
		return err
	}

	if p.AlreadyExists {
		fmt.Println("---- A PR already exists. Attempting to find it...")
		p.NodeID, err = gitpr.FindExistingPR(&b, githubUser, parsedOrigin.GetOwner(), *pf.githubPAT)
		if err != nil {
			return err
		}
	} else {
		fmt.Printf("---- Submitted brand new PR: %v\n", p.HTMLURL)

		fmt.Printf("---- Approving with reviewer account...\n")
		err = gitpr.MutateGraphQL(
			*pf.githubPATReviewer,
			`mutation {
						addPullRequestReview(input: {pullRequestId: "`+p.NodeID+`", event: APPROVE, body: "Thanks! Auto-approving."}) {
							clientMutationId
						}
					}`)
		if err != nil {
			return err
		}
	}

	fmt.Printf("---- Enabling auto-merge with reviewer account...\n")
	err = gitpr.MutateGraphQL(
		*pf.githubPATReviewer,
		`mutation {
					enablePullRequestAutoMerge(input: {pullRequestId: "`+p.NodeID+`", mergeMethod: MERGE}) {
						clientMutationId
					}
				}`)
	if err != nil {
		return err
	}

	fmt.Printf("---- PR for %v: Done.\n", b.Name)

	return nil
}

// getwd gets the current working dir or panics, for easy use in expressions.
func getwd() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return wd
}

// runOrPanic uses 'run', then panics on error (such as nonzero exit code).
func runOrPanic(c *exec.Cmd) {
	if err := run(c); err != nil {
		panic(err)
	}
}

// run sets up the command so it logs directly to our stdout/stderr streams, then runs it.
func run(c *exec.Cmd) error {
	fmt.Printf("---- Running command: %v %v\n", c.Path, c.Args)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
