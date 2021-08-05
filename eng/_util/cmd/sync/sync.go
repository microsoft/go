// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const description = `
Example: A sync operation dry run from upstream master to microsoft/go:

  eng/run.ps1 sync -b master -n

It may be useful to specify Git addresses like 'git@github.com:microsoft/go' to
use SSH authentication.

A 'sync' is a few steps to run "merge from upstream" and "mirror from upstream":

1. Fetch every 'branch' from 'upstream'.
2. Fetch each 'microsoft/{branch}' from 'origin'.
3. Merge each upstream branch 'b' into corresponding 'microsoft/b'.
4. Push each merge commit to 'to' as 'auto-merge/microsoft/{branch}'.
5. Create a PR in 'origin' that merges the auto-merge branch.
   - This PR is the "merge from upstream".
6. Push each branch from 'upstream' to 'to' with the exact same name.
   - This push is the "mirror from upstream".
   - We may change this to push to 'origin' in the future. See https://github.com/microsoft/go/issues/4

This script creates a temporary copy of the repository in 'eng/artifacts/' by
default. This avoids trampling changes in the user's clone.`

// Files and dirs that upstream may modify, but we want to ignore those modifications and keep our
// changes to them. Normally our files are all in the 'eng/' directory, but some files are required
// by GitHub to be in the root of the repo or in the '.github' directory, so we must modify them in
// place and auto-resolve conflicts.
//
// This is in package scope just so it's easy to find at the top of the file for maintenance.
var autoResolveOurPaths = []string{
	".github",
	"CODE_OF_CONDUCT.md",
	"README.md",
	"SECURITY.md",
	"SUPPORT.md",
}

var dryRun = flag.Bool("n", false, "Enable dry run: do not push, do not submit PR.")
var tempGitDir = flag.String("temp-git-dir", filepath.Join(getwd(), "eng", "artifacts", "sync-upstream-temp-repo"), "Location to create the temporary Git repo. Must not exist.")

var client = http.Client{
	Timeout: time.Second * 30,
}

func main() {
	var to = flag.String("to", "https://github.com/microsoft-golang-bot/go", "Push synced refs to this Git repository.\n[Need push Git permission.]")
	var origin = flag.String("origin", "https://github.com/microsoft/go", "Get latest 'microsoft/*' branches from this repo, and submit sync PR to this repo.\n[Need fetch Git permission.]")
	var upstream = flag.String("upstream", "https://go.googlesource.com/go", "Get upstream Git data from this repo.\n[Need fetch Git permission.]")

	var githubPAT = flag.String("github-pat", "", "Submit the PR with this GitHub PAT, if specified.")
	var githubPATReviewer = flag.String("github-pat-reviewer", "", "Approve the PR and turn on auto-merge with this PAT, if specified. Required, if github-pat specified.")

	var help = flag.Bool("h", false, "Print this help message.")

	var branchNames []string
	flag.Func(
		"b",
		"Sync this upstream branch. Specify multiple times to sync multiple branches.\n"+
			"This must be the branch name as it's known by GitHub, like 'master'.",
		func(arg string) error {
			branchNames = append(branchNames, arg)
			return nil
		})

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "\nUsage of sync-upstream-refs.go:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n\n", description)
	}

	flag.Parse()

	if len(flag.Args()) > 0 {
		fmt.Printf("Non-flag argument(s) provided but not accepted: %v\n", flag.Args())
		flag.Usage()
		os.Exit(1)
	}

	if *help || len(branchNames) == 0 {
		flag.Usage()
		// Exit 0: script is successful, even though it didn't do anything except print usage info.
		return
	}

	if _, err := os.Stat(*tempGitDir); !errors.Is(err, os.ErrNotExist) {
		fmt.Printf("Error: Temporary Git dir already exists: %v\n", *tempGitDir)
		os.Exit(1)
	}

	runOrPanic(exec.Command("git", "init", *tempGitDir))

	var branches []*branch = make([]*branch, 0, len(branchNames))
	for _, b := range branchNames {
		nb := newBranch(b)
		branches = append(branches, &nb)
	}

	// Fetch latest from remotes. We fetch with one big Git command per remote, instead of simply
	// looping across every branch. This keeps round-trips to a minimum and benefits from innate Git
	// parallelism.
	//
	// For each mirrored branch B in upstream, fetch it as 'auto-sync/B'.
	//
	// For each corresponding branch C in origin, fetch it as 'auto-merge/C'. (Branches in origin
	// correspond to branches in upstream. E.g. 'master' B corresponds to 'microsoft/main' C.)
	//
	// Next, run auto-merge for each branch. We checkout 'auto-merge/C' and merge 'auto-sync/B' into
	// it. This creates a merge commit in the local repo that brings origin 'microsoft/B' up to date
	// with new changes in upstream 'B'.
	//
	// Once we're done merging each 'auto-merge/C' branch, we push all 'auto-sync/B' and
	// 'auto-merge/C' branches to the 'to' repo. (Like fetching, this is also done with two commands
	// to minimize round trips.)

	fetchUpstream := newGitCommand("fetch", "--no-tags", *upstream)
	fetchOrigin := newGitCommand("fetch", "--no-tags", *origin)
	for _, b := range branches {
		fetchUpstream.Args = append(fetchUpstream.Args, b.upstreamFetchRefspec())
		fetchOrigin.Args = append(fetchOrigin.Args, b.originFetchRefspec())
	}
	runOrPanic(fetchUpstream)
	runOrPanic(fetchOrigin)

	for _, b := range branches {
		runOrPanic(newGitCommand("checkout", "auto-merge/"+b.mergeTarget))

		if err := run(newGitCommand("merge", "--no-ff", "--no-commit", "auto-sync/"+b.name)); err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				fmt.Printf("---- Merge hit an ExitError: '%v'. A non-zero exit code is expected if there were conflicts. The script will try to resolve them, next.\n", exitError)
			} else {
				// Make sure we don't ignore more than we intended.
				panic(err)
			}
		}

		// Automatically resolve conflicts in specific project doc files. Use '--no-overlay' to make
		// sure we delete new files in e.g. '.github' that are in upstream but don't exist locally.
		// '--ours' auto-deletes if upstream modifies a file that we deleted in our branch.
		runOrPanic(newGitCommand(append([]string{"checkout", "--no-overlay", "--ours", "HEAD", "--"}, autoResolveOurPaths...)...))

		// If we still have unmerged files, 'git commit' will exit non-zero, causing the script to
		// exit. This prevents the script from pushing a bad merge.
		runOrPanic(newGitCommand("commit", "-m", "Merge upstream branch '"+b.name+"' into "+b.mergeTarget))

		// Show a summary of which files are in our branch vs. upstream. This is just informational.
		// CI is a better place to *enforce* a low diff: it's more visible, can be fixed up more
		// easily, and doesn't block other branch mirror/merge operations.
		//
		// Save it to the branch struct so we can add it to the PR text.
		b.fileDiff = combinedOutput(newGitCommand(
			"diff",
			"--name-status",
			"auto-sync/"+b.name,
			"auto-merge/"+b.mergeTarget,
		))

		fmt.Printf("---- Files changed from '%v' to '%v' ----\n", b.name, b.mergeTarget)
		fmt.Print(b.fileDiff)
		fmt.Println("--------")
	}

	// Mirroring should always be FF: fail if not. This indicates upstream did some kind of a force
	// push, so the merging probably wouldn't work anyway.
	mirrorPushRefspecs := make([]string, 0, len(branches))
	for _, b := range branches {
		mirrorPushRefspecs = append(mirrorPushRefspecs, b.mirrorPushRefspec())
	}
	runOrPanic(newGitPushCommand(*to, false, mirrorPushRefspecs))

	// Force push the merge branches. We can't do a fast-forward push: our new merge commit is based
	// on "origin", not "to", so if "to" has any commits, they aren't in our commit's history.
	//
	// Even if we did base our branch on "to", we'd hit undesired behaviors if the branch still has
	// changes from an old PR. There are ways to handle this, but no clear benefit. Force push is
	// simple and makes the PR flow simple.
	mergePushRefspecs := make([]string, 0, len(branches))
	for _, b := range branches {
		mergePushRefspecs = append(mergePushRefspecs, b.mergePushRefspec())
	}
	runOrPanic(newGitPushCommand(*to, true, mergePushRefspecs))

	// All Git operations are complete! Next, ensure there's a GitHub PR for each auto-merge branch.

	// Accumulate overall failure. This lets PR submission continue even if there's a problem for a
	// specific branch.
	var prFailed bool

	// Lazy var. github user that owns the PRs. This is normally the owner of the 'to' repo.
	var githubUser string
	// Lazy var. The origin that should receive the PR.
	var parsedOrigin *remote

	for _, b := range branches {
		var skipReason string
		switch {
		case *dryRun:
			skipReason = "Dry run"

		case *githubPAT == "":
			skipReason = "github-pat not provided"

		case *githubPATReviewer == "":
			// In theory, if we have githubPAT but no reviewer, we can submit the PR but skip
			// reviewing it/enabling auto-merge. However, this doesn't seem very useful, so it isn't
			// implemented.
			skipReason = "github-pat-reviewer not provided"
		}

		if skipReason != "" {
			fmt.Printf("---- %s: skipping submitting PR for %v -> %v\n", skipReason, b.name, b.mergeTarget)
			continue
		}

		if githubUser == "" {
			githubUser = getUsername(*githubPAT)
			fmt.Printf("---- User for github-pat is: %v\n", githubUser)
		}

		if parsedOrigin == nil {
			var err error
			if parsedOrigin, err = parseRemoteURL(*origin); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}

		// err contains any err we get from running the sequence of GitHub PR submission API calls.
		//
		// This uses an immediately invoked anonymous function for convenience/maintainability. We
		// can 'return err' from anywhere in the function, to keep control flow simple. Also, we can
		// capture vars from the 'main()' scope rather than making them global or explicitly passing
		// each one into a named function.
		err := func() error {
			fmt.Printf("---- PR for %v -> %v: Submitting...\n", b.name, b.mergeTarget)

			// POST the PR. The call returns success if the PR is created or if we receive a
			// specific error message back from GitHub saying the PR is already created.
			pr, err := postPR(parsedOrigin.getOwnerSlashRepo(), b.createPRRequest(githubUser), *githubPAT)
			fmt.Printf("%+v\n", pr)

			if err != nil {
				return err
			}

			if pr.AlreadyExists {
				fmt.Println("---- A PR already exists. Attempting to find it...")
				pr.NodeID, err = findExistingPR(b, githubUser, parsedOrigin.getOwner(), *githubPAT)
				if err != nil {
					return err
				}
			} else {
				fmt.Printf("---- Submitted brand new PR: %v\n", pr.HTMLURL)

				fmt.Printf("---- Approving with reviewer account...\n")
				err = mutateGraphQL(
					*githubPATReviewer,
					`mutation {
						addPullRequestReview(input: {pullRequestId: "`+pr.NodeID+`", event: APPROVE, body: "Thanks! Auto-approving."}) {
							clientMutationId
						}
					}`)
				if err != nil {
					return err
				}
			}

			fmt.Printf("---- Enabling auto-merge with reviewer account...\n")
			err = mutateGraphQL(
				*githubPATReviewer,
				`mutation {
					enablePullRequestAutoMerge(input: {pullRequestId: "`+pr.NodeID+`", mergeMethod: MERGE}) {
						clientMutationId
					}
				}`)
			if err != nil {
				return err
			}

			fmt.Printf("---- PR for %v -> %v: Done.\n", b.name, b.mergeTarget)
			return nil
		}()

		// If we got an error, don't panic! Log the error and set a flag to indicate it happened,
		// then continue to process the next branch in the for loop.
		//
		// Say we are syncing branches main, go1.15, and go1.16. We're in the go1.15 iteration. For
		// some reason, GitHub errored out when we submitted the PR for go1.15. If we panic, the
		// script terminates before trying to submit a PR for go1.16, even though that one might
		// work fine. That's not ideal. But worse, if the error persists and happens again when we
		// try to update go1.15 in future runs of this script, go1.16 will never get synced. This is
		// why we want to try to keep processing branches.
		if err != nil {
			fmt.Println(err)
			prFailed = true
			continue
		}
	}

	// If PR submission failed for any branch, exit the overall script with NZEC.
	if prFailed {
		fmt.Printf("Failed to submit one or more PRs.")
		os.Exit(1)
	}

	fmt.Println("\nSuccess.")
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

// combinedOutput returns the output string of c.CombinedOutput, and panics on error.
func combinedOutput(c *exec.Cmd) string {
	fmt.Printf("---- Running command: %v %v\n", c.Path, c.Args)
	out, err := c.CombinedOutput()
	if err != nil {
		panic(err)
	}
	return string(out)
}

func newGitCommand(args ...string) *exec.Cmd {
	c := exec.Command("git", args...)
	c.Dir = *tempGitDir
	return c
}

func newGitPushCommand(remote string, force bool, refspecs []string) *exec.Cmd {
	c := newGitCommand("push")
	if force {
		c.Args = append(c.Args, "--force")
	}
	c.Args = append(c.Args, remote)
	for _, r := range refspecs {
		c.Args = append(c.Args, r)
	}
	if *dryRun {
		c.Args = append(c.Args, "-n")
	}
	return c
}

// branch contains information about a specific branch to sync. During the sync process, more info
// can be added to this struct to be used later. This struct has methods that help calculate derived
// information such as Git ref names.
type branch struct {
	name        string
	mergeTarget string

	// fileDiff starts empty. It's filled in after the sync performs the merge. It contains a
	// file-level diff between the upstream branch and the merge target.
	fileDiff string
}

func newBranch(b string) branch {
	return branch{
		name:        b,
		mergeTarget: "microsoft/" + strings.ReplaceAll(b, "master", "main"),
	}
}

func (b branch) upstreamFetchRefspec() string {
	return "refs/heads/" + b.name + ":refs/heads/auto-sync/" + b.name
}

func (b branch) mirrorPushRefspec() string {
	return "auto-sync/" + b.name + ":refs/heads/" + b.name
}

func (b branch) originFetchRefspec() string {
	return "refs/heads/" + b.mergeTarget + ":refs/heads/auto-merge/" + b.mergeTarget
}

func (b branch) mergePushRefspec() string {
	return "auto-merge/" + b.mergeTarget + ":refs/heads/auto-merge/" + b.mergeTarget
}

func (b branch) createPRRequest(githubUser string) prRequest {
	return prRequest{
		Head: githubUser + ":auto-merge/" + b.mergeTarget,
		Base: b.mergeTarget,

		Title: fmt.Sprintf("Merge upstream `%v` into `%v`", b.name, b.mergeTarget),
		Body: fmt.Sprintf(
			"🔃 This is an automatically generated PR merging upstream `%v` into `%v`.\n\n"+
				"This PR should auto-merge itself when PR validation passes. If CI fails and you need to make fixups, be sure to use a merge commit, not a squash or rebase!\n\n"+
				"---\n\n"+
				"After these changes, the difference between upstream and the branch is:\n\n"+
				"```\n%v\n```",
			b.name,
			b.mergeTarget,
			strings.TrimSpace(b.fileDiff),
		),

		MaintainerCanModify: true,
		Draft:               false,
	}
}

// remote is a parsed version of a Git remote. It helps determine how to send a GitHub PR.
type remote struct {
	url      string
	urlParts []string
}

// parseRemoteURL takes the URL ("https://github.com/microsoft/go", "git@github.com:microsoft/go")
// and grabs the owner ("microsoft") and repository name ("go"). This assumes the URL follows one of
// these two patterns, or something that's compatible. Returns an initialized 'remote'.
func parseRemoteURL(url string) (*remote, error) {
	r := &remote{
		url,
		strings.FieldsFunc(url, func(r rune) bool { return r == '/' || r == ':' }),
	}
	if len(r.urlParts) < 3 {
		return r, fmt.Errorf(
			"failed to find 3 parts of remote url '%v'. Found '%v'. Expected a string separated with '/' or ':', like https://github.com/microsoft/go or git@github.com:microsoft/go",
			r.url,
			r.urlParts,
		)
	}
	fmt.Printf("From repo URL %v, detected %v for the PR target.\n", url, r.urlParts)
	return r, nil
}

func (r remote) getOwnerRepo() []string {
	return r.urlParts[len(r.urlParts)-2:]
}

func (r remote) getOwner() string {
	return r.getOwnerRepo()[0]
}

func (r remote) getOwnerSlashRepo() string {
	return strings.Join(r.getOwnerRepo(), "/")
}

// sendJSONRequest sends a request for JSON information. The JSON response is unmarshalled (parsed)
// into the 'response' parameter, based on the structure of 'response'.
func sendJSONRequest(request *http.Request, response interface{}) (status int, err error) {
	request.Header.Add("Accept", "application/vnd.github.v3+json")
	fmt.Printf("Sending request: %v %v\n", request.Method, request.URL)

	httpResponse, err := client.Do(request)
	if err != nil {
		return
	}
	defer httpResponse.Body.Close()
	status = httpResponse.StatusCode

	for key, value := range httpResponse.Header {
		if strings.HasPrefix(key, "X-Ratelimit-") {
			fmt.Printf("%v : %v\n", key, value)
		}
	}

	jsonBytes, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return
	}

	fmt.Printf("---- Full response:\n%v\n", string(jsonBytes))
	fmt.Printf("----\n")

	err = json.Unmarshal(jsonBytes, response)
	return
}

// sendJSONRequestSuccessful sends a request for JSON information via sendJsonRequest and verifies
// the status code is success.
func sendJSONRequestSuccessful(request *http.Request, response interface{}) error {
	status, err := sendJSONRequest(request, response)
	if err != nil {
		return err
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("request unsuccessful, http status %v, %v", status, http.StatusText(status))
	}
	return nil
}

// getUsername queries GitHub for the username associated with a PAT.
func getUsername(pat string) string {
	request, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		panic(err)
	}
	request.SetBasicAuth("", pat)

	response := &struct {
		Login string `json:"login"`
	}{}

	if err := sendJSONRequestSuccessful(request, response); err != nil {
		panic(err)
	}

	return response.Login
}

// prRequest is the payload for a GitHub PR creation API call, marshallable as JSON.
type prRequest struct {
	Head                string `json:"head"`
	Base                string `json:"base"`
	Title               string `json:"title"`
	Body                string `json:"body"`
	MaintainerCanModify bool   `json:"maintainer_can_modify"`
	Draft               bool   `json:"draft"`
}

// prRequestResponse is a PR creation response from GitHub. It may represent success or failure.
type prRequestResponse struct {
	// GitHub success response:
	HTMLURL string `json:"html_url"`
	NodeID  string `json:"node_id"`

	// GitHub failure response:
	Message string           `json:"message"`
	Errors  []prRequestError `json:"errors"`

	// AlreadyExists is set to true if the error message says the PR exists. Otherwise, false. For
	// our purposes, a GitHub failure response that indicates a PR already exists is not an error.
	AlreadyExists bool
}

type prRequestError struct {
	Message string `json:"message"`
}

func postPR(ownerRepo string, request prRequest, pat string) (response *prRequestResponse, err error) {
	prSubmitContent, err := json.MarshalIndent(request, "", "")
	fmt.Printf("Submitting payload: %s\n", prSubmitContent)

	httpRequest, err := http.NewRequest("POST", "https://api.github.com/repos/"+ownerRepo+"/pulls", bytes.NewReader(prSubmitContent))
	if err != nil {
		return
	}
	httpRequest.SetBasicAuth("", pat)

	response = &prRequestResponse{}
	statusCode, err := sendJSONRequest(httpRequest, response)
	if err != nil {
		return
	}

	switch statusCode {
	case http.StatusCreated:
		// 201 Created is the expected code if the PR is created. Do nothing.

	case http.StatusUnprocessableEntity:
		// 422 Unprocessable Entity may indicate the PR already exists. GitHub also gives us a response
		// that looks like this:
		/*
			{
				"message": "Validation Failed",
				"errors": [
					{
						"resource": "PullRequest",
						"code": "custom",
						"message": "A pull request already exists for microsoft-golang-bot:auto-merge/microsoft/main."
					}
				],
				"documentation_url": "https://docs.github.com/rest/reference/pulls#create-a-pull-request"
			}
		*/
		for _, e := range response.Errors {
			if strings.HasPrefix(e.Message, "A pull request already exists for ") {
				response.AlreadyExists = true
			}
		}
		if !response.AlreadyExists {
			err = fmt.Errorf(
				"response code %v may indicate PR already exists, but the error message is not recognized: %v",
				statusCode,
				response.Errors,
			)
		}

	default:
		err = fmt.Errorf("unexpected http status code: %v", statusCode)
	}
	return
}

func queryGraphQL(pat string, query string, result interface{}) error {
	queryBytes, err := json.Marshal(&struct {
		Query string `json:"query"`
	}{query})
	if err != nil {
		return err
	}

	httpRequest, err := http.NewRequest("POST", "https://api.github.com/graphql", bytes.NewReader(queryBytes))
	if err != nil {
		return err
	}
	httpRequest.SetBasicAuth("", pat)

	return sendJSONRequestSuccessful(httpRequest, result)
}

func mutateGraphQL(pat string, query string) error {
	// Queries and mutations use the same API. But with a mutation, the results aren't useful to us.
	return queryGraphQL(pat, query, &struct{}{})
}

func findExistingPR(b *branch, githubUser string, originOwner string, githubPAT string) (string, error) {
	prQuery := `{
		user(login: "` + githubUser + `") {
			pullRequests(states: OPEN, baseRefName: "` + b.mergeTarget + `", first: 5) {
				nodes {
					title
					id
					headRepositoryOwner {
						login
					}
					baseRepository {
						owner {
							login
						}
					}
				}
			}
		}
	}`
	// Output structure from the query. We pull out some data to make sure our search result is what
	// we expect and avoid relying solely on the search engine query. This may be expanded in the
	// future to search for a specific PR among the search results, if necessary. (Needed if we want
	// to submit multiple, similar PRs from this bot.)
	//
	// Declared adjacent to the query because the query determines the structure.
	result := &struct {
		// Note: Go encoding/json only detects exported properties (capitalized), but it does handle
		// matching it to the lowercase JSON for us.
		Data struct {
			User struct {
				PullRequests struct {
					Nodes []struct {
						Title               string
						ID                  string
						HeadRepositoryOwner struct {
							Login string
						}
						BaseRepository struct {
							Owner struct {
								Login string
							}
						}
					}
					PageInfo struct {
						HasNextPage bool
					}
				}
			}
		}
	}{}

	if err := queryGraphQL(githubPAT, prQuery, result); err != nil {
		return "", err
	}
	fmt.Printf("%+v\n", result)

	// Basic search result validation. We could be more flexible in some cases, but the goal here is
	// to detect an unknown state early so we don't end up doing something strange.

	if prNodes := len(result.Data.User.PullRequests.Nodes); prNodes != 1 {
		return "", fmt.Errorf("expected 1 PR search result, found %v", prNodes)
	}
	if result.Data.User.PullRequests.PageInfo.HasNextPage {
		return "", fmt.Errorf("expected 1 PR search result, but the results say there's another page")
	}

	n := result.Data.User.PullRequests.Nodes[0]
	if headOwner := n.HeadRepositoryOwner.Login; headOwner != githubUser {
		return "", fmt.Errorf("pull request head owner is %v, expected %v", headOwner, githubUser)
	}
	if baseOwner := n.BaseRepository.Owner.Login; baseOwner != originOwner {
		return "", fmt.Errorf("pull request base owner is %v, expected %v", baseOwner, originOwner)
	}

	return n.ID, nil
}
