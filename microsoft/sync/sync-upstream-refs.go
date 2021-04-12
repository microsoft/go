// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
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

  go run microsoft/sync/sync-upstream-refs.go -b master -n

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

This script creates a temporary copy of the repository in 'microsoft/artifacts/'
by default. This avoids trampling changes in the user's clone.`

// Files and dirs that upstream may modify, but we want to ignore those modifications and keep our
// changes to them. Normally our files are all in the 'microsoft/' directory, but some files are
// required by GitHub to be in the root of the repo or in the '.github' directory, so we must modify
// them in place and auto-resolve conflicts.
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
var tempGitDir = flag.String("temp-git-dir", filepath.Join(getwd(), "microsoft", "artifacts", "sync-upstream-temp-repo"), "Location to create the temporary Git repo. Must not exist.")

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

	originParts := strings.FieldsFunc(*origin, func(r rune) bool { return r == '/' || r == ':' })
	if len(originParts) < 3 {
		fmt.Println("Error: Failed to find 3 parts of 'origin' url. Expected a string separated with '/' or ':', like https://github.com/microsoft/go or git@github.com:microsoft/go")
		os.Exit(1)
	}
	originOwnerRepo := originParts[len(originParts)-2:]
	originOwnerSlashRepo := strings.Join(originOwnerRepo, "/")
	fmt.Printf("From origin repo URL %v, detected %v for the PR target.\n", *origin, originOwnerSlashRepo)

	if _, err := os.Stat(*tempGitDir); !os.IsNotExist(err) {
		fmt.Printf("Error: Temporary Git dir already exists: %v\n", *tempGitDir)
		os.Exit(1)
	}

	run(exec.Command("git", "init", *tempGitDir))

	var branches []*branch = make([]*branch, 0, len(branchNames))
	for _, b := range branchNames {
		nb := newBranch(b)
		branches = append(branches, &nb)
	}

	{
		c := newGitCommand("fetch", "--no-tags", *upstream)
		for _, b := range branches {
			c.Args = append(c.Args, b.upstreamFetchRefspec())
		}
		run(c)
	}

	{
		c := newGitCommand("fetch", "--no-tags", *origin)
		for _, b := range branches {
			c.Args = append(c.Args, b.originFetchRefspec())
		}
		run(c)
	}

	for _, b := range branches {
		run(newGitCommand("checkout", "auto-merge/"+b.mergeTarget))
		run(newGitCommand("merge", "--no-ff", "--no-commit", "auto-sync/"+b.name))

		// Automatically resolve conflicts in specific project doc files. Use '--no-overlay' to make
		// sure we delete new files in e.g. '.github' that are in upstream but don't exist locally.
		{
			c := newGitCommand("checkout", "--no-overlay", "HEAD", "--")
			c.Args = append(c.Args, autoResolveOurPaths...)
			run(c)
		}

		// If we still have unmerged files, 'git commit' will exit non-zero, causing the script to exit.
		// This prevents the script from pushing a bad merge.
		run(newGitCommand("commit", "-m", "Merge upstream branch '"+b.name+"' into "+b.mergeTarget))

		// Show a summary of which files are in our branch vs. upstream. This is just informational. CI
		// is a better place to *enforce* a low diff: it's more visible, can be fixed up more easily, and
		// doesn't block other branch mirror/merge operations.
		fileDiffCommand := newGitCommand("diff", "--name-status", "auto-sync/"+b.name, "auto-merge/"+b.mergeTarget)
		out, err := fileDiffCommand.CombinedOutput()
		if err != nil {
			panic(err)
		}
		b.fileDiff = string(out)

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
	run(newGitPushCommand(*to, false, mirrorPushRefspecs))

	// Force push the merge branches. If an auto-PR is closed rather than accepted, or if an auto-PR
	// doesn't ever get completed, the branch may contain a stale commit that we can't FF from.
	mergePushRefspecs := make([]string, 0, len(branches))
	for _, b := range branches {
		mergePushRefspecs = append(mergePushRefspecs, b.mergePushRefspec())
	}
	run(newGitPushCommand(*to, true, mergePushRefspecs))

	var prFailed bool

	var githubUser string

	for _, b := range branches {
		var skipReason string
		switch {
		case *dryRun:
			skipReason = "Dry run"

		case *githubPAT == "":
			skipReason = "github-pat not provided"

		case *githubPATReviewer == "":
			// In theory, if we have githubPAT but no reviewer, we can submit the PR but skip
			// reviewing it/enabling auto-merge. However, this doesn't seem very useful.
			skipReason = "github-pat-reviewer not provided"
		}

		if skipReason != "" {
			fmt.Printf("%s: skipping submitting PR for %v -> %v\n", skipReason, b.name, b.mergeTarget)
			continue
		}

		// Lazily get username once for all branches.
		if githubUser == "" {
			githubUser = getUsername(*githubPAT)
			fmt.Printf("User for github-pat is: %v\n", githubUser)
		}

		// Use anonymous function to simplify returning errors in the body. We need to handle the
		// error in a special way to avoid blocking other branches, and this lets us centralize it.
		// Using a closure rather than calling a named function keeps var access simple.
		err := func() error {
			fmt.Printf("PR for %v -> %v: Submitting...\n", b.name, b.mergeTarget)

			// POST the PR. This is considered successful if the PR is created or if we receive a
			// specific error message back from GitHub saying the PR is already created.
			pr, err := postPR(
				originOwnerSlashRepo,
				prRequest{
					Head: githubUser + ":auto-merge/" + b.mergeTarget,
					Base: b.mergeTarget,

					Title: fmt.Sprintf("[`%v`] Merge upstream `%v`", b.mergeTarget, b.name),
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
				},
				*githubPAT,
			)
			fmt.Printf("%+v\n", pr)

			if err != nil {
				return err
			}

			if !pr.AlreadyExists {
				fmt.Printf("Submitted brand new PR: %v\n", pr.HTMLURL)

				fmt.Printf("Approving with second account...\n")
				err = mutateGraphQL(*githubPATReviewer, `mutation {
					addPullRequestReview(input: {pullRequestId: "`+pr.NodeID+`", event: APPROVE, body: "Thanks! Auto-approving."}) {
						clientMutationId
					}
				}`)
				if err != nil {
					return err
				}
			} else {
				fmt.Println("A PR already exists. Attempting to find it...")

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
				// Output structure from the query. We pull out some data to make sure our search
				// result is what we expect and avoid relying solely on the search engine query.
				// This may be expanded in the future to search for a specific PR among the search
				// results, if necessary. (Needed if we want to submit multiple, similar PRs from
				// this bot.)
				result := &struct {
					// Go encoding/json requires exported properties (capitalized) but does handle
					// matching it to the JSON (lowercase) for us.
					Data struct {
						User struct {
							PullRequests struct {
								Nodes []struct {
									Title               string
									Id                  string
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

				if err = queryGraphQL(*githubPAT, prQuery, result); err != nil {
					return err
				}
				fmt.Printf("%+v\n", result)

				// Basic search result validation.
				if prNodes := len(result.Data.User.PullRequests.Nodes); prNodes != 1 {
					return fmt.Errorf("Expected 1 PR search result, found %v.", prNodes)
				}
				if result.Data.User.PullRequests.PageInfo.HasNextPage {
					return fmt.Errorf("Another page of pull request search results found. Expected only one result, much less than one page.")
				}

				n := result.Data.User.PullRequests.Nodes[0]
				if headOwner := n.HeadRepositoryOwner.Login; headOwner != githubUser {
					return fmt.Errorf("PR head owner is %v, expected %v.", headOwner, githubUser)
				}
				if baseOwner := n.BaseRepository.Owner.Login; baseOwner != originOwnerRepo[0] {
					return fmt.Errorf("PR base owner is %v, expected %v.", baseOwner, originOwnerRepo[0])
				}
				// Save the PR ID we found. We need to reapply automerge after the new push.
				pr.NodeID = n.Id
			}

			fmt.Printf("Enabling auto-merge with first account...\n")

			err = mutateGraphQL(*githubPATReviewer, `mutation {
				enablePullRequestAutoMerge(input: {pullRequestId: "`+pr.NodeID+`", mergeMethod: MERGE}) {
					clientMutationId
				}
			}`)
			if err != nil {
				return err
			}

			fmt.Printf("PR for %v -> %v: Done.\n", b.name, b.mergeTarget)
			return nil
		}()

		if err != nil {
			fmt.Println(err)
			prFailed = true
			continue
		}
	}

	if prFailed {
		panic("Failed to submit one or more PRs.")
	}

	fmt.Println("Success.")
}

// getwd gets the current working dir or panics, for easy use in expressions.
func getwd() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return wd
}

// run sets up the command so it logs directly to our stdout/stderr streams, then runs it.
func run(c *exec.Cmd) {
	fmt.Printf("---- Running command: %v %v\n", c.Path, c.Args)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		panic(err)
	}
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

func sendJsonRequest(request *http.Request, response interface{}) (status int, err error) {
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

func sendJsonRequestSuccessful(request *http.Request, response interface{}) error {
	status, err := sendJsonRequest(request, response)
	if err != nil {
		return err
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("Request unsuccessful, http status %v, %v\n", status, http.StatusText(status))
	}
	return nil
}

func getUsername(pat string) string {
	request, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		panic(err)
	}
	request.SetBasicAuth("", pat)

	response := &struct {
		Login string `json:"login"`
	}{}

	if err := sendJsonRequestSuccessful(request, response); err != nil {
		panic(err)
	}

	return response.Login
}

type prRequest struct {
	Head                string `json:"head"`
	Base                string `json:"base"`
	Title               string `json:"title"`
	Body                string `json:"body"`
	MaintainerCanModify bool   `json:"maintainer_can_modify"`
	Draft               bool   `json:"draft"`
}

type prRequestResponse struct {
	// Success:
	HTMLURL string `json:"html_url"`
	NodeID  string `json:"node_id"`

	// Failure:
	Message string           `json:"message"`
	Errors  []prRequestError `json:"errors"`

	// Calculated:
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
	statusCode, err := sendJsonRequest(httpRequest, response)
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
				"Response code %v may indicate PR already exists, but the error message is not recognized: %v",
				statusCode,
				response.Errors,
			)
		}

	default:
		err = fmt.Errorf("Unexpected http status code: %v", statusCode)
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

	return sendJsonRequestSuccessful(httpRequest, result)
}

func mutateGraphQL(pat string, query string) error {
	// Queries and mutations use the same API. But with a mutation, the results aren't useful to us.
	return queryGraphQL(pat, query, &struct{}{})
}
