// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gitpr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var client = http.Client{
	Timeout: time.Second * 30,
}

// PRBranch contains information about the specific branch to update. During the sync process,
// more info can be added to this struct to be used later. This struct has methods that help
// calculate derived information such as Git ref names.
type PRBranch struct {
	// Name of the branch to update, without "refs/heads/".
	Name string
	// Purpose of the PR. This is used to generate the PR branch name, "dev/{Purpose}/{Name}".
	Purpose string
}

func (b PRBranch) PRBranch() string {
	return "dev/" + b.Purpose + "/" + b.Name
}

func (b PRBranch) BaseBranchFetchRefspec() string {
	return "refs/heads/" + b.Name + ":refs/heads/" + b.PRBranch()
}

func (b PRBranch) PRBranchFetchRefspec() string {
	return "refs/heads/" + b.PRBranch() + ":refs/heads/" + b.PRBranch()
}

func (b PRBranch) PRPushRefspec() string {
	return b.PRBranch() + ":refs/heads/" + b.PRBranch()
}

// CreateGitHubPR creates the data model that can be sent to GitHub to create a PR for this branch.
func (b PRBranch) CreateGitHubPR(githubUser string) GitHubRequest {
	return GitHubRequest{
		Head: githubUser + ":" + b.PRBranch(),
		Base: b.Name,

		Title: fmt.Sprintf("Update dependencies in `%v`", b.Name),
		Body: fmt.Sprintf(
			"🔃 This is an automatically generated PR updating the version of Go in `%v`.\n\n"+
				"This PR should auto-merge itself when PR validation passes.\n\n",
			b.Name,
		),

		MaintainerCanModify: true,
		Draft:               false,
	}
}

// Remote is a parsed version of a Git Remote. It helps determine how to send a GitHub PR.
type Remote struct {
	url      string
	urlParts []string
}

// ParseRemoteURL takes the URL ("https://github.com/microsoft/go", "git@github.com:microsoft/go")
// and grabs the owner ("microsoft") and repository name ("go"). This assumes the URL follows one of
// these two patterns, or something that's compatible. Returns an initialized 'Remote'.
func ParseRemoteURL(url string) (*Remote, error) {
	r := &Remote{
		url,
		strings.FieldsFunc(url, func(r rune) bool { return r == '/' || r == ':' }),
	}
	if len(r.urlParts) < 3 {
		return r, fmt.Errorf(
			"failed to find 3 parts of Remote url '%v'. Found '%v'. Expected a string separated with '/' or ':', like https://github.com/microsoft/go or git@github.com:microsoft/go",
			r.url,
			r.urlParts,
		)
	}
	fmt.Printf("From repo URL %v, detected %v for the PR target.\n", url, r.urlParts)
	return r, nil
}

func (r Remote) GetOwnerRepo() []string {
	return r.urlParts[len(r.urlParts)-2:]
}

func (r Remote) GetOwner() string {
	return r.GetOwnerRepo()[0]
}

func (r Remote) GetOwnerSlashRepo() string {
	return strings.Join(r.GetOwnerRepo(), "/")
}

// GetUsername queries GitHub for the username associated with a PAT.
func GetUsername(pat string) string {
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

// GitHubRequest is the payload for a GitHub PR creation API call, marshallable as JSON.
type GitHubRequest struct {
	Head                string `json:"head"`
	Base                string `json:"base"`
	Title               string `json:"title"`
	Body                string `json:"body"`
	MaintainerCanModify bool   `json:"maintainer_can_modify"`
	Draft               bool   `json:"draft"`
}

// GitHubResponse is a PR creation response from GitHub. It may represent success or failure.
type GitHubResponse struct {
	// GitHub success response:
	HTMLURL string `json:"html_url"`
	NodeID  string `json:"node_id"`

	// GitHub failure response:
	Message string               `json:"message"`
	Errors  []GitHubRequestError `json:"errors"`

	// AlreadyExists is set to true if the error message says the PR exists. Otherwise, false. For
	// our purposes, a GitHub failure response that indicates a PR already exists is not an error.
	AlreadyExists bool
}

type GitHubRequestError struct {
	Message string `json:"message"`
}

func PostGitHub(ownerRepo string, request GitHubRequest, pat string) (response *GitHubResponse, err error) {
	prSubmitContent, err := json.MarshalIndent(request, "", "")
	fmt.Printf("Submitting payload: %s\n", prSubmitContent)

	httpRequest, err := http.NewRequest("POST", "https://api.github.com/repos/"+ownerRepo+"/pulls", bytes.NewReader(prSubmitContent))
	if err != nil {
		return
	}
	httpRequest.SetBasicAuth("", pat)

	response = &GitHubResponse{}
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
						"resource": "GitHubRequest",
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

func QueryGraphQL(pat string, query string, result interface{}) error {
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

func MutateGraphQL(pat string, query string) error {
	// Queries and mutations use the same API. But with a mutation, the results aren't useful to us.
	return QueryGraphQL(pat, query, &struct{}{})
}

func FindExistingPR(b *PRBranch, githubUser string, originOwner string, githubPAT string) (string, error) {
	prQuery := `{
		user(login: "` + githubUser + `") {
			pullRequests(states: OPEN, baseRefName: "` + b.Name + `", first: 5) {
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

	if err := QueryGraphQL(githubPAT, prQuery, result); err != nil {
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
