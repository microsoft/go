# Developer Guide

This document is a guide for developers who want to contribute to the Microsoft build of Go repository.
It explains how to build the repository, how to work with the Go submodule, and how to use the different tools that help maintain the repository.

This guide is primarily intended for developers working for the Go team at Microsoft, but it can also be useful for external contributors.

## Setting up the repository

### Contributor License Agreement

Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution.
For details, visit https://cla.opensource.microsoft.com.

### Install a Go toolchain

A preexisting Go toolchain is required to bootstrap the build process.
You can use your system's package manager to install Go, download Go from the [official Go website](https://golang.org/dl/), or download a prebuilt version of the Microsoft build Go itself.

The only requirement is that the Go version is high enough for the bootstrap process.
If you attempt to build Go while using a bootstrap Go with a version that is too low, the bootstrap process will fail and ask you to install a newer version.

> [!NOTE]
> The in-support versions of Go found on the [official Go website](https://golang.org/dl/) are always high enough to bootstrap the development branch.
> This is because:
> * The [last two major versions of Go are supported by the Go project](https://go.dev/s/release#release-maintenance). (the Microsoft build of Go has the same policy.)
> * Go N can always be bootstrapped by [both N-1 and N-2](https://tip.golang.org/doc/install/source#go14).

> [!NOTE]
> This repository's `eng/run.ps1` PowerShell script is able to download a correct bootstrapping Go version automatically before building the Microsoft build of Go from source.
> We recommend that Microsoft developers team members be familiar with this script because it is used by our CI.
> However, it isn't necessary to use the script for most work on the Microsoft build of Go patches.
> See the [`eng` Readme](/eng/README.md) for more information about `eng/run.ps1`.

### Install git and the git-go-patch command

This repository heavily relies on advanced Git features to manage the Go submodule, so it is recommended to develop with a local Git clone of the repository rather than other methods, e.g. using the GitHub web interface.

Make sure Git is installed on your system.
You can get Git from your system's package manager or the [official Git website](https://git-scm.com/downloads).

The [`git-go-patch`](https://github.com/microsoft/go-infra/tree/main/cmd/git-go-patch) command is a tool that helps you manage the patches in the `go` submodule.

To install the `git-go-patch` command, run the following command:

```
go install github.com/microsoft/go-infra/cmd/git-go-patch@latest
```

> [!NOTE]
> Make sure `git-go-patch` is accessible in your shell's `PATH` variable.
> You may need to add `$GOPATH/bin` to your `PATH`. Use `go env GOPATH` to locate it.

Then, run the command to see the help documentation:

```
git go-patch -h
```

> [!NOTE]
> `git` detects that our `git-go-patch` executable starts with `git-` and makes it available as `git go-patch`.

### Initialize the submodule and apply patches

The repository uses a [Git submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules) named `go` to store the Go source code.
All the patches that modify the Go source code are stored in the [`patches`](../../patches) directory.

To initialize the submodule and apply the patches, run the following command:

```
git go-patch apply
```

### Build the Go toolchain

You now can edit the `go/src` directory as you would the upstream Go project.
[The upstream "Installing Go from source" instructions](https://go.dev/doc/install/source) apply to the `go` directory and can be used to build and test.
We recommend reading the upstream instructions, but we've included some minimal instructions here to get started.

First, use the following commands to build the Go toolchain using the source in the `go/src` directory:

- On Unix-like systems:
    ```bash
    cd go/src
    ./make.bash
    ```

- On Windows:
    ```bat
    cd go/src
    .\make.bat
    ```

The newly built Go toolchain is available in the `go/bin` directory.
An app built by `go/bin/go` uses the standard library in `go/src`, so changes that you make to the standard library are reflected in the built app.

From now on, when this guide mentions the `go` command, it refers to executing the `go` binary in the `go/bin` directory.

> [!NOTE]
> Rebuilding the Go toolchain from source is not necessary for changes in the Go standard library: changes are immediately reflected in any `go build`, `go test`, or `go run` commands.
> However, if you make changes to the Go toolchain itself (any package under `go/src/cmd`), you do need to rebuild the Go toolchain.

There are different ways to use the new Go toolchain:

- Use the full path to the `go` command.
- Add the full path of `go/bin` to the start of `PATH`.
  - We only recommend setting `PATH` in a specific terminal session, not user-wide or system-wide. The development version of Go will probably contain unstable features that may interfere with your other Go projects.
- Instruct your IDE to use the `go` command. Recommended approach for most development work. See the [IDE setup](#ide-setup) section for more information.

### Test that your environment is set up correctly

To test that your environment is set up correctly, run the following commands, which work the same on all platforms:

```
cd go/src
go version
go test -short ./...
```

## IDE setup

### VS Code

[VS Code](https://code.visualstudio.com/) (Visual Studio Code) is a popular IDE for Go development.
We recommend using the official Go extension for VS Code.
Please refer to the [Go extension documentation](https://code.visualstudio.com/docs/languages/go) for more information on how to set up VS Code for Go development.

#### Using the Go toolchain from the `go` submodule

You can use your build of `go` in VS Code by following these steps:

1. In VS Code, open the command palette.
    - `View` > `Command Palette...`.
    - Default keyboard shortcut: `Ctrl+Shift+P`.
1. Search for `Go: Choose Go environment` and select it.
1. Select `Choose from file browser`.
1. Select the `go` executable in the `go/bin` directory. (On Windows, `go.exe`.)
1. Open the command palette.
1. Search for `Developer: Reload Window` and select it.

## Making changes to `go`

Once the `go` directory is prepared, it is a submodule, a semi-independent Git repository.
Git tracks changes in `go` separately from the main repository.

You can view the changes tracked in `go` by running:

```bash
cd go
git status
```

A Git GUI that supports submodules shows the statuses of both the main repository and the `go` submodule.

> [!NOTE]
> In this section, many commands expect that your console's working directory is somewhere inside the submodule.
> This is indicated by a code sample starting with `cd go`.
> If you use the same console session, you don't need to run the `cd` command again.
>
> The `git go-patch` subcommands don't require that your working directory is in the submodule.
> However, we recommend running them inside the submodule anyway because it makes the workflow less confusing and error-prone.

At this point, you can make changes, run tests, rebuild, and use the built Go toolchain in external projects.
Most of the interesting Go code to modify is in `go/src`.

### Working with `cryptobackend`

Most Microsoft build of Go changes live in `go/src`, but `cryptobackend` has two copies to know about:

* [`cryptobackend`](../../cryptobackend) is the source module in this repository.
* `go/src/vendor/github.com/microsoft/go/cryptobackend` is the copy that gets built into the Go standard library.

If you change cryptobackend code, run `go mod vendor` from `go/src` before running `git go-patch extract`; that copies the source module into `go/src/vendor/github.com/microsoft/go/cryptobackend` and updates the vendor metadata.

The vendored copy has one special rule: it is allowed to import selected `crypto/internal/...` packages because the Microsoft `go` command treats it as part of the standard-library build.
The source module under [`cryptobackend`](../../cryptobackend) does not get that special access when it is built like a normal external module.
See the [`cryptobackend` README](../../cryptobackend/README.md) for more detail.

Once you have made changes that work as you expect, move on to the next step.

### Generating new patch files

After making changes in the `go` directory, you must commit your changes following the standard Git process.
For example:

```bash
cd go
git add . --all
git commit -m "example"
```

This creates a commit with the message "example" in the Git log. 

### Changing existing patch files

Creating new patch files is not always necessary.
It often makes more sense to update an existing patch file because the changes serve the same purpose.
In such cases, you can squash new commits on top of the existing ones to update their contents.
You can also amend commits directly.

Before submitting a PR, check the `patches` directory or submodule history for any existing patches related to the files you're working on.
We prefer to avoid redundant patch files to keep the repository clean and easy to review.

To squash commits, amend them, and more, use a rebase.
We recommend using an [*interactive rebase*](https://git-scm.com/docs/git-rebase#_interactive_mode).
The patching tool can start an interactive rebase session for you.
To do this, run:

```bash
cd go
git go-patch rebase
```

Make sure the rebase is complete before continuing.
If you're unsure, check `git status` in the submodule.

### Updating `patches`

So far, your change only exists inside the `go` submodule's Git state.
To extract your change into a new patch file or update the existing patch files, run:

```bash
cd go
git go-patch extract
```

Each automatically generated patch filename has a serial number prefix followed by a dash-separated commit message.
They are human-readable text files, but you shouldn't edit or rename them manually.

### Submitting changes

When working with the `go` submodule, you may notice that outside the submodule, Git marks the `go` submodule as modified.
It's important to **not** commit this change.

One way to avoid committing the change is to clean up the submodule after completing your work on the patches.
To restore the submodule to its original state, execute the following command:

```bash
git submodule update --init --recursive --checkout
```

This allows you to use `git add .`, `git commit -a`, and similar commands without concern.

If you make a mistake and commit the submodule change, PR tests will fail harmlessly.

> [!NOTE]
> If you use `git add [...]` or a GUI to selectively stage and commit changes, it isn't necessary to clean up the submodule.
> It may be useful to keep the submodule dirty for faster iteration on the patches in response to PR feedback and test results.

Commit the patch file changes.

If you have write access to the `microsoft/go` repository, push the changes to a branch named `dev/<your GitHub username>/<topic>`.
The `dev/` prefix is important, `your GitHub username` isn't as important, and `topic` is unimportant but helps you organize and recognize your own work.

If you don't have write access, use a GitHub fork, and give the branch any name you want.

Submit a GitHub PR with your change.
Include a short description and links to related GitHub issues if any exist.
If you submit the PR to a release branch, add a `[<branch>]` prefix to the PR title, such as `[release-branch.go1.22] Support TLS 1.3`.

### Merging changes

If you don't have write access to `microsoft/go`, wait for a maintainer to review and merge your PR.

If you do have write access, in general, wait for two review approvals before merging your PR.
Exceptions where only one approval is necessary:

* Small documentation updates.
* Backports to release branches without significant changes.

Squash, rebase, and merge-commit merges are all acceptable.
