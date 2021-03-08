#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

source="${BASH_SOURCE[0]}"

# resolve $SOURCE until the file is no longer a symlink
while [[ -h $source ]]; do
  scriptroot="$( cd -P "$( dirname "$source" )" && pwd )"
  source="$(readlink "$source")"

  # if $source was a relative symlink, we need to resolve it relative to the path where the
  # symlink file was located
  [[ $source != /* ]] && source="$scriptroot/$source"
done

scriptroot="$( cd -P "$( dirname "$source" )" && pwd )"

build=1
test=
pack=

# Print usage information and exit 0 if no error message is provided.
# $1: An error message to display. If provided, this function will exit 1.
usage() {
  exit_code=0

  if [ "${1:-}" ]; then
    echo "Error: $1"
    echo ""
    exit_code=1
  fi

  echo "$0 builds Go, optionally running tests and packing a tar.gz file."
  echo ""
  echo "This script is used by CI for PR validation and building rolling builds, and can be used to reproduce issues in those environments. It downloads and installs a local copy of Go to ensure a consistent version."
  echo ""
  echo "Options:"
  echo "  --skip-build  Disable building Go."
  echo "  --test        Enable running tests."
  echo "  --pack        Enable creating a tar.gz file similar to the official Go binary release."
  echo "  -h|--help     Print this help message and exit."
  echo ""
  echo "Example: Perform a build, run tests on it, and produce a tar.gz file:"
  echo "  $0 --test --pack"

  exit "$exit_code"
}

while [[ $# > 0 ]]; do
  case "$1" in
    --skip-build)
      build=
      ;;
    --test)
      test=1
      ;;
    --pack)
      pack=1
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage "Unexpected argument: $1"
      ;;
  esac

  shift
done

# We need Go installed in order to build Go, but our common build environment
# doesn't have it pre-installed. This CI script installs a consistent, official
# version of Go to a hidden directory in $HOME to handle this. This also makes
# it easier to locally repro issues in CI that involve a specific version of Go.
# The downloaded copy of Go is called the "stage 0" version.
#
# Ideally we could set up stage 0 inside the repository, rather than $HOME. It
# would be easier to clean up stage 0 in dev builds, because an ordinary 'git
# clean ...' would delete it. However, if we try to put stage 0 in the project
# directory, some tests fail:
#
# --- FAIL: TestAllDependencies (6.36s)
#     --- FAIL: TestAllDependencies/std(quick) (1.80s)
#         moddeps_test.go:63: /work/bin/go list -mod=vendor -deps ./...: exit status 1
#             package std/bytes
#                 bytes/bytes.go:10:2: use of internal package internal/bytealg not allowed
#             [...]
#         moddeps_test.go:64: (Run 'go mod vendor' in /work/microsoft/.go-stage-0/go/src to ensure that dependecies have been vendored.)
# FAIL
# FAIL    cmd/internal/moddeps    6.405s
stage0_go_version='1.16'
stage0_go_sha256='013a489ebb3e24ef3d915abe5b94c3286c070dfe0818d5bca8108f1d6e8440d2'
stage0_dir="$HOME/.go-stage-0/$stage0_go_version"

download_complete_indicator="$stage0_dir/.downloaded"

if [ ! -f "$download_complete_indicator" ]; then
  echo "Downloading stage 0 Go compiler and extracting to '$stage0_dir' ..."

  # Clear existing stage0 dir in case it's in a broken state.
  rm -rf "$stage0_dir"
  mkdir -p "$stage0_dir"

  go_tarball="$stage0_dir/go.tar.gz"

  curl -SL --output "$go_tarball" https://golang.org/dl/go${stage0_go_version}.linux-amd64.tar.gz \
    && echo "$stage0_go_sha256  $go_tarball" | sha256sum -c - \
    && tar -C "$stage0_dir" -xzf "$go_tarball" \
    && rm "$go_tarball"

  touch "$download_complete_indicator"

  echo "Done extracting stage 0 Go compiler to '$stage0_dir'"
fi

(
  cd "$scriptroot/../src"
  PATH="$PATH:$stage0_dir/go/bin"

  if [ "$build" ]; then
    echo "Running main build..."
    ./make.bash

    # Build race detection runtime. It's included with the official Go binary distribution.
    echo "Building race runtime..."
    ../bin/go install -race -a std
  fi

  if [ "$test" ]; then
    echo "Running tests..."
    ./run.bash --no-rebuild
  fi

  if [ "$pack" ]; then
    echo "Running pack..."
    "$scriptroot/pack.sh"
  fi
)
