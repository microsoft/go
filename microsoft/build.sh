#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

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
test_json=
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
  echo "  --json        Runs tests with -json flag to emit verbose results in JSON format. For use in CI."
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
    --json)
      test_json=1
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

. "$scriptroot/init-stage0.sh"

(
  cd "$scriptroot/../src"
  PATH="$PATH:$stage0_dir/go/bin"

  if [ "$build" ]; then
    echo "Running main build..."
    ./make.bash

    # Build race detection runtime. It's included with the official Go binary distribution. It
    # requires cgo to build.
    if [ "${CGO_ENABLED:-}" != '0' ]; then
      echo "Building race runtime..."
      ../bin/go install -race -a std
    fi
  fi

  if [ "$test" ]; then
    echo "Running tests..."
    if [ "$test_json" ]; then
      # "-json": Get test results as lines of JSON.
      #
      # "2>&1": If we're running in JSON mode, we are probably running under gotestsum, which
      # detects stderr output and prints it as a problem even though we expect it. This could be
      # misleading for someone looking at test results. To avoid this, redirect stderr to stdout.
      # The test script returns a correct exit code, so the redirect doesn't affect overall test
      # success/failure.
      #
      # For example, stderr output is normal when checking for machine capabilities. A Cgo static
      # linking test emits "/usr/bin/ld: cannot find -lc" and then skips the test because that
      # indicates static linking isn't supported with the current build/platform.
      ./run.bash --no-rebuild -json 2>&1
    else
      ./run.bash --no-rebuild
    fi
  fi

  if [ "$pack" ]; then
    echo "Running pack..."
    "$scriptroot/pack.sh"
  fi
)
