#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

# Print the purpose of the script and how to use it.
usage() {
  echo "$0 builds Go, optionally running tests and packing a tar.gz file.

Use this script to build Go on your local machine in the way the Microsoft
infrastructure builds it. This script automatically downloads a copy of the Go
compiler (required to build Go) then starts the build. This script is also
capable of running tests and packing a tar.gz file: see Options.

The Microsoft CI infrastructure uses 'microsoft/run-util.sh run-builder', which
runs this script to build Go. If the builder configuration is 'devscript',
run-builder then uses this script to run tests. Otherwise, 'go tool dist test'
is used directly to run tests. (Pass '-h' to run-builder for more info.) The
'devscript' configuration is validated by CI to ensure you can always build and
test locally.

To build and test Go without the Microsoft infrastructure, use the Bash scripts
in 'src' such as 'src/run.bash' instead of this script.

Options:
  --skip-build  Disable building Go.
  --test        Enable running tests.
  --json        Runs tests with -json flag to emit verbose results in JSON format. For use in CI.
  --pack        Enable creating a tar.gz file similar to the official Go binary release.
  -h|--help     Print this help message and exit.

Example: Perform a build, run tests on it, and produce a tar.gz file:
  $0 --test --pack"
}

# Print an optional error message and general script usage info, then call "exit 1".
# $1: An error message to print.
exit_error() {
  if [ "${1:-}" ]; then
    echo "Error: $1"
    echo ""
  fi

  usage
  exit 1
}

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
      exit
      ;;
    *)
      exit_error "Unexpected argument: $1"
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
