#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

# Print the purpose of the script and how to use it.
usage() {
  echo "$0 builds and runs a tool defined in 'eng/_util/cmd'.

Usage: $0 <tool> [arguments...]

Builds 'eng/_util/cmd/{tool}/{tool}.go' and runs it using the list of
arguments. If necessary, this command automatically installs Go and downloads
the dependencies of the 'eng/_util' module.

Every tool accepts a '-h' argument to show tool usage help.

Possible tool commands:"
  for x in $toolroot/cmd/*; do
    echo "  $0 ${x##*/}"
  done
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
toolroot="$scriptroot/_util"

if [ ! "${1:-}" ]; then
  exit_error "No tool specified."
fi

# Take the first arg as the tool name. The remaining args ($@) will be passed into the tool.
tool=$1
shift

tool_src="$toolroot/cmd/$tool"
tool_output="$scriptroot/artifacts/toolbin/$tool"

if [ ! -d "$tool_src" ]; then
  exit_error "Tool doesn't exist: '$tool_src'."
fi

. "$scriptroot/init-stage0.sh"
PATH="$PATH:$stage0_dir/go/bin"

(
  # Move into module so "go build" detects it and fetches dependencies.
  cd "$toolroot"
  "$stage0_dir/go/bin/go" build -o "$tool_output" "./cmd/$tool"

  # Run tools from the root of the repo.
  cd "$scriptroot/.."
  "$tool_output" "$@"
)
