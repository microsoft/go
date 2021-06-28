#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

# Print the purpose of the script and how to use it.
usage() {
  echo "$0 builds and runs a tool defined in a module in 'eng'.

To run a tool:
  $0 <tool> [arguments...]

To list possible tools:
  $0

Builds 'eng/<module>/cmd/<tool>/<tool>.go' and runs it using the list of
arguments. If necessary, this command automatically installs Go and downloads
the dependencies of the module.

Every tool accepts a '-h' argument to show tool usage help.

Possible tool commands:"
  # Search every underscore-prefixed dir (assumed to be a module) for any "cmd" scripts. Use quotes
  # to allow spaces in the repo path.
  for module in "$scriptroot/_"*; do
    echo "  Module ${module##*/}"
    for x in "$module/cmd/"*; do
      echo "    $0 ${x##*/}"
    done
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

if [ ! "${1:-}" ]; then
  exit_error "No tool specified."
fi

# Take the first arg as the tool name. The remaining args ($@) will be passed into the tool.
tool=$1
shift

# Use "for" to expand the wildcard, with quotes to handle spaces. We expect a single match, always.
for tool_src in "$scriptroot/_"*"/cmd/$tool"; do
  tool_module="$tool_src/../.."
done

tool_output="$scriptroot/artifacts/toolbin/$tool"

if [ ! -d "$tool_src" ]; then
  exit_error "Tool doesn't exist: '$tool_src'."
fi

. "$scriptroot/init-stage0.sh"
PATH="$PATH:$stage0_dir/go/bin"

(
  # Move into module so "go build" detects it and fetches dependencies.
  cd "$tool_module"
  echo "Building $tool_src/$tool -> $tool_output"
  "$stage0_dir/go/bin/go" build -o "$tool_output" "./cmd/$tool"
  echo "Building done."
)

(
  # Run tools from the root of the repo.
  cd "$scriptroot/.."
  "$tool_output" "$@"
)
