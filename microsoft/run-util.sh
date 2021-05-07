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
toolroot="$scriptroot/util"

# Print usage information and exit 0 if no error message is provided.
# $1: An error message to display. If provided, this function will exit 1.
usage() {
  exit_code=0

  if [ "${1:-}" ]; then
    echo "Error: $1"
    echo ""
    exit_code=1
  fi

  echo "$0 builds and runs a tool in the 'github.com/microsoft/go/util' Go module, downloading dependencies if necessary."
  echo ""
  echo "Possible tool commands:"
  for x in $toolroot/cmd/*; do
    echo "  $0 ${x##*/}"
  done

  exit "$exit_code"
}

if [ ! "${1:-}" ]; then
  usage "No tool specified."
fi

# Take the first arg as the tool name. The remaining args ($@) will be passed into the tool.
tool=$1
shift

tool_src="$toolroot/cmd/$tool"
tool_output="$scriptroot/artifacts/toolbin/$tool"

if [ ! -d "$tool_src" ]; then
  usage "Tool doesn't exist: '$tool_src'."
fi

. "$scriptroot/init-stage0.sh"
PATH="$PATH:$stage0_dir/go/bin"

(
  # Move into module so "go build" detects it and fetches dependencies.
  cd "$toolroot"
  go build -o "$tool_output" "./cmd/$tool"

  # Run tools from the root of the repo.
  cd "$scriptroot/.."
  "$tool_output" "$@"
)
