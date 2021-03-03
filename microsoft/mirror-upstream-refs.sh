#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

from='https://go.googlesource.com/go'
to=
dry_run_arg=

# Print usage information and exit 0 if no error message is provided.
# $1: An error message to display. If provided, this function will exit 1.
usage() {
  exit_code=0

  if [ "${1:-}" ]; then
    echo "Error: $1"
    echo ""
    exit_code=1
  fi

  echo "This script mirrors a filtered set of Go branches from the upstream repo and pushes them to a specified target repo."
  echo ""
  echo "Note: Before mirroring, the script deletes all branches matching 'auto-mirror/*'. This ensures the local environment doesn't interfere with the mirror."
  echo ""
  echo "Required options:"
  echo "  --to <repository>  Specifies the target Git repository to push mirrored refs to."
  echo ""
  echo "Optional:"
  echo "  --from <repository>  Mirror the specified repository instead of the default upstream, $from"
  echo "  -n                   Do everything except push the mirroring update to the target repository."
  echo "  -h|--help            Print this help message and exit."
  echo ""
  echo "Example: Perform a dry run of a mirroring operation from the default upstream to microsoft/go:"
  echo "  $0 --to git@github.com:microsoft/go -n"

  exit "$exit_code"
}

while [[ $# > 0 ]]; do
  case "$1" in
    --from)
      from=$2
      shift
      ;;
    --to)
      to=$2
      shift
      ;;
    -n)
      dry_run_arg='-n'
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

[ "$from" ] || { usage "'from' not provided"; }
[ "$to" ] || { usage "'to' not provided"; }

clean_temp_branches() {
  branches=$(git branch --list 'auto-mirror/*')
  if [ "$branches" ]; then
    git branch -D $branches
  fi
}

clean_temp_branches

# Create temp branches for each ref to mirror.
git fetch "$from" \
  refs/heads/master:refs/heads/auto-mirror/master \
  refs/heads/dev.boring*:refs/heads/auto-mirror/dev.boring* \
  refs/heads/release-branch.go*:refs/heads/auto-mirror/release-branch.go*

# Refspecs to be passed to a single git push command.
refspecs=()

# Figure out the refspec for each temp branch.
for b in $(git branch --list 'auto-mirror/*'); do
  target=$b
  target=${target#auto-mirror/}
  target=refs/heads/$target
  refspecs+=("$b:$target")
done

(
  set -x
  git push "$to" "${refspecs[@]}" $dry_run_arg
)

clean_temp_branches
