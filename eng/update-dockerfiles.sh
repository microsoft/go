#!/usr/bin/env bash
set -euo pipefail

# This script updates the Microsoft dockerfiles in "/src/microsoft/" based on
# the version data available in "/src/microsoft/versions.json".

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

(
  # Run this script from the /src/microsoft directory, which contains the
  # versions.json file and the Dockerfiles. The upstream script relies on the
  # current working directory.
  cd "$scriptroot/../src/microsoft"

  # Copy templates into the current directory. This puts them in the correct
  # location for "apply-templates.sh" to see them. We don't check in a copy: we
  # want to keep it in sync with upstream's copy and apply some small patches.
  cp "$scriptroot/../"*.template .

  # Make sure "apply-templates.sh" uses our checked-in copy of "jq-template.awk"
  # instead of downloading it on the fly.
  export BASHBREW_SCRIPTS=.

  # Run the upstream "apply-templates.sh", but in this directory. This causes
  # the script to update our Dockerfiles using the data in versions.json.
  # Keeping our own version of the checked-in evaluated templates prevents merge
  # conflicts in generated code when we merge changes from upstream.
  "$scriptroot/../apply-templates.sh" "$@"
)
