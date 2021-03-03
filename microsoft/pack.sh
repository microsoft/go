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

artifacts_dir="$scriptroot/artifacts"
mkdir "$artifacts_dir" || :

version=${BUILD_BUILDNUMBER:-dev}
go_tarball="$artifacts_dir/go.$version.tar.gz"

(
  cd "$scriptroot/.."

  set -x

  tar -cz \
    --numeric-owner \
    --transform 's,^,go/,' \
    --exclude=pkg/obj \
    *.txt *.ico *.md AUTHORS CONTRIBUTORS LICENSE PATENTS \
    api bin doc lib misc pkg src test \
    -f "$go_tarball"
)
