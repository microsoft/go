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

artifacts_dir="$scriptroot/artifacts"
test ! -d "$artifacts_dir" && mkdir "$artifacts_dir"

version=${BUILD_BUILDNUMBER:-dev}

(
  cd "$scriptroot/.."

  if [ ! -f bin/go ]; then
    echo "Error: 'bin/go' not found! Build must be complete to pack it. Use build.sh instead."
    exit 1
  fi

  GOOS=$(bin/go env GOOS)
  GOARCH=$(bin/go env GOARCH)
  echo "Detected bin/go built for GOOS=$GOOS, GOARCH=$GOARCH"

  go_tarball="$artifacts_dir/go.$version.$GOOS-$GOARCH.tar.gz"
  go_tarball_excludes="$artifacts_dir/exclude-from-targz.txt"

  echo "Creating $go_tarball ..."

  # Release branches have a 'VERSION' file, others may not. Include if exists.
  test -f VERSION && version_file=VERSION

  # The official Go tar.gz binary distribution is a tar.gz of the Go directory, with a bunch of
  # files removed. Here, match that behavior by creating an exclusion file and passing to 'tar'.

  # Begin the file by excluding general build intermediates.
  echo "pkg/obj" > "$go_tarball_excludes"

  # Exclude the compiler build.
  echo "pkg/${GOOS}_${GOARCH}/cmd" >> "$go_tarball_excludes"

  # Exclude the api checker prebuilt binary.
  echo "pkg/tool/${GOOS}_${GOARCH}/api" >> "$go_tarball_excludes"

  # Exclude prebuilt race detector syso file for all but the current OS/ARCH.
  find src/runtime/race -iname 'race_*.syso' -and ! -iname "race_${GOOS}_${GOARCH}.syso" \
    >> "$go_tarball_excludes"

  # Create the tarball. Pass in the exclusion list, and also be selective in which files/dirs are
  # given as input.
  tar -cz \
    --numeric-owner \
    --transform 's,^,go/,' \
    --exclude-from="$go_tarball_excludes" \
    *.txt *.ico *.md AUTHORS CONTRIBUTORS LICENSE PATENTS \
    api bin doc lib misc pkg src test \
    ${version_file:-} \
    -f "$go_tarball"

  echo "Done!"
)
