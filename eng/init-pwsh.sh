#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# This script sets up a copy of PowerShell (pwsh command) in $HOME that can run on Linux. This is
# used in CI to set up PowerShell in a container that doesn't have pwsh installed already. It is not
# intended for use on dev machines.

set -euo pipefail

pwsh_version='7.1.3'
pwsh_sha256='9f853fb8f7c7719005bd1054fa13ca4d925c519b893f439dd2574e84503e6a85'
pwsh_url="https://github.com/PowerShell/PowerShell/releases/download/v$pwsh_version/powershell-$pwsh_version-linux-x64.tar.gz"

# pwsh must be installed outside of the Go repo. If it's in the repo, longtest "TestAllDependencies"
# fails. It tries to traverse the pwsh directory and can't handle the "no such file or directory"
# error caused by the symlink in the extracted dir: "libcrypto.so.1.0.0 -> /lib64/libcrypto.so.10".
# Ideally this should be in the repository. Tracked by: https://github.com/microsoft/go/issues/12
pwsh_dir="$HOME/.go-ci-prereq/pwsh/$pwsh_version"
download_complete_indicator="$pwsh_dir/.downloaded"

if [ ! -f "$download_complete_indicator" ]; then
  echo "Downloading PowerShell $pwsh_version and extracting to '$pwsh_dir' ..."

  # Clear existing dir in case it's in a broken state.
  rm -rf "$pwsh_dir"
  mkdir -p "$pwsh_dir"

  tarball="$pwsh_dir/pwsh.tar.gz"

  curl -SL --output "$tarball" "$pwsh_url"
  echo "$pwsh_sha256  $tarball" | sha256sum -c -
  tar -C "$pwsh_dir" -xzf "$tarball"
  rm "$tarball"

  touch "$download_complete_indicator"

  echo "Done extracting to '$pwsh_dir'"
fi
