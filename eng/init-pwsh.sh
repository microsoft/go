#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# This script sets up a copy of PowerShell (pwsh command) in $HOME that can run on Linux. This is
# used in CI to set up PowerShell in a container that doesn't have pwsh installed already. It is not
# intended for use on dev machines.

set -euo pipefail

# Default values for x64.
pwsh_version='7.2.1'
pwsh_sha256='337d9864799ad09b46d261071b9f835f69f078814409bc2681f4cc2857b6bda5'
pwsh_arch='x64'

# 'uname' approach adapted from .NET install script: https://github.com/dotnet/install-scripts/blob/df8f863720a462448ad244f03ffeb619f0631bad/src/dotnet-install.sh#L295-L315
if command -v uname > /dev/null; then
  CPUName=$(uname -m)
  case $CPUName in
    armv*l)
      echo "armv*l was detected, but it is not supported by the microsoft/go build infrastructure."
      exit 1
      ;;
    aarch64|arm64)
      pwsh_sha256='f0d6c9c36d69e1466e5a9412085ef52cafd10b73f862d29479b806279a2975f4'
      pwsh_arch='arm64'
      ;;
  esac
else
  echo "uname command not detected. Assuming $pwsh_arch."
fi

pwsh_url="https://github.com/PowerShell/PowerShell/releases/download/v$pwsh_version/powershell-$pwsh_version-linux-$pwsh_arch.tar.gz"

# pwsh must be installed outside of the Go repo. If it's in the repo, longtest "TestAllDependencies"
# fails. It tries to traverse the pwsh directory and can't handle the "no such file or directory"
# error caused by the symlink in the extracted dir: "libcrypto.so.1.0.0 -> /lib64/libcrypto.so.10".
# Ideally this should be in the repository. Tracked by: https://github.com/microsoft/go/issues/12
pwsh_dir="$HOME/.go-ci-prereq/pwsh/$pwsh_version"
download_complete_indicator="$pwsh_dir/.downloaded"

if [ ! -f "$download_complete_indicator" ]; then
  echo "Downloading PowerShell $pwsh_version and extracting to '$pwsh_dir' ..."
  echo "URL: $pwsh_url"

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
