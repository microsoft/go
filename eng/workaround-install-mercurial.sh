#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# This script downloads Deb packages to install Mercurial on Ubuntu 18.04. It's
# here as a workaround to get Mercurial installed in Azure DevOps containers
# that don't seem to work with more ordinary installation methods. For example,
# 'apt update' fails. We need Mercurial for source control integration tests,
# when running in long mode.

# TODO: Include prereq in Docker image and delete this script. https://github.com/microsoft/go/issues/5

set -euo pipefail

fetch() {
  out=$1
  url=$2
  sum=$3
  curl -SL --output "$out" "$url"
  echo "$sum  $out" | sha256sum -c -
}

# Install mercurial to test Go integration.
fetch mercurial.deb 'http://security.ubuntu.com/ubuntu/pool/universe/m/mercurial/mercurial_4.5.3-1ubuntu2.1_amd64.deb' b78465669b0e3acdebead196881a617091b0acbc0fac488220361225db8642d8
fetch mercurial-common.deb 'http://security.ubuntu.com/ubuntu/pool/universe/m/mercurial/mercurial-common_4.5.3-1ubuntu2.1_all.deb' 537693dae1c193c724da306e3669f8561cff5cf594863b8746c3b44f66a28616
sudo apt install ./mercurial.deb ./mercurial-common.deb
