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
fetch mercurial.deb 'http://security.ubuntu.com/ubuntu/pool/universe/m/mercurial/mercurial_4.5.3-1ubuntu2.2_amd64.deb' 6f5ce6968cc9da1c122b3ec67f47a3e5f7621ec72cd82bed8bacc94faab1682a
fetch mercurial-common.deb 'http://security.ubuntu.com/ubuntu/pool/universe/m/mercurial/mercurial-common_4.5.3-1ubuntu2.2_all.deb' b4e695920304d7fa42c77c671cd77fd4f0ef9c205b81435a31cdb074d682cb17
sudo apt install ./mercurial.deb ./mercurial-common.deb
