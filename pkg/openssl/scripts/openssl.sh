#!/bin/sh

# openssl.sh is intended for use in a CI workflow to set up various versions of OpenSSL without
# relying on availability in any particular distro's package manager. It downloads the specified
# OpenSSL version, builds it, and configures it for global use on the current machine.

set -eux

version=$1

case "$version" in
    "1.1.0")
        tag="OpenSSL_1_1_0l"
        sha256="e2acf0cf58d9bff2b42f2dc0aee79340c8ffe2c5e45d3ca4533dd5d4f5775b1d"
        config="shared"
        make="build_libs"
        install=""
        ;;
    "1.1.1")
        tag="OpenSSL_1_1_1m"
        sha256="36ae24ad7cf0a824d0b76ac08861262e47ec541e5d0f20e6d94bab90b2dab360"
        config="shared"
        make="build_libs"
        install=""
        ;;
    "3.0.1")
        tag="openssl-3.0.1";
        sha256="2a9dcf05531e8be96c296259e817edc41619017a4bf3e229b4618a70103251d5"
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    "3.0.9")
        tag="openssl-3.0.9";
        sha256="2eec31f2ac0e126ff68d8107891ef534159c4fcfb095365d4cd4dc57d82616ee"
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    "3.0.13")
        tag="openssl-3.0.13";
        sha256="e74504ed7035295ec7062b1da16c15b57ff2a03cd2064a28d8c39458cacc45fc"
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    "3.1.5")
        tag="openssl-3.1.5";
        sha256="299ddfd0a506a6d37de56386d15ce30d344d91884dfc98ab3330b7c009029931"
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    "3.2.1")
        tag="openssl-3.2.1";
        sha256="75cc6803ffac92625c06ea3c677fb32ef20d15a1b41ecc8dddbc6b9d6a2da84c"
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    "3.3.0")
        tag="openssl-3.3.0";
        sha256="1a47bdc46fac256a0dc8efb696f7f76fa5f96049ba1b60fded5478bd3165c6d2"
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    "3.3.1")
        tag="openssl-3.3.1";
        sha256="133bf39b8d1635ac94a8483042cc448251b770a0d12c7af0c05ea895ddd98f1d"
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    *)
        echo >&2 "error: unsupported OpenSSL version '$version'"
        exit 1 ;;
esac

cd /usr/local/src
wget -O "$tag.tar.gz" "https://github.com/openssl/openssl/archive/refs/tags/$tag.tar.gz"
echo "$sha256 $tag.tar.gz" | sha256sum -c -
rm -rf "openssl-$tag"
tar -xzf "$tag.tar.gz"

rm -rf "openssl-$version"
mv "openssl-$tag" "openssl-$version"

cd "openssl-$version"
# -d makes a debug build which helps with debugging memory issues and
# other problems. It's not necessary for normal use.
./config -d $config

make -j$(nproc) $make
if [ -n "$install" ]; then
    make $install
fi

cp -H ./libcrypto.so "/usr/lib/libcrypto.so.${version}"
