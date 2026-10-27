#!/bin/sh
# toolchain.sh - turn the official Rust image's toolchain into /opt/rust, without rustup.
#
# Runs once, as root, in the build stage of agent/Dockerfile and verify/Dockerfile. Both images
# call this same file, so they hold the same compiler.
#
#   1. Checks that the base image holds exactly the pinned Rust version.
#   2. Moves the toolchain to /opt/rust. Its programs find their libraries relative to
#      themselves, so they need no rustup and no environment variable.
#   3. Installs clippy and rustfmt from the two archives that the Dockerfile downloaded and
#      checked against a pinned SHA-256 (/tmp/dl/clippy.tar.gz and /tmp/dl/rustfmt.tar.gz).
#      rust-toolchain.toml asks for both components.
#   4. Deletes rustup, the cargo proxies and cargo's registry. Nothing can fetch a toolchain
#      or a crate at run time.
#
# usage: toolchain.sh VERSION
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: toolchain.sh VERSION" >&2
    exit 2
fi
version=$1

set -- /usr/local/rustup/toolchains/"$version"-*
if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
    echo "toolchain.sh: the base image does not hold exactly one Rust $version toolchain" >&2
    exit 1
fi
source_dir=$1
triple=${source_dir##*/}
triple=${triple#"$version"-}

mv "$source_dir" /opt/rust
if ! /opt/rust/bin/rustc --version | grep -q "^rustc $version "; then
    echo "toolchain.sh: rustc does not report version $version" >&2
    exit 1
fi

for component in clippy rustfmt; do
    work=$(mktemp -d)
    tar -xzf "/tmp/dl/$component.tar.gz" -C "$work"
    "$work/$component-$version-$triple/install.sh" \
        --prefix=/opt/rust --components="$component-preview" --disable-ldconfig
    rm -rf "$work"
done
test -x /opt/rust/bin/cargo-clippy
test -x /opt/rust/bin/clippy-driver
test -x /opt/rust/bin/rustfmt
test -x /opt/rust/bin/cargo-fmt

rm -rf /tmp/dl /usr/local/rustup /usr/local/cargo
