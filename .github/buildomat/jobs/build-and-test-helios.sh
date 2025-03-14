#!/bin/bash
#:
#: name = "build-and-test (helios)"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = true
#: output_rules = []

set -o errexit
set -o pipefail
set -o xtrace

# shellcheck source=/dev/null
source .github/buildomat/ci-env.sh

cargo --version
rustc --version
curl -sSfL --retry 10 https://get.nexte.st/latest/illumos | gunzip | tar -xvf - -C ~/.cargo/bin

banner build
ptime -m cargo build

banner build-all
ptime -m cargo build --all-features --all-targets

banner test
ptime -m cargo nextest run --all-features --all-targets

banner doctest
ptime -m cargo test --doc --all-features
