#!/bin/bash
#:
#: name = "clippy (helios)"
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

banner clippy
ptime -m cargo clippy --all-features --all-targets
RUSTDOCFLAGS="--document-private-items -D warnings" ptime -m cargo doc --workspace --no-deps
