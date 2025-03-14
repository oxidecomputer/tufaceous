# Setup shared across Buildomat CI builds.
#
# This file contains environment variables shared across Buildomat CI jobs.

# Color the output for easier readability.
export CARGO_TERM_COLOR=always

# Fail on warnings.
export RUSTFLAGS="-D warnings"

# We only build once, so there's no need to incur the overhead of incremental compilation.
export CARGO_INCREMENTAL=0

# When running on illumos we need to pass an additional runpath that is
# usually configured via ".cargo/config" but the `RUSTFLAGS` env variable
# takes precedence. This path contains oxide specific libraries such as
# libipcc.
if [[ $target_os == "illumos" ]]; then
    RUSTFLAGS="$RUSTFLAGS -C link-arg=-R/usr/platform/oxide/lib/amd64"
fi
