# Setup shared across Buildomat CI builds.
#
# This file contains environment variables shared across Buildomat CI jobs.

# Color the output for easier readability.
export CARGO_TERM_COLOR=always

# Fail on warnings.
export RUSTFLAGS="-D warnings"

# We only build once, so there's no need to incur the overhead of incremental compilation.
export CARGO_INCREMENTAL=0

# aws-lc crypto requires libclang to be available.
HOST_OS=$(uname -s)
if [[ $HOST_OS == "SunOS" ]]; then
    CLANGVER=15
    pfexec pkg install -v build-essential pkg-config "pkg:/ooce/developer/clang-$CLANGVER" || rc=$?
    # 4 means we're already up-to-date.
    if ((rc != 4 && rc != 0 )); then
        echo "Failed to install libclang: exit code $rc"
        exit 1
    fi

    pfexec pkg set-mediator -V $CLANGVER clang llvm
fi
