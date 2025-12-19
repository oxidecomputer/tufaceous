// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod build;
mod edit;
mod list_targets;
mod show_target;
mod sign;

use std::sync::LazyLock;

use anyhow::Result;
use clap::Parser;
use slog::Drain;
use slog::Logger;

static LOG: LazyLock<Logger> = LazyLock::new(|| {
    let stderr_decorator = slog_term::TermDecorator::new().build();
    let stderr_drain =
        slog_term::FullFormat::new(stderr_decorator).build().fuse();
    let mut builder = slog_envlogger::LogBuilder::new(stderr_drain);
    if let Ok(s) = std::env::var("RUST_LOG") {
        builder = builder.parse(&s);
    } else {
        // Log at the info level by default.
        builder = builder.filter(None, slog::FilterLevel::Info);
    }
    let stderr_drain = builder.build();
    let drain = slog_async::Async::new(stderr_drain).build().fuse();
    Logger::root(drain, slog::o!())
});

#[derive(Debug, Parser)]
enum Command {
    Build(build::Args),
    Edit(edit::Args),
    #[clap(alias = "ls")]
    ListTargets(list_targets::Args),
    #[clap(aliases = ["cat", "show"])]
    ShowTarget(show_target::Args),
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Command::parse();
    match args {
        Command::Build(args) => args.run().await,
        Command::Edit(args) => args.run().await,
        Command::ListTargets(args) => args.run().await,
        Command::ShowTarget(args) => args.run().await,
    }
}
