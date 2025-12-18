// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod assemble;
mod sign;

use anyhow::Result;
use clap::Parser;
use slog::Drain;
use slog::Logger;

#[derive(Debug, Parser)]
enum Command {
    Assemble(assemble::Args),
}

#[tokio::main]
async fn main() -> Result<()> {
    let stderr_drain = stderr_env_drain("RUST_LOG");
    let drain = slog_async::Async::new(stderr_drain).build().fuse();
    let _log = Logger::root(drain, slog::o!());

    let args = Command::parse();
    match args {
        Command::Assemble(args) => args.run().await,
    }
}

fn stderr_env_drain(env_var: &str) -> impl Drain<Ok = (), Err = slog::Never> {
    let stderr_decorator = slog_term::TermDecorator::new().build();
    let stderr_drain =
        slog_term::FullFormat::new(stderr_decorator).build().fuse();
    let mut builder = slog_envlogger::LogBuilder::new(stderr_drain);
    if let Ok(s) = std::env::var(env_var) {
        builder = builder.parse(&s);
    } else {
        // Log at the info level by default.
        builder = builder.filter(None, slog::FilterLevel::Info);
    }
    builder.build()
}
