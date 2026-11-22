//! `zkopa`: builds bundles, issues credentials and feed updates, and proves and verifies
//! requests, with plain files in between.

mod args;
mod files;
mod issuer;
mod policy;
mod request;

use std::{env, process::ExitCode, time::SystemTime};

use anyhow::Context;

use crate::args::{Cli, Command, Parsed};

/// The exit code for a command line that does not parse, as getopt-style tools use.
const USAGE_EXIT: u8 = 2;

fn main() -> anyhow::Result<ExitCode> {
    match args::parse(env::args_os().skip(1)) {
        Ok(Parsed::Run(cli)) => run(cli),
        Ok(Parsed::Help(usage)) => {
            print!("{usage}");
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            eprint!("{error}");
            Ok(ExitCode::from(USAGE_EXIT))
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let now_ms = cli.now_ms.map_or_else(clock_ms, Ok)?;
    match cli.command {
        Command::Keygen { out } => issuer::keygen(&out)?,
        Command::Build(args) => policy::build(args)?,
        Command::Inspect { bundle } => policy::inspect(&bundle)?,
        Command::Eval(args) => policy::eval(args)?,
        Command::Issue(args) => issuer::issue(args)?,
        Command::Feed(args) => issuer::feed(args, now_ms)?,
        Command::Prove(args) => request::prove(args, now_ms)?,
        Command::Verify(args) => {
            if !request::verify(args, now_ms)? {
                return Ok(ExitCode::FAILURE);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn clock_ms() -> anyhow::Result<u64> {
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("the clock is before 1970")?;
    u64::try_from(since_epoch.as_millis()).context("the clock is past year 584 million")
}
