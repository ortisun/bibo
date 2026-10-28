//! The operator command line. See the crate documentation for the commands and the exit codes.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exit = factory_cli::run(
        &args,
        &|name| std::env::var(name).ok(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    ExitCode::from(exit.code())
}
