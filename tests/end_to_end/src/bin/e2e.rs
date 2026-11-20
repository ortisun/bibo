//! `e2e`: the command line of the end-to-end harness. `scripts/e2e.sh` calls it.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(factory_e2e::cli::main(&args));
}
