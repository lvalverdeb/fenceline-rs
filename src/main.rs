use clap::Parser;
use fenceline::cli::{Args, run};

fn main() {
    let args = Args::parse();
    std::process::exit(run(&args));
}
