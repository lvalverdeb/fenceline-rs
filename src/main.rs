use clap::Parser;
use fenceline::cli::{Args, run};

/// Every AST walk in fenceline (the parser's own, the collector's, the
/// taint indexer's) recurses with expression depth, and a generated
/// 20,000-term `1+1+...` chain is a legitimate Python file. Scanning on a
/// thread with a generous stack turns that from a hard abort into a normal
/// run; only the pages actually touched are ever committed.
const SCAN_STACK_BYTES: usize = 512 << 20;

fn main() {
    let args = Args::parse();
    let code = std::thread::Builder::new()
        .name("fenceline-scan".into())
        .stack_size(SCAN_STACK_BYTES)
        .spawn(move || run(&args))
        .expect("spawn scan thread")
        .join()
        .unwrap_or(2);
    std::process::exit(code);
}
