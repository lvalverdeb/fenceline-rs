//! Phase 2 smoke test: proves the plumbing (workspace discovery, package
//! registry, file iteration, AST parsing, report rendering) works end to
//! end. No checks exist yet -- that's Phase 3 -- so this always reports
//! zero findings. Not the real CLI (that's Phase 4, with `clap` and the
//! full flag set `cli.py` has).

use fenceline::config::{default_packages, find_workspace_root};
use fenceline::reporting::print_report;
use fenceline::scanner::{ast_parse, iter_py, read_lines};

fn main() {
    let cwd = std::env::current_dir().expect("cwd must be readable");
    let workspace_root = find_workspace_root(&cwd);
    let packages = default_packages(workspace_root.as_deref());

    println!("workspace root: {workspace_root:?}");
    println!("default packages: {} found", packages.len());

    let mut total_files = 0usize;
    let mut total_parsed = 0usize;
    for (name, root) in &packages {
        let files = iter_py(root);
        for path in &files {
            total_files += 1;
            let lines = read_lines(path);
            let _ = lines.len();
            if ast_parse(path).is_some() {
                total_parsed += 1;
            }
        }
        println!("  {name}: {} files under {}", files.len(), root.display());
    }
    println!("total: {total_files} files, {total_parsed} parsed cleanly");

    let mut no_findings: Vec<fenceline::models::Finding> = Vec::new();
    print_report(&mut no_findings, false, 0, 0);
}
