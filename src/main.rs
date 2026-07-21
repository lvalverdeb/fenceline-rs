//! Interim scan driver for Phase 3 validation: runs all 56 ported checks
//! over the default package registry and prints a JSON report, so the
//! output can be diffed side by side against the real Python CLI's
//! `--json` output on the same code. Not the real CLI yet (that's Phase 4,
//! with `clap` and the full flag set `cli.py` has -- `--package`,
//! `--fail-on`, `--confidence-min`, `--baseline`/`--write-baseline`,
//! `# nosec` suppression).

use fenceline::checks::checks;
use fenceline::config::{DEP_MANIFEST_FILES, default_packages, find_workspace_root};
use fenceline::models::Finding;
use fenceline::reporting::print_report;
use fenceline::scanner::{ast_parse, iter_py, read_lines, rel};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Mirrors `cli.py::_find_manifest_files`: walk upward from `root` to
/// `ceiling`, stopping at the first ancestor where any manifest file exists.
fn find_manifest_files(root: &Path, ceiling: Option<&Path>) -> Vec<PathBuf> {
    let mut candidate = Some(root.to_path_buf());
    while let Some(dir) = candidate {
        let found: Vec<PathBuf> = DEP_MANIFEST_FILES
            .iter()
            .map(|name| dir.join(name))
            .filter(|p| p.exists())
            .collect();
        if !found.is_empty() {
            return found;
        }
        if Some(dir.as_path()) == ceiling {
            break;
        }
        candidate = dir.parent().map(PathBuf::from);
    }
    Vec::new()
}

fn main() {
    let cwd = std::env::current_dir().expect("cwd must be readable");
    let workspace_root = find_workspace_root(&cwd);
    let packages = default_packages(workspace_root.as_deref());
    let all_checks = checks();

    let mut path_package: BTreeMap<PathBuf, String> = BTreeMap::new();
    for (name, root) in &packages {
        for path in iter_py(root) {
            path_package.entry(path).or_insert_with(|| name.clone());
        }
        for path in find_manifest_files(root, workspace_root.as_deref()) {
            path_package.entry(path).or_insert_with(|| name.clone());
        }
    }

    let mut all_findings: Vec<Finding> = Vec::new();
    for (path, pkg_name) in &path_package {
        let lines = read_lines(path);
        let tree = if path.extension().is_some_and(|e| e == "py") {
            ast_parse(path)
        } else {
            None
        };
        let pk = rel(path, workspace_root.as_deref());
        for (_, check_fn) in &all_checks {
            for mut f in check_fn(path, &pk, &lines, tree.as_ref()) {
                f.package = pkg_name.clone();
                all_findings.push(f);
            }
        }
    }

    print_report(&mut all_findings, true, 0, 0);
}
