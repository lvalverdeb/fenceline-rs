//! File discovery and reading, used before dispatching to checks -- mirrors
//! `fenceline/scanner.py`.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// fenceline's own check-definition, shared-detection-helper, and
/// reporting files necessarily contain, as string literals, the exact regex
/// patterns / function names / CVE tables their own checks search for
/// elsewhere (e.g. `checks/text_checks.py` defines a pattern to *detect*
/// `pickle.loads()` calls -- that pattern's own source line contains the
/// substring `pickle.loads(` and will match itself). Scanning these files
/// produces guaranteed self-referential false positives, not real findings
/// in application code. `cli.rs`/`scanner.rs`/`config.rs`/`models.rs` are
/// deliberately left scannable: they're plumbing (arg parsing, file I/O,
/// data models), not pattern tables, so real bugs there are still worth
/// catching by self-scan.
///
/// Matched by path suffix (not "is this literally the fenceline package"),
/// so this only ever excludes fenceline's own files, wherever a package
/// root happens to point.
const SELF_SCAN_EXCLUDE: &[&[&str]] = &[
    &["fenceline", "checks", "__init__.py"],
    &["fenceline", "checks", "text_checks.py"],
    &["fenceline", "checks", "ast_checks.py"],
    &["fenceline", "checks", "manifest_checks.py"],
    &["fenceline", "ast_helpers.py"],
    &["fenceline", "reporting.py"],
];

pub fn is_self_scan_exclusion(path: &Path) -> bool {
    let parts: Vec<&str> = path.iter().filter_map(|p| p.to_str()).collect();
    SELF_SCAN_EXCLUDE.iter().any(|pattern| {
        pattern.len() <= parts.len() && parts[parts.len() - pattern.len()..] == **pattern
    })
}

/// Every `.py` file under `root`, sorted for deterministic output --
/// mirrors `scanner.py::_iter_py`'s `sorted(root.rglob("*.py"))`.
pub fn iter_py(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.into_path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "py"))
        .filter(|path| !is_self_scan_exclusion(path))
        .collect()
}

/// Mirrors `scanner.py::_read`: never raises on a malformed/unreadable file
/// -- returns an empty line list instead, same as Python's broad
/// `except Exception: return []`.
pub fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|text| text.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Mirrors `scanner.py::_ast_parse`. Returns `None` on any read or parse
/// failure -- syntax error, unreadable file, or malformed UTF-8 -- matching
/// the fixed version of the Python function (its own `read_text()` call
/// originally caught only `SyntaxError`, which meant a malformed-UTF-8 `.py`
/// file crashed the whole scan rather than being skipped; fixed in the
/// Python source alongside this port, see the fenceline history).
pub fn ast_parse(path: &Path) -> Option<rustpython_ast::ModModule> {
    let source = std::fs::read_to_string(path).ok()?;
    let path_str = path.to_string_lossy();
    match rustpython_parser::parse(&source, rustpython_parser::Mode::Module, &path_str) {
        Ok(rustpython_ast::Mod::Module(module)) => Some(module),
        _ => None,
    }
}

/// Workspace-relative path when possible, absolute otherwise -- mirrors
/// `scanner.py::_rel`.
pub fn rel(path: &Path, workspace_root: Option<&Path>) -> String {
    if let Some(root) = workspace_root
        && let Ok(relative) = path.strip_prefix(root)
    {
        return relative.display().to_string();
    }
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_self_scan_exclusion_matches_by_suffix_not_absolute_path() {
        // Matching is by trailing path parts, not "is this exactly
        // fenceline's installed package" -- so it works the same whether
        // the package root came from the default registry or an explicit
        // --package override pointing at a differently-located checkout.
        assert!(is_self_scan_exclusion(Path::new(
            "/anywhere/src/fenceline/reporting.py"
        )));
        assert!(is_self_scan_exclusion(Path::new(
            "/other/checkout/fenceline/checks/text_checks.py"
        )));
        assert!(!is_self_scan_exclusion(Path::new(
            "/anywhere/src/fenceline/cli.py"
        )));
        assert!(!is_self_scan_exclusion(Path::new(
            "/anywhere/src/boti_data/reporting.py"
        )));
    }

    #[test]
    fn iter_py_excludes_fencelines_own_check_definition_files() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("fenceline");
        std::fs::create_dir_all(pkg.join("checks")).unwrap();
        std::fs::write(pkg.join("checks").join("__init__.py"), "CHECKS = []\n").unwrap();
        std::fs::write(
            pkg.join("checks").join("text_checks.py"),
            "PATTERN = r'pickle.loads('\n",
        )
        .unwrap();
        std::fs::write(pkg.join("checks").join("ast_checks.py"), "# ast checks\n").unwrap();
        std::fs::write(
            pkg.join("checks").join("manifest_checks.py"),
            "# manifest checks\n",
        )
        .unwrap();
        std::fs::write(pkg.join("ast_helpers.py"), "# helpers\n").unwrap();
        std::fs::write(pkg.join("reporting.py"), "# report\n").unwrap();
        // Real plumbing -- must still be scanned.
        std::fs::write(pkg.join("cli.py"), "import sys\n").unwrap();
        std::fs::write(pkg.join("scanner.py"), "import ast\n").unwrap();

        let found: Vec<String> = iter_py(&pkg)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(found, vec!["cli.py".to_string(), "scanner.py".to_string()]);
    }

    #[test]
    fn ast_parse_returns_none_on_malformed_utf8_instead_of_panicking() {
        let tmp = tempfile::tempdir().unwrap();
        let bad_file = tmp.path().join("bad.py");
        std::fs::write(&bad_file, b"import os\nx = '\xff\xfe invalid utf8'\n").unwrap();
        assert!(ast_parse(&bad_file).is_none());
    }

    #[test]
    fn ast_parse_returns_none_on_syntax_error() {
        let tmp = tempfile::tempdir().unwrap();
        let bad_file = tmp.path().join("bad_syntax.py");
        std::fs::write(&bad_file, "def f(:\n").unwrap();
        assert!(ast_parse(&bad_file).is_none());
    }

    #[test]
    fn ast_parse_succeeds_on_valid_python() {
        let tmp = tempfile::tempdir().unwrap();
        let good_file = tmp.path().join("good.py");
        std::fs::write(&good_file, "x = 1\n").unwrap();
        assert!(ast_parse(&good_file).is_some());
    }

    #[test]
    fn rel_returns_relative_path_inside_workspace_root() {
        let root = Path::new("/workspace");
        let path = Path::new("/workspace/pkg/mod.py");
        assert_eq!(rel(path, Some(root)), "pkg/mod.py");
    }

    #[test]
    fn rel_returns_absolute_path_outside_workspace_root() {
        let root = Path::new("/workspace");
        let path = Path::new("/elsewhere/mod.py");
        assert_eq!(rel(path, Some(root)), "/elsewhere/mod.py");
    }

    #[test]
    fn rel_returns_absolute_path_when_no_workspace_root() {
        let path = Path::new("/elsewhere/mod.py");
        assert_eq!(rel(path, None), "/elsewhere/mod.py");
    }
}
