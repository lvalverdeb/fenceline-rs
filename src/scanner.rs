//! File discovery and reading, used before dispatching to checks -- mirrors
//! `fenceline/scanner.py`.

use rustpython_ast::{Constant, Expr, ModModule, Ranged, StmtExpr, Visitor};
use rustpython_parser::{Mode, Tok, lexer::lex};
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
/// mirrors `scanner.py::_iter_py`.
///
/// `recursive: false` walks only `root` itself (one level), not its
/// subdirectories -- used for the cwd auto-discovery "loose root" package,
/// whose files sit directly in the invoking directory while its
/// subdirectories are already registered as their own separate packages
/// (scanning both would double-count them).
///
/// `exclude` is a list of path-substring patterns (e.g. `"/.venv/"`) to
/// skip, same convention as `scanner.py`'s own `exclude` parameter --
/// lets cwd auto-discovery step around virtualenvs, caches, and vendored
/// dependency trees nested under a scanned directory.
pub fn iter_py(root: &Path, recursive: bool, exclude: &[&str]) -> Vec<PathBuf> {
    let walker = if recursive {
        WalkDir::new(root)
    } else {
        WalkDir::new(root).max_depth(1)
    };
    walker
        .sort_by_file_name()
        .into_iter()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.into_path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "py"))
        .filter(|path| {
            let path_str = path.to_string_lossy();
            !path_str.contains("__pycache__") && !exclude.iter().any(|p| path_str.contains(p))
        })
        .filter(|path| !is_self_scan_exclusion(path))
        .collect()
}

/// The file's text, or empty when unreadable or not valid UTF-8 -- mirrors
/// `scanner.py::_read`'s broad `except Exception: return []` (an empty source
/// yields no lines and no AST, so every check sees nothing).
pub fn read_source(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

pub fn split_lines(source: &str) -> Vec<String> {
    source.lines().map(str::to_string).collect()
}

/// Mirrors `scanner.py::_ast_parse`: `None` on any parse failure.
pub fn parse_source(source: &str, path: &Path) -> Option<ModModule> {
    let path_str = path.to_string_lossy();
    match rustpython_parser::parse(source, Mode::Module, &path_str) {
        Ok(rustpython_ast::Mod::Module(module)) => Some(module),
        _ => None,
    }
}

/// `read_source` + `parse_source` for one path.
pub fn ast_parse(path: &Path) -> Option<ModModule> {
    parse_source(&std::fs::read_to_string(path).ok()?, path)
}

/// Byte ranges of every string-only statement (docstrings and bare `"..."`
/// statements used as block comments), anywhere in the tree.
struct StringStmtCollector {
    ranges: Vec<(usize, usize)>,
}

impl Visitor for StringStmtCollector {
    fn visit_stmt_expr(&mut self, node: StmtExpr) {
        if let Expr::Constant(c) = node.value.as_ref()
            && matches!(c.value, Constant::Str(_))
        {
            let r = c.range();
            self.ranges.push((r.start().to_usize(), r.end().to_usize()));
        }
        self.generic_visit_stmt_expr(node);
    }
}

/// Mirrors `scanner.py::mask_non_code`: the file's lines with every comment
/// and every string-only statement blanked to spaces, so line numbers and
/// columns are preserved exactly. This is the view the line-regex checks
/// scan -- a regex can't tell `os.system(` in code from `os.system(` quoted
/// in a docstring or noted in a trailing comment.
///
/// Non-`.py` files (dependency manifests) are returned unchanged. Comments
/// come from the lexer and are taken as far as it gets on a file it can't
/// fully tokenize; string statements come from `tree` and so are only
/// masked when the file parsed. Trojan Source deliberately keeps scanning
/// the raw lines (see `checks::LineView`).
pub fn mask_non_code(path: &Path, source: &str, tree: Option<&ModModule>) -> Vec<String> {
    if !path.extension().is_some_and(|e| e == "py") {
        return split_lines(source);
    }
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    if let Some(tree) = tree {
        let mut collector = StringStmtCollector { ranges: Vec::new() };
        for stmt in &tree.body {
            collector.visit_stmt(stmt.clone());
        }
        ranges.extend(collector.ranges);
    }
    for item in lex(source, Mode::Module) {
        match item {
            Ok((Tok::Comment(_), range)) => {
                ranges.push((range.start().to_usize(), range.end().to_usize()));
            }
            Ok(_) => {}
            Err(_) => break, // keep whatever was collected before the lexer gave up
        }
    }
    if ranges.is_empty() {
        return split_lines(source);
    }
    ranges.sort_unstable();
    let mut masked = String::with_capacity(source.len());
    let mut idx = 0usize;
    for (pos, ch) in source.char_indices() {
        while idx < ranges.len() && ranges[idx].1 <= pos {
            idx += 1;
        }
        let in_range = idx < ranges.len() && ranges[idx].0 <= pos;
        masked.push(if in_range && ch != '\n' && ch != '\r' {
            ' '
        } else {
            ch
        });
    }
    split_lines(&masked)
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

const TEST_DIR_NAMES: &[&str] = &["tests", "test"];

/// True if `file_path` looks like test code by common pytest convention: a
/// `tests`/`test` directory component, a `test_*.py`/`*_test.py` filename,
/// or `conftest.py` -- mirrors `scanner.py::_is_test_path`.
///
/// Deliberately narrow to these well-established naming conventions —
/// doesn't attempt to recognize codebase-specific "not quite production"
/// directories (e.g. an app's own `evaluation/` benchmark harness), since a
/// name like that means different things in different codebases and
/// guessing wrong risks silently suppressing real production findings
/// under a misleadingly broad match. A project that has its own such
/// directories can name them explicitly via `extra_dir_names` (see
/// `cli.rs`'s `--test-paths` flag) rather than fenceline guessing.
pub fn is_test_path(file_path: &str, extra_dir_names: &[String]) -> bool {
    let normalized = file_path.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').collect();
    let Some((name, dirs)) = parts.split_last() else {
        return false;
    };
    if *name == "conftest.py" {
        return true;
    }
    if name.ends_with(".py") && (name.starts_with("test_") || name.ends_with("_test.py")) {
        return true;
    }
    dirs.iter()
        .any(|part| TEST_DIR_NAMES.contains(part) || extra_dir_names.iter().any(|d| d == part))
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

        let found: Vec<String> = iter_py(&pkg, true, &[])
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(found, vec!["cli.py".to_string(), "scanner.py".to_string()]);
    }

    #[test]
    fn iter_py_non_recursive_only_scans_root_level() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("root.py"), "x = 1\n").unwrap();
        let nested = tmp.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("deep.py"), "y = 2\n").unwrap();

        let found: Vec<String> = iter_py(tmp.path(), false, &[])
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(found, vec!["root.py".to_string()]);
    }

    #[test]
    fn iter_py_exclude_patterns_skip_matching_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let venv = tmp.path().join(".venv").join("lib");
        std::fs::create_dir_all(&venv).unwrap();
        std::fs::write(venv.join("vendored.py"), "x = 1\n").unwrap();
        std::fs::write(tmp.path().join("real.py"), "y = 2\n").unwrap();

        let found: Vec<String> = iter_py(tmp.path(), true, &["/.venv/"])
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(found, vec!["real.py".to_string()]);
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

    fn mask(src: &str) -> Vec<String> {
        let tree = parse_source(src, Path::new("x.py"));
        mask_non_code(Path::new("x.py"), src, tree.as_ref())
    }

    #[test]
    fn mask_blanks_trailing_comment_but_keeps_code_columns() {
        let (code, comment) = ("x = os.system(\"ls\")", "  # os.popen( here is prose");
        let out = mask(&format!("{code}{comment}\n"));
        assert_eq!(out, vec![format!("{code}{}", " ".repeat(comment.len()))]);
    }

    #[test]
    fn mask_blanks_multiline_docstring_and_bare_string_statements() {
        let src = "def f():\n    \"\"\"Example:\n        os.system('rm -rf /')\n    \"\"\"\n    'block comment with pickle.loads('\n    return eval(x)\n";
        let out = mask(src);
        assert!(out[1..5].iter().all(|l| l.trim().is_empty()), "{out:?}");
        assert_eq!(out[5], "    return eval(x)");
        let orig: Vec<usize> = src.lines().map(|l| l.chars().count()).collect();
        let masked: Vec<usize> = out.iter().map(|l| l.chars().count()).collect();
        assert_eq!(orig, masked);
    }

    #[test]
    fn mask_handles_non_ascii_before_a_docstring_end() {
        let (doc, code, comment) = ("\"\"\"héllo wörld\"\"\"", "; y = 1", "  # tail");
        let out = mask(&format!("class C:\n    {doc}{code}{comment}\n"));
        assert_eq!(
            out[1],
            format!(
                "    {}{code}{}",
                " ".repeat(doc.chars().count()),
                " ".repeat(comment.len())
            )
        );
    }

    #[test]
    fn mask_still_blanks_comments_when_file_does_not_parse() {
        let src = "def f(:\n    pass  # subprocess.run(\n";
        let out = mask_non_code(Path::new("x.py"), src, None);
        assert_eq!(
            out[1],
            format!("    pass{}", " ".repeat("  # subprocess.run(".len()))
        );
    }

    #[test]
    fn mask_leaves_non_python_files_untouched() {
        let src = "requests==2.0.0  # pinned\n";
        assert_eq!(
            mask_non_code(Path::new("requirements.txt"), src, None),
            vec![src.trim_end()]
        );
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

    #[test]
    fn is_test_path_recognizes_pytest_conventions() {
        assert!(is_test_path("tests/test_foo.py", &[]));
        assert!(is_test_path("pkg/tests/helpers.py", &[]));
        assert!(is_test_path("pkg/test_foo.py", &[]));
        assert!(is_test_path("pkg/foo_test.py", &[]));
        assert!(is_test_path("pkg/conftest.py", &[]));
        assert!(is_test_path("test/foo.py", &[]));
    }

    #[test]
    fn is_test_path_ignores_production_code() {
        assert!(!is_test_path("pkg/mod.py", &[]));
        assert!(!is_test_path("pkg/attestation.py", &[]));
        assert!(!is_test_path("pkg/testing_utils.py", &[]));
        // "evaluation/" is deliberately NOT recognized by default -- see
        // is_test_path's own doc comment for why a codebase-specific
        // directory name isn't safe to hardcode as a universal
        // "not production" signal.
        assert!(!is_test_path("evaluation/load_test_identify.py", &[]));
    }

    #[test]
    fn is_test_path_recognizes_extra_dir_names_when_given() {
        let extra = vec!["evaluation".to_string()];
        assert!(is_test_path("evaluation/load_test_identify.py", &extra));
        let other = vec!["benchmarks".to_string()];
        assert!(!is_test_path("evaluation/load_test_identify.py", &other));
    }
}
