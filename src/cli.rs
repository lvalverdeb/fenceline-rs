//! CLI argument parsing and the top-level scan pipeline -- mirrors
//! `fenceline/cli.py`.

use crate::baseline::{load_baseline, split_by_baseline, write_baseline};
use crate::checks::checks;
use crate::config::{DEP_MANIFEST_FILES, find_workspace_root, is_secure_path};
use crate::models::{Confidence, Finding, Severity};
use crate::reporting::print_report;
use crate::scanner::{ast_parse, is_test_path, iter_py, read_lines, rel};
use crate::suppression::apply_suppressions;
use clap::{Parser, ValueEnum};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Path-substring patterns skipped while walking a cwd-auto-discovered
/// package's subtree -- mirrors `cli.py::DEFAULT_CWD_EXCLUDES`.
pub const DEFAULT_CWD_EXCLUDES: &[&str] = &[
    "/.venv/",
    "/venv/",
    "/.git/",
    "/__pycache__/",
    "/node_modules/",
    "/build/",
    "/dist/",
    ".egg-info",
    "/.mypy_cache/",
    "/.pytest_cache/",
    "/.ruff_cache/",
    "/.tox/",
    "/site-packages/",
];

/// CWE categories where test-code context (an ephemeral testcontainers
/// password, a test assertion, a hardcoded localhost URL, a small
/// committed fixture read) changes the finding from "real risk" to "not
/// applicable" often enough that treating it identically to a production
/// hit drowns out genuine findings in the same category -- mirrors
/// `cli.py::_TEST_DEPRIORITIZED_CWES`.
const TEST_DEPRIORITIZED_CWES: &[&str] = &["CWE-798", "CWE-617", "CWE-918", "CWE-770"];

const NOISE_DIR_NAMES: &[&str] = &[
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    "site-packages",
];

fn is_noise_dir(name: &str) -> bool {
    name.starts_with('.') || NOISE_DIR_NAMES.contains(&name) || name.ends_with(".egg-info")
}

/// Auto-discovers a `{name: path}` registry from `cwd` for a bare
/// invocation (no `--package` given) -- mirrors `cli.py::discover_cwd_packages`.
/// This is what makes fenceline a generic, pip-install-anywhere tool: a bare
/// invocation scans whatever's actually under the current directory instead
/// of a hardcoded package list.
///
/// Each immediate, non-noise subdirectory of `cwd` containing at least one
/// `.py` file anywhere in its subtree becomes its own named package. `.py`
/// files sitting directly in `cwd` (outside any subdirectory) are grouped
/// into one additional package named after `cwd` itself -- the second
/// return value is that package's name (`None` if there were no such loose
/// files), so the caller can scan it non-recursively and avoid
/// double-scanning the subdirectories already registered on their own.
pub fn discover_cwd_packages(cwd: &Path) -> (BTreeMap<String, PathBuf>, Option<String>) {
    let mut packages: BTreeMap<String, PathBuf> = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(cwd) else {
        return (packages, None);
    };
    let mut dirs: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    dirs.sort();
    for entry in dirs {
        let Some(name) = entry.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !entry.is_dir() || is_noise_dir(name) {
            continue;
        }
        let has_python = walkdir::WalkDir::new(&entry)
            .into_iter()
            .filter_map(|e| e.ok())
            .any(|e| e.path().extension().is_some_and(|ext| ext == "py"));
        if has_python {
            packages.insert(name.to_string(), entry);
        }
    }

    let has_loose_python = std::fs::read_dir(cwd)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .any(|e| e.path().extension().is_some_and(|ext| ext == "py"));

    let mut loose_root_name = None;
    if has_loose_python {
        let resolved = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
        let mut name = resolved
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
            .unwrap_or_else(|| resolved.display().to_string());
        if packages.contains_key(&name) {
            name = format!("{name} (root)");
        }
        packages.insert(name.clone(), cwd.to_path_buf());
        loose_root_name = Some(name);
    }

    (packages, loose_root_name)
}

#[derive(Copy, Clone, Debug, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl FailOn {
    fn severity(self) -> Severity {
        match self {
            FailOn::Critical => Severity::Critical,
            FailOn::High => Severity::High,
            FailOn::Medium => Severity::Medium,
            FailOn::Low => Severity::Low,
            FailOn::Info => Severity::Info,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum ConfidenceMin {
    High,
    Medium,
    Low,
}

impl ConfidenceMin {
    fn confidence(self) -> Confidence {
        match self {
            ConfidenceMin::High => Confidence::High,
            ConfidenceMin::Medium => Confidence::Medium,
            ConfidenceMin::Low => Confidence::Low,
        }
    }
}

/// Zero-day vulnerability scanner for the workspace.
#[derive(Parser, Debug)]
#[command(
    name = "fenceline",
    about = "Zero-day vulnerability scanner for the workspace",
    version
)]
pub struct Args {
    /// JSON output
    #[arg(long)]
    pub json: bool,

    /// Suppress banner
    #[arg(long, short = 'q')]
    pub quiet: bool,

    /// Add a scan target package as NAME=PATH (repeatable). Replaces the cwd
    /// auto-discovered registry entirely when given, rather than adding to
    /// it -- pass one --package per target to scan more than one.
    #[arg(long, value_name = "NAME=PATH")]
    pub package: Vec<String>,

    /// Names to scan from the resolved registry (default: all -- see
    /// --package for how the registry is built)
    #[arg(long, value_name = "NAME", num_args = 0..)]
    pub packages: Option<Vec<String>>,

    /// Exit 1 only when findings at or above this severity exist
    #[arg(long, value_enum, default_value = "high")]
    pub fail_on: FailOn,

    /// Drop findings below this confidence level (default: low, i.e. no filtering)
    #[arg(long, value_enum, default_value = "low")]
    pub confidence_min: ConfidenceMin,

    /// Include findings for CWE categories that are usually noise in test code
    /// (CWE-798, CWE-617, CWE-918, CWE-770) when they occur in a tests/ directory,
    /// test_*.py/*_test.py file, or conftest.py. Off by default; production
    /// code paths are unaffected either way.
    #[arg(long)]
    pub include_tests: bool,

    /// Extra directory names to treat as non-production for the same
    /// CWE-category suppression --include-tests governs, alongside the
    /// built-in tests/test/conftest.py conventions (e.g. --test-paths
    /// evaluation benchmarks). Ignored if --include-tests is also given.
    #[arg(long, value_name = "DIRNAME", num_args = 0..)]
    pub test_paths: Vec<String>,

    /// Only report/fail on findings not already present in this baseline file
    #[arg(long, value_name = "PATH")]
    pub baseline: Option<PathBuf>,

    /// Write current findings to PATH as a baseline (for --baseline on later runs) and exit 0
    #[arg(long, value_name = "PATH")]
    pub write_baseline: Option<PathBuf>,
}

/// Parses repeated `--package NAME=PATH` CLI entries into a registry. Every
/// resolved path is validated with `is_secure_path` against the workspace
/// root (when one was found) and the invoking directory -- mirrors
/// `cli.py::_parse_package_args`. Returns `Err(message)` on a malformed
/// entry or a path outside the allowed roots, for the caller to print to
/// stderr and exit non-zero with, matching argparse's `SystemExit` shape.
fn parse_package_args(
    entries: &[String],
    cwd: &Path,
    workspace_root: Option<&Path>,
) -> Result<BTreeMap<String, PathBuf>, String> {
    let allowed_roots: Vec<&Path> = [workspace_root, Some(cwd)].into_iter().flatten().collect();
    let mut resolved = BTreeMap::new();
    for entry in entries {
        let Some((name, raw_path)) = entry.split_once('=') else {
            return Err(format!("error: --package expects NAME=PATH, got {entry:?}"));
        };
        let (name, raw_path) = (name.trim(), raw_path.trim());
        if name.is_empty() || raw_path.is_empty() {
            return Err(format!("error: --package expects NAME=PATH, got {entry:?}"));
        }
        let joined = cwd.join(raw_path);
        let Ok(candidate) = joined.canonicalize() else {
            return Err(format!(
                "error: --package {entry:?} resolves to {}, which does not exist.",
                joined.display()
            ));
        };
        if !is_secure_path(&candidate, &allowed_roots) {
            return Err(format!(
                "error: --package {entry:?} resolves to {}, which is outside the allowed roots {:?}.",
                candidate.display(),
                allowed_roots
            ));
        }
        resolved.insert(name.to_string(), candidate);
    }
    Ok(resolved)
}

/// Finds dependency manifest files for a package by walking upward from
/// `root` to `ceiling`, stopping at the first ancestor where any manifest
/// file exists -- mirrors `cli.py::_find_manifest_files`.
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

/// Package name for a manifest file, derived from the file's own parent
/// directory rather than which package's upward `find_manifest_files`
/// search happened to reach it first -- mirrors
/// `cli.py::_manifest_package_label`.
///
/// A manifest genuinely local to a package (its parent directory *is* that
/// package's own root) gets that package's name. A manifest shared above
/// every package's root — most commonly the scanned project's own
/// top-level `pyproject.toml`, found by every package's upward walk once
/// it climbs past its own directory — previously got silently attributed
/// to whichever package's `entry().or_insert_with` reached it first, an
/// arbitrary artifact of iteration order rather than anything about the
/// file itself. Falls back to the manifest's own parent directory name,
/// which is always at least traceable to where the file actually lives.
fn manifest_package_label(manifest_path: &Path, packages: &BTreeMap<String, PathBuf>) -> String {
    let parent = manifest_path.parent();
    for (name, root) in packages {
        if Some(root.as_path()) == parent {
            return name.clone();
        }
    }
    parent
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "root".to_string())
}

/// Runs the full scan pipeline and returns the process exit code -- mirrors
/// `cli.py::main`.
pub fn run(args: &Args) -> i32 {
    let cwd = std::env::current_dir().expect("cwd must be readable");
    let workspace_root = find_workspace_root(&cwd);

    // A bare invocation (no --package) must never silently fall back to a
    // hardcoded workspace-specific registry -- instead it auto-discovers
    // whatever's actually under the current directory. --package opts back
    // into an explicit, non-cwd-derived registry.
    let mut non_recursive: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut exclude: &[&str] = &[];
    let mut packages = if args.package.is_empty() {
        let (packages, loose_root_name) = discover_cwd_packages(&cwd);
        exclude = DEFAULT_CWD_EXCLUDES;
        if let Some(name) = loose_root_name {
            non_recursive.insert(name);
        }
        packages
    } else {
        match parse_package_args(&args.package, &cwd, workspace_root.as_deref()) {
            Ok(packages) => packages,
            Err(message) => {
                eprintln!("{message}");
                return 2;
            }
        }
    };

    if packages.is_empty() {
        eprintln!("error: no packages to scan — the resolved package registry is empty");
        return 2;
    }

    if let Some(selected) = &args.packages {
        let unknown: Vec<&String> = selected
            .iter()
            .filter(|n| !packages.contains_key(*n))
            .collect();
        if !unknown.is_empty() {
            let unknown_str: Vec<&str> = unknown.iter().map(|s| s.as_str()).collect();
            let available: Vec<&str> = packages.keys().map(|s| s.as_str()).collect();
            eprintln!(
                "error: unknown package(s): {}. Available: {}",
                unknown_str.join(", "),
                available.join(", ")
            );
            return 2;
        }
        packages = selected
            .iter()
            .map(|name| (name.clone(), packages[name].clone()))
            .collect();
    }

    let all_checks = checks();

    let mut path_package: BTreeMap<PathBuf, String> = BTreeMap::new();
    for (name, root) in &packages {
        let recursive = !non_recursive.contains(name);
        for path in iter_py(root, recursive, exclude) {
            path_package.entry(path).or_insert_with(|| name.clone());
        }
        for path in find_manifest_files(root, workspace_root.as_deref()) {
            path_package
                .entry(path.clone())
                .or_insert_with(|| manifest_package_label(&path, &packages));
        }
    }

    if !args.quiet && !args.json {
        println!("\n  {}", "=".repeat(72));
        println!("  Zero-Day Security Audit — fenceline");
        println!("  CWEs: CWE Top 25 (2025) + OWASP Top 10:2025 + Python Zero-Day Patterns");
        println!(
            "  Scanning {} packages, {} files...",
            packages.len(),
            path_package
                .keys()
                .filter(|p| p.extension().is_some_and(|e| e == "py"))
                .count()
        );
        println!("  {}", "=".repeat(72));
        println!();
    }

    let mut all_findings: Vec<Finding> = Vec::new();
    let mut nosec_suppressed = 0usize;

    for (path, pkg_name) in &path_package {
        let lines = read_lines(path);
        let tree = if path.extension().is_some_and(|e| e == "py") {
            ast_parse(path)
        } else {
            None
        };
        let pk = rel(path, workspace_root.as_deref());

        let mut file_findings = Vec::new();
        for (_, check_fn) in &all_checks {
            for mut f in check_fn(path, &pk, &lines, tree.as_ref()) {
                f.package = pkg_name.clone();
                file_findings.push(f);
            }
        }

        let (kept, suppressed_here) = apply_suppressions(file_findings, &lines);
        nosec_suppressed += suppressed_here;
        all_findings.extend(kept);
    }

    let conf_threshold = args.confidence_min.confidence();
    all_findings.retain(|f| f.confidence <= conf_threshold);

    let mut test_suppressed = 0usize;
    if !args.include_tests {
        let mut kept = Vec::with_capacity(all_findings.len());
        for f in all_findings {
            if TEST_DEPRIORITIZED_CWES.contains(&f.cwe_id)
                && is_test_path(&f.file, &args.test_paths)
            {
                test_suppressed += 1;
            } else {
                kept.push(f);
            }
        }
        all_findings = kept;
    }

    if let Some(write_baseline_path) = &args.write_baseline {
        if let Err(err) = write_baseline(&all_findings, write_baseline_path) {
            eprintln!(
                "error: could not write baseline to {}: {err}",
                write_baseline_path.display()
            );
            return 2;
        }
        print_report(
            &mut all_findings,
            args.json,
            0,
            nosec_suppressed,
            test_suppressed,
        );
        if !args.quiet && !args.json {
            println!(
                "  Wrote baseline with {} finding(s) to {}",
                all_findings.len(),
                write_baseline_path.display()
            );
        }
        return 0;
    }

    let mut baseline_suppressed = 0usize;
    if let Some(baseline_path) = &args.baseline {
        match load_baseline(baseline_path) {
            Ok(baseline_fingerprints) => {
                let (kept, suppressed) = split_by_baseline(all_findings, &baseline_fingerprints);
                all_findings = kept;
                baseline_suppressed = suppressed;
            }
            Err(err) => {
                eprintln!(
                    "error: could not read baseline from {}: {err}",
                    baseline_path.display()
                );
                return 2;
            }
        }
    }

    print_report(
        &mut all_findings,
        args.json,
        baseline_suppressed,
        nosec_suppressed,
        test_suppressed,
    );

    let threshold = args.fail_on.severity();
    let gating = all_findings.iter().any(|f| f.severity <= threshold);
    if gating { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_cwd_packages_registers_each_subdir_containing_python() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir(root.join("pkg_a")).unwrap();
        std::fs::write(root.join("pkg_a").join("mod.py"), "x = 1\n").unwrap();
        std::fs::create_dir_all(root.join("pkg_b").join("nested")).unwrap();
        std::fs::write(root.join("pkg_b").join("nested").join("mod.py"), "y = 2\n").unwrap();
        std::fs::create_dir(root.join("no_python")).unwrap();
        std::fs::write(root.join("no_python").join("readme.txt"), "nothing\n").unwrap();

        let (packages, loose_root_name) = discover_cwd_packages(root);

        assert_eq!(
            packages.keys().cloned().collect::<Vec<_>>(),
            vec!["pkg_a".to_string(), "pkg_b".to_string()]
        );
        assert_eq!(loose_root_name, None);
    }

    #[test]
    fn discover_cwd_packages_groups_loose_root_files_separately() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("loose.py"), "z = 3\n").unwrap();
        std::fs::create_dir(root.join("pkg_a")).unwrap();
        std::fs::write(root.join("pkg_a").join("mod.py"), "x = 1\n").unwrap();

        let (packages, loose_root_name) = discover_cwd_packages(root);

        let expected_name = root
            .canonicalize()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert_eq!(loose_root_name, Some(expected_name.clone()));
        assert!(packages.contains_key("pkg_a"));
        assert!(packages.contains_key(&expected_name));
        assert_eq!(packages[&expected_name], root);
    }

    #[test]
    fn discover_cwd_packages_skips_noise_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for noise in [".venv", "__pycache__", "node_modules", ".git"] {
            std::fs::create_dir(root.join(noise)).unwrap();
            std::fs::write(root.join(noise).join("junk.py"), "# junk\n").unwrap();
        }
        std::fs::create_dir(root.join("real_pkg")).unwrap();
        std::fs::write(root.join("real_pkg").join("mod.py"), "x = 1\n").unwrap();

        let (packages, _) = discover_cwd_packages(root);

        assert_eq!(
            packages.keys().cloned().collect::<Vec<_>>(),
            vec!["real_pkg".to_string()]
        );
    }

    #[test]
    fn manifest_package_label_uses_owning_package_when_manifest_is_local() {
        let packages: BTreeMap<String, PathBuf> = [
            ("evaluation".to_string(), PathBuf::from("/proj/evaluation")),
            ("migrations".to_string(), PathBuf::from("/proj/migrations")),
        ]
        .into_iter()
        .collect();
        let manifest = PathBuf::from("/proj/evaluation/pyproject.toml");
        assert_eq!(manifest_package_label(&manifest, &packages), "evaluation");
    }

    #[test]
    fn manifest_package_label_falls_back_to_parent_dir_name_for_shared_manifest() {
        // Real-world bug report: a manifest shared above every package's own
        // root (the scanned project's top-level pyproject.toml, found by
        // every package's upward search once it climbs past its own
        // directory) must not be attributed to whichever package's
        // entry().or_insert_with reached it first.
        let packages: BTreeMap<String, PathBuf> = [
            ("evaluation".to_string(), PathBuf::from("/proj/evaluation")),
            ("migrations".to_string(), PathBuf::from("/proj/migrations")),
        ]
        .into_iter()
        .collect();
        let manifest = PathBuf::from("/proj/pyproject.toml");
        assert_eq!(manifest_package_label(&manifest, &packages), "proj");
    }
}
