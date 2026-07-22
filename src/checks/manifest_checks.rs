//! Checks that operate on dependency manifests (pyproject.toml,
//! requirements.txt, setup.py, Pipfile) rather than Python source files --
//! mirrors `fenceline/checks/manifest_checks.py`.

use crate::ast_helpers::skip;
use crate::models::{Confidence, Finding, Severity};
use regex::Regex;
use rustpython_ast::ModModule;
use serde::Deserialize;
use std::path::Path;
use std::sync::LazyLock;

#[derive(Deserialize)]
struct VulnDep {
    dep: String,
    cve: String,
}

/// Loaded once from the same `vuln_deps.json` the Python original loads at
/// runtime (RUST_PORT_PROPOSAL.md §7.3) -- embedded at compile time here
/// rather than read from disk, since a single static binary is the whole
/// point of the port.
static VULN_DEPS: LazyLock<Vec<VulnDep>> =
    LazyLock::new(|| serde_json::from_str(include_str!("../vuln_deps.json")).unwrap());

const MANIFEST_NAMES_CVE: &[&str] = &["pyproject.toml", "requirements.txt", "setup.py", "Pipfile"];
const MANIFEST_NAMES_PINS: &[&str] = &["pyproject.toml", "requirements.txt", "Pipfile"];

fn file_name_is(path: &Path, names: &[&str]) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| names.contains(&n))
}

const LOCKFILE_NAMES: &[&str] = &["uv.lock", "poetry.lock", "Pipfile.lock"];

/// True if a recognized lockfile sits alongside `manifest_path` -- mirrors
/// `manifest_checks.py::_sibling_lockfile_exists`. When a project is
/// locked, the manifest's own loose version ranges only matter at upgrade
/// time (a deliberate, reviewable relock), not at every install/sync,
/// which resolves from the lockfile rather than re-resolving the
/// manifest's ranges.
fn sibling_lockfile_exists(manifest_path: &Path) -> bool {
    let Some(parent) = manifest_path.parent() else {
        return false;
    };
    if LOCKFILE_NAMES.iter().any(|name| parent.join(name).exists()) {
        return true;
    }
    // pip-compile: requirements.txt is itself the generated lockfile, so
    // its presence only counts when *this* manifest isn't that same file.
    manifest_path.file_name().and_then(|n| n.to_str()) != Some("requirements.txt")
        && parent.join("requirements.txt").exists()
}

/// Scan pyproject.toml / requirements.txt / setup.py for known CVEs -- CWE-1104.
pub fn check_dependency_cve(
    path: &Path,
    pk: &str,
    lines: &[String],
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    if !file_name_is(path, MANIFEST_NAMES_CVE) {
        return vec![];
    }
    let mut results = Vec::new();
    let content = lines.join("\n").to_lowercase();

    for entry in VULN_DEPS.iter() {
        let (dep_base, max_ver_str) = match entry.dep.split_once('<') {
            Some((base, ver)) => (base.trim(), ver.trim()),
            None => continue,
        };
        // Word-boundary-safe dependency-name match: a lookahead in the
        // Python original (`(?=...)`), rewritten here without one since
        // Rust's `regex` crate has no lookaround support -- verified safe
        // because both call sites only ever check truthiness, never
        // extract what the lookahead matched (see RUST_PORT_PROPOSAL.md §7.1).
        let pattern = format!(
            r#"(?:^|["'=,\s]){}(?:["':,<>=!\s]|$)"#,
            regex::escape(dep_base)
        );
        let Ok(dep_pattern) = Regex::new(&pattern) else {
            continue;
        };
        if !dep_pattern.is_match(&content) {
            continue;
        }
        let Some(max_ver) = parse_version(max_ver_str) else {
            continue;
        };
        for (i, line) in lines.iter().enumerate() {
            let lineno = i + 1;
            if !dep_pattern.is_match(&line.to_lowercase()) {
                continue;
            }
            let Some(found_ver) = extract_version(line) else {
                continue;
            };
            if found_ver < max_ver {
                results.push(Finding {
                    cwe_id: "CWE-1104",
                    cwe_name: "Supply Chain — Dependency with Known Vulnerability",
                    severity: Severity::High,
                    confidence: Confidence::High,
                    package: String::new(),
                    file: pk.to_string(),
                    line: lineno,
                    code_snippet: line.trim().to_string(),
                    description: format!("{}: {}", entry.dep, entry.cve),
                    zero_day_relevance: "Dependency CVEs are the most common zero-day entry vector — 74% of breaches involve third-party code.",
                });
                break;
            }
        }
    }
    results
}

static VERSION_MATCH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:>=|==|~=|!=|<|>)\s*(\d+\.\d+\.\d+)").unwrap());

fn extract_version(line: &str) -> Option<(u32, u32, u32)> {
    let caps = VERSION_MATCH_RE.captures(line)?;
    parse_version(&caps[1])
}

fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

static LOWER_BOUND_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["']([\w.-]+)\s*>=\s*(\d+\.\d+(?:\.\d+)?)["']"#).unwrap());
static HAS_UPPER_BOUND_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s*<\s*").unwrap());
static MULTI_UPPER_BOUND_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r",\s*<\s*").unwrap());

/// CVE-2026-42208 pattern: `>=<version>` without an upper bound allows pip
/// to resolve to a compromised wheel.
pub fn check_unbounded_pins(
    path: &Path,
    pk: &str,
    lines: &[String],
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    if !file_name_is(path, MANIFEST_NAMES_PINS) {
        return vec![];
    }
    let locked = sibling_lockfile_exists(path);
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let lineno = i + 1;
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        let Some(caps) = LOWER_BOUND_RE.captures(stripped) else {
            continue;
        };
        let dep_name = &caps[1];
        let version = &caps[2];
        if dep_name == "python" || dep_name == "requires-python" {
            continue;
        }
        if HAS_UPPER_BOUND_RE.is_match(stripped) {
            continue;
        }
        if MULTI_UPPER_BOUND_RE.is_match(stripped) {
            continue;
        }
        let description = if locked {
            format!(
                "'{dep_name}>={version}' has no upper bound, but a lockfile alongside this manifest means installs resolve from the lockfile, not this range directly — the residual risk is at upgrade-time review (`lock --upgrade` or equivalent), not silent install-time drift. Still worth bounding for when that upgrade happens."
            )
        } else {
            format!(
                "'{dep_name}>={version}' has no upper bound — pip resolves to latest matching version. A compromised wheel at a higher version propagates silently. Use '{dep_name}>={version},<next_major' to bound."
            )
        };
        results.push(Finding {
            cwe_id: "CWE-1104",
            cwe_name: "Supply Chain — Unbounded Dependency Pin",
            severity: if locked { Severity::Info } else { Severity::Low },
            confidence: Confidence::default(),
            package: String::new(),
            file: pk.to_string(),
            line: lineno,
            code_snippet: stripped.to_string(),
            description,
            zero_day_relevance: "CVE-2026-42208: litellm>=1.61.3 with no upper bound led to a .pth backdoor via transitive dep (semantic-router).",
        });
    }
    results
}
