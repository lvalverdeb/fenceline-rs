//! Checks that operate on dependency manifests (pyproject.toml,
//! requirements.txt, setup.py, Pipfile) rather than Python source files --
//! mirrors `fenceline/checks/manifest_checks.py`.

use crate::analysis::ParsedFile;
use crate::ast_helpers::skip;
use crate::models::{Confidence, Finding, Severity};
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
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

/// PEP 440 version as an orderable key -- mirrors
/// `manifest_checks._parse_version`. Derived `Ord` compares fields in
/// declaration order, which is exactly the Python tuple's order: epoch,
/// release (trailing `.0` segments dropped, so `1.0 == 1.0.0`), then a
/// stage that orders `.devN < aN/bN/rcN < final < .postN`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    epoch: u64,
    release: Vec<u64>,
    stage: (u8, u64, u64),
}

static VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-._]?(a|b|c|rc|alpha|beta|pre|preview)[-._]?(\d*))?(?:[-._]?(?:post|rev|r)[-._]?(\d*)|-(\d+))?(?:[-._]?dev[-._]?(\d*))?(?:\+[0-9a-z.]+)?$",
    )
    .unwrap()
});

fn pre_tag_rank(tag: &str) -> u64 {
    match tag {
        "a" | "alpha" => 0,
        "b" | "beta" => 1,
        _ => 2,
    }
}

fn parse_version(text: &str) -> Option<Version> {
    let lower = text.trim().to_ascii_lowercase();
    let caps = VERSION_RE.captures(&lower)?;
    let num = |i: usize| caps.get(i).and_then(|m| m.as_str().parse::<u64>().ok());
    let epoch = num(1).unwrap_or(0);
    let mut release: Vec<u64> = caps[2].split('.').map(|x| x.parse().unwrap_or(0)).collect();
    while release.len() > 1 && release.last() == Some(&0) {
        release.pop();
    }
    let stage = if let Some(tag) = caps.get(3) {
        (1, pre_tag_rank(tag.as_str()), num(4).unwrap_or(0))
    } else if caps.get(5).is_some() || caps.get(6).is_some() {
        (3, num(5).or_else(|| num(6)).unwrap_or(0), 0)
    } else if caps.get(7).is_some() {
        (0, num(7).unwrap_or(0), 0)
    } else {
        (2, 0, 0)
    };
    Some(Version {
        epoch,
        release,
        stage,
    })
}

static SPECIFIER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(===|==|~=|>=|<=|!=|<|>)\s*([0-9][0-9A-Za-z.!+\-]*)").unwrap());

enum Constraint {
    Exact(Version),
    Floor(Version),
}

/// What a manifest line says about the version that will be installed --
/// mirrors `_constraint_floor`: `==`/`===` is exact; the highest of
/// `>=`/`>`/`~=` is a floor; nothing when the line pins nothing.
fn constraint_floor(line: &str) -> Option<Constraint> {
    let mut exact = None;
    let mut floor: Option<Version> = None;
    for caps in SPECIFIER_RE.captures_iter(line) {
        let Some(v) = parse_version(&caps[2]) else {
            continue;
        };
        match &caps[1] {
            "==" | "===" => exact = Some(v),
            ">=" | ">" | "~=" => {
                floor = Some(match floor {
                    Some(f) if f > v => f,
                    _ => v,
                })
            }
            _ => {}
        }
    }
    exact
        .map(Constraint::Exact)
        .or(floor.map(Constraint::Floor))
}

static DIST_SEP_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[-_.]+").unwrap());

/// PEP 503 normalised distribution name.
fn normalize_dist(name: &str) -> String {
    DIST_SEP_RE
        .replace_all(&name.trim().to_ascii_lowercase(), "-")
        .into_owned()
}

/// Lockfile -> the manifest that owns it. Only the owner reports lockfile
/// findings, so a requirements.txt next to pyproject.toml + uv.lock doesn't
/// produce the same finding twice.
const LOCK_OWNERS: &[(&str, &str)] = &[
    ("uv.lock", "pyproject.toml"),
    ("poetry.lock", "pyproject.toml"),
    ("Pipfile.lock", "Pipfile"),
];

static TOML_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^name\s*=\s*"([^"]+)""#).unwrap());
static TOML_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^version\s*=\s*"([^"]+)""#).unwrap());

/// `{normalised name: (version, line)}` for every package a lockfile
/// resolves -- mirrors `_locked_versions`. `uv.lock`/`poetry.lock` are
/// `[[package]]` TOML blocks with `name`/`version` lines; `Pipfile.lock` is
/// JSON. Line-scanned because the finding needs the line number.
fn locked_versions(lock_path: &Path, lock_lines: &[String]) -> BTreeMap<String, (String, usize)> {
    let mut out = BTreeMap::new();
    if lock_path.file_name().and_then(|n| n.to_str()) == Some("Pipfile.lock") {
        let Ok(data) = serde_json::from_str::<serde_json::Value>(&lock_lines.join("\n")) else {
            return out;
        };
        for section in ["default", "develop"] {
            let Some(packages) = data.get(section).and_then(|s| s.as_object()) else {
                continue;
            };
            for (name, info) in packages {
                let version = info
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim_start_matches('=')
                    .to_string();
                let key =
                    Regex::new(&format!(r#"^\s*"{}"\s*:\s*\{{"#, regex::escape(name))).unwrap();
                let lineno = lock_lines
                    .iter()
                    .position(|l| key.is_match(l))
                    .map(|i| i + 1);
                if let Some(lineno) = lineno
                    && !version.is_empty()
                {
                    out.insert(normalize_dist(name), (version, lineno));
                }
            }
        }
        return out;
    }
    let mut current: Option<(String, usize)> = None;
    for (i, line) in lock_lines.iter().enumerate() {
        let stripped = line.trim();
        if stripped.starts_with('[') {
            current = None;
        } else if let Some(caps) = TOML_NAME_RE.captures(stripped) {
            current = Some((caps[1].to_string(), i + 1));
        } else if let Some((name, name_line)) = current.take()
            && let Some(caps) = TOML_VERSION_RE.captures(stripped)
        {
            out.insert(normalize_dist(&name), (caps[1].to_string(), name_line));
        } else if let Some(c) = current.take() {
            // Not a version line: keep waiting for one within this block.
            current = Some(c);
        }
    }
    out
}

const CVE_ZERO_DAY: &str = "Dependency CVEs are the most common zero-day entry vector — 74% of breaches involve third-party code.";

fn cve_finding(
    pk: &str,
    line: usize,
    snippet: &str,
    confidence: Confidence,
    description: String,
) -> Finding {
    Finding {
        cwe_id: "CWE-1104",
        cwe_name: "Supply Chain — Dependency with Known Vulnerability",
        severity: Severity::High,
        confidence,
        package: String::new(),
        file: pk.to_string(),
        line,
        code_snippet: snippet.to_string(),
        description,
        zero_day_relevance: CVE_ZERO_DAY,
    }
}

/// Findings against the versions a lockfile actually resolves, or `None` if
/// the lockfile yielded nothing usable (the caller then falls back to the
/// manifest's own constraints). `pk` is the lockfile's display path.
fn lockfile_cve_findings(lock_path: &Path, pk: &str) -> Option<Vec<Finding>> {
    let text = std::fs::read_to_string(lock_path).ok()?;
    let lock_lines: Vec<String> = text.lines().map(str::to_string).collect();
    let locked = locked_versions(lock_path, &lock_lines);
    if locked.is_empty() {
        return None;
    }
    let lock_name = lock_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let mut results = Vec::new();
    for entry in VULN_DEPS.iter() {
        let Some((dep_base, max_ver_text)) = entry.dep.split_once('<') else {
            continue;
        };
        let Some(max_ver) = parse_version(max_ver_text) else {
            continue;
        };
        let Some((version, lineno)) = locked.get(&normalize_dist(dep_base)) else {
            continue;
        };
        if parse_version(version).is_some_and(|found| found < max_ver) {
            results.push(cve_finding(
                pk,
                *lineno,
                lock_lines[lineno - 1].trim(),
                Confidence::High,
                format!(
                    "{}: {} (locked at {version} in {lock_name})",
                    entry.dep, entry.cve
                ),
            ));
        }
    }
    Some(results)
}

/// CWE-1104: a dependency pinned or locked to a release with a known CVE
/// (table: `vuln_deps.json`) -- mirrors `check_dependency_cve`.
///
/// When a lockfile sits next to the manifest, the lockfile is what gets
/// installed, so its exact versions are checked and the manifest's own
/// ranges are ignored, with the finding reported on the lockfile line.
/// Without a lockfile the manifest is read on its own terms: an `==` pin
/// below the fixed version is HIGH confidence; a lower bound (`>=`, `~=`)
/// below it is MEDIUM -- a fresh resolve may pick a fixed release, but
/// nothing in the repository guarantees it.
pub fn check_dependency_cve(
    path: &Path,
    pk: &str,
    lines: &[String],
    _tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    if !file_name_is(path, MANIFEST_NAMES_CVE) {
        return vec![];
    }
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let own_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    for (lock_name, owner) in LOCK_OWNERS {
        let lock_path = parent.join(lock_name);
        if !lock_path.is_file() {
            continue;
        }
        let owner = if parent.join(owner).is_file() {
            *owner
        } else {
            MANIFEST_NAMES_CVE
                .iter()
                .copied()
                .filter(|n| parent.join(n).is_file())
                .min()
                .unwrap_or(own_name)
        };
        if own_name != owner {
            return vec![];
        }
        // The lockfile's display path: the manifest's own, with the file name swapped.
        let lock_pk = match pk.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/{lock_name}"),
            None => lock_name.to_string(),
        };
        if let Some(found) = lockfile_cve_findings(&lock_path, &lock_pk) {
            return found;
        }
        break;
    }

    let mut results = Vec::new();
    let content = lines.join("\n").to_lowercase();
    for entry in VULN_DEPS.iter() {
        let Some((dep_base, max_ver_text)) = entry.dep.split_once('<') else {
            continue;
        };
        let dep_base = dep_base.trim();
        let Some(max_ver) = parse_version(max_ver_text) else {
            continue;
        };
        // Word-boundary-safe dependency-name match ("dask" must not match
        // "boti-dask"); the Python lookahead is rewritten without one since
        // both sides only test for a match, never extract it.
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
        for (i, line) in lines.iter().enumerate() {
            if skip(line) || !dep_pattern.is_match(&line.to_lowercase()) {
                continue;
            }
            let Some(constraint) = constraint_floor(line) else {
                continue;
            };
            let (found, exact) = match constraint {
                Constraint::Exact(v) => (v, true),
                Constraint::Floor(v) => (v, false),
            };
            if found >= max_ver {
                continue;
            }
            let (description, confidence) = if exact {
                (format!("{}: {}", entry.dep, entry.cve), Confidence::High)
            } else {
                (
                    format!(
                        "{}: {} — lower bound allows a vulnerable release to resolve; pin or lock above the fixed version",
                        entry.dep, entry.cve
                    ),
                    Confidence::Medium,
                )
            };
            results.push(cve_finding(pk, i + 1, line.trim(), confidence, description));
            break;
        }
    }
    results
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
    _tree: Option<&ParsedFile>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        parse_version(s).unwrap()
    }

    #[test]
    fn parse_version_orders_like_pep_440() {
        let ordered = [
            "1.0.dev1",
            "1.0a1",
            "1.0b2",
            "1.0rc1",
            "1.0",
            "1.0.post1",
            "1.0.1",
            "1.1",
            "2024.1.0",
        ];
        let keys: Vec<Version> = ordered.iter().map(|s| v(s)).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert_eq!(v("1.0"), v("1.0.0"));
        assert!(v("1!0.1") > v("99.0"));
        assert_eq!(v("2.32.3+local"), v("2.32.3"));
        assert!(parse_version("not-a-version").is_none());
    }

    fn cve(dir: &Path, name: &str) -> Vec<Finding> {
        let path = dir.join(name);
        let lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        check_dependency_cve(&path, &format!("proj/{name}"), &lines, None)
    }

    #[test]
    fn reads_uv_lock_instead_of_manifest_ranges() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("pyproject.toml"),
            "[project]\nname = \"x\"\ndependencies = [\"requests>=2.0\"]\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("uv.lock"),
            "[[package]]\nname = \"x\"\nversion = \"0.1\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\ndependencies = [\n    { name = \"urllib3\" },\n]\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.2.0\"\n",
        )
        .unwrap();
        let findings = cve(tmp.path(), "pyproject.toml");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "proj/uv.lock");
        assert_eq!(findings[0].line, 6);
        assert_eq!(findings[0].confidence, Confidence::High);
        assert!(findings[0].description.contains("locked at 2.31.0"));
    }

    #[test]
    fn locked_fixed_version_silences_loose_range_and_only_owner_reports() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("pyproject.toml"),
            "dependencies = [\"requests>=2.0\"]\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("requirements.txt"), "requests==2.31.0\n").unwrap();
        std::fs::write(
            tmp.path().join("uv.lock"),
            "[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\n",
        )
        .unwrap();
        assert!(cve(tmp.path(), "pyproject.toml").is_empty());
        assert!(cve(tmp.path(), "requirements.txt").is_empty());
    }

    #[test]
    fn reads_pipfile_lock() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Pipfile"), "[packages]\nrequests = \"*\"\n").unwrap();
        std::fs::write(
            tmp.path().join("Pipfile.lock"),
            "{\n  \"default\": {\n    \"requests\": {\n      \"version\": \"==2.31.0\"\n    }\n  }\n}\n",
        )
        .unwrap();
        let findings = cve(tmp.path(), "Pipfile");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "proj/Pipfile.lock");
        assert_eq!(findings[0].line, 3);
    }

    #[test]
    fn manifest_only_distinguishes_pin_from_floor() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("requirements.txt"),
            "requests==2.31.0\nurllib3>=1.26.0\njinja2>=3.1.5\nwerkzeug<4\n",
        )
        .unwrap();
        let findings = cve(tmp.path(), "requirements.txt");
        let by_line: BTreeMap<usize, &Finding> = findings.iter().map(|f| (f.line, f)).collect();
        assert_eq!(by_line[&1].confidence, Confidence::High);
        assert_eq!(by_line[&2].confidence, Confidence::Medium);
        assert!(by_line[&2].description.contains("lower bound"));
        assert!(!by_line.contains_key(&3));
        assert!(!by_line.contains_key(&4));
    }
}
