//! Conformance runner for the vendored fixture corpus (mirrors
//! `fenceline/tests/test_fixtures.py`): every
//! `fixtures/<check_fn_name>/case_*.py` + `case_*.expected.json` pair is run
//! through the real check function and diffed on `cwe_id`/`severity`/
//! `confidence`/`line` -- the fields a port must reproduce exactly. Message
//! text is not compared (allowed to differ, per RUST_PORT_PROPOSAL.md §5).

use fenceline::analysis::ParsedFile;
use fenceline::checks::{LineView, checks};
use fenceline::models::{Confidence, Finding, Severity};
use fenceline::scanner::mask_non_code;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Deserialize)]
struct ExpectedFinding {
    cwe_id: String,
    severity: String,
    confidence: String,
    line: usize,
}

#[derive(Deserialize)]
struct ExpectedCase {
    findings: Vec<ExpectedFinding>,
    path_name: Option<String>,
}

fn severity_from_str(s: &str) -> Severity {
    match s {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        "INFO" => Severity::Info,
        other => panic!("unknown severity {other}"),
    }
}

fn confidence_from_str(s: &str) -> Confidence {
    match s {
        "HIGH" => Confidence::High,
        "MEDIUM" => Confidence::Medium,
        "LOW" => Confidence::Low,
        other => panic!("unknown confidence {other}"),
    }
}

fn fingerprint(f: &Finding) -> (String, Severity, Confidence, usize) {
    (f.cwe_id.to_string(), f.severity, f.confidence, f.line)
}

#[test]
fn fixture_corpus_matches_expected_findings() {
    let checks: HashMap<&str, _> = checks().into_iter().map(|c| (c.fn_name, c)).collect();
    let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    assert!(fixtures_dir.is_dir(), "fixtures/ directory must exist");

    let mut case_count = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for check_dir in std::fs::read_dir(&fixtures_dir).unwrap() {
        let check_dir = check_dir.unwrap().path();
        if !check_dir.is_dir() {
            continue;
        }
        let check_name = check_dir.file_name().unwrap().to_str().unwrap().to_string();
        let Some(check) = checks.get(check_name.as_str()) else {
            failures.push(format!(
                "{check_name}: no matching Rust check function registered"
            ));
            continue;
        };

        for entry in std::fs::read_dir(&check_dir).unwrap() {
            let py_path = entry.unwrap().path();
            if py_path.extension().and_then(|e| e.to_str()) != Some("py") {
                continue;
            }
            let stem = py_path.file_stem().unwrap().to_str().unwrap();
            let expected_path = check_dir.join(format!("{stem}.expected.json"));

            if !expected_path.exists() {
                continue;
            }
            case_count += 1;

            let source = std::fs::read_to_string(&py_path).unwrap();
            let expected: ExpectedCase =
                serde_json::from_str(&std::fs::read_to_string(&expected_path).unwrap()).unwrap();
            let path_name = expected
                .path_name
                .clone()
                .unwrap_or_else(|| py_path.file_name().unwrap().to_str().unwrap().to_string());
            // A relative label would resolve against the crate root, where a
            // sibling-lockfile lookup could find real files; anchor it in the
            // fixture's own directory instead (same intent as the Python
            // harness's chdir to an empty tmp dir).
            let fake_path_buf = py_path.with_file_name(&path_name);
            let fake_path = fake_path_buf.as_path();

            let lines: Vec<String> = source.lines().map(str::to_string).collect();
            let tree = if fake_path.extension().and_then(|e| e.to_str()) == Some("py") {
                ParsedFile::parse(&source, fake_path)
            } else {
                None
            };
            // Same dispatch as cli.rs: regex checks see the comment/docstring-masked view.
            let code_lines = mask_non_code(fake_path, &source, tree.as_ref().map(|t| &t.module));
            let view = match check.view {
                LineView::CodeOnly => &code_lines,
                LineView::Raw => &lines,
            };

            let findings = (check.run)(fake_path, &path_name, view, tree.as_ref());
            let mut actual: Vec<_> = findings.iter().map(fingerprint).collect();
            actual.sort();

            let mut expected_fps: Vec<_> = expected
                .findings
                .iter()
                .map(|f| {
                    (
                        f.cwe_id.clone(),
                        severity_from_str(&f.severity),
                        confidence_from_str(&f.confidence),
                        f.line,
                    )
                })
                .collect();
            expected_fps.sort();

            if actual != expected_fps {
                failures.push(format!(
                    "{check_name}/{stem}: expected {expected_fps:?}, got {actual:?}"
                ));
            }
        }
    }

    assert!(
        case_count > 0,
        "expected to discover at least one fixture case"
    );
    assert!(
        failures.is_empty(),
        "{}/{} fixture cases failed:\n{}",
        failures.len(),
        case_count,
        failures.join("\n")
    );
}
