//! Conformance runner for the vendored fixture corpus (mirrors
//! `fenceline/tests/test_fixtures.py`): every
//! `fixtures/<check_fn_name>/case_*.py` + `case_*.expected.json` pair is run
//! through the real check function and diffed on `cwe_id`/`severity`/
//! `confidence`/`line` -- the fields a port must reproduce exactly. Message
//! text is not compared (allowed to differ, per RUST_PORT_PROPOSAL.md §5).

use fenceline::checks::checks_by_name;
use fenceline::models::{Confidence, Finding, Severity};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
    let checks: HashMap<&str, _> = checks_by_name().into_iter().collect();
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
        let Some(&check_fn) = checks.get(check_name.as_str()) else {
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
            let fake_path = Path::new(&path_name);

            let lines: Vec<String> = source.lines().map(str::to_string).collect();
            let tree = if fake_path.extension().and_then(|e| e.to_str()) == Some("py") {
                match rustpython_parser::parse(&source, rustpython_parser::Mode::Module, &path_name)
                {
                    Ok(rustpython_ast::Mod::Module(m)) => Some(m),
                    _ => None,
                }
            } else {
                None
            };

            let findings = check_fn(fake_path, &path_name, &lines, tree.as_ref());
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
