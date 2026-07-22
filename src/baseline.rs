//! Baseline support: snapshot current findings so a later scan only reports
//! and fails on *new* findings -- mirrors `fenceline/baseline.py`.

use crate::models::Finding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// `(cwe_id, file, code_snippet)` -- deliberately not line number, so the
/// baseline still matches after unrelated edits elsewhere in the file shift
/// line numbers.
pub type Fingerprint = (String, String, String);

fn fingerprint(f: &Finding) -> Fingerprint {
    (f.cwe_id.to_string(), f.file.clone(), f.code_snippet.clone())
}

#[derive(Serialize, Deserialize)]
struct BaselineData {
    fingerprints: Vec<(String, String, String)>,
}

pub fn write_baseline(findings: &[Finding], path: &Path) -> std::io::Result<()> {
    let fingerprints: BTreeSet<Fingerprint> = findings.iter().map(fingerprint).collect();
    let data = BaselineData {
        fingerprints: fingerprints.into_iter().collect(),
    };
    let mut text = serde_json::to_string_pretty(&data).unwrap();
    text.push('\n');
    std::fs::write(path, text)
}

pub fn load_baseline(path: &Path) -> std::io::Result<BTreeSet<Fingerprint>> {
    let text = std::fs::read_to_string(path)?;
    let data: BaselineData = serde_json::from_str(&text).unwrap_or(BaselineData {
        fingerprints: Vec::new(),
    });
    Ok(data.fingerprints.into_iter().collect())
}

/// Returns `(new_findings, suppressed_count)` -- a finding whose fingerprint
/// is already in `baseline` is pre-existing debt, not new.
pub fn split_by_baseline(
    findings: Vec<Finding>,
    baseline: &BTreeSet<Fingerprint>,
) -> (Vec<Finding>, usize) {
    let mut new = Vec::new();
    let mut suppressed = 0;
    for f in findings {
        if baseline.contains(&fingerprint(&f)) {
            suppressed += 1;
        } else {
            new.push(f);
        }
    }
    (new, suppressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, Severity};

    fn sample_finding(file: &str, snippet: &str) -> Finding {
        Finding {
            cwe_id: "CWE-502",
            cwe_name: "Deserialization of Untrusted Data",
            severity: Severity::Critical,
            package: "pkg".to_string(),
            file: file.to_string(),
            line: 1,
            code_snippet: snippet.to_string(),
            description: "unsafe".to_string(),
            zero_day_relevance: "",
            confidence: Confidence::High,
        }
    }

    #[test]
    fn write_then_load_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("baseline.json");
        let findings = vec![sample_finding("a.py", "pickle.loads(x)")];
        write_baseline(&findings, &path).unwrap();
        let loaded = load_baseline(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains(&(
            "CWE-502".to_string(),
            "a.py".to_string(),
            "pickle.loads(x)".to_string()
        )));
    }

    #[test]
    fn split_by_baseline_separates_new_from_preexisting() {
        let baseline: BTreeSet<Fingerprint> = [(
            "CWE-502".to_string(),
            "a.py".to_string(),
            "pickle.loads(x)".to_string(),
        )]
        .into_iter()
        .collect();
        let findings = vec![
            sample_finding("a.py", "pickle.loads(x)"),
            sample_finding("b.py", "pickle.loads(y)"),
        ];
        let (new, suppressed) = split_by_baseline(findings, &baseline);
        assert_eq!(suppressed, 1);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].file, "b.py");
    }

    #[test]
    fn fingerprint_ignores_line_number() {
        let baseline: BTreeSet<Fingerprint> = [(
            "CWE-502".to_string(),
            "a.py".to_string(),
            "pickle.loads(x)".to_string(),
        )]
        .into_iter()
        .collect();
        let mut f = sample_finding("a.py", "pickle.loads(x)");
        f.line = 999;
        let (new, suppressed) = split_by_baseline(vec![f], &baseline);
        assert_eq!(suppressed, 1);
        assert!(new.is_empty());
    }
}
