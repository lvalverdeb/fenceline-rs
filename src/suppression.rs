//! Bandit-compatible inline suppression comments -- mirrors
//! `fenceline/suppression.py`.
//!
//! `# nosec` (bare) suppresses every finding on that line; `# nosec
//! CWE-502,CWE-94` suppresses only findings with one of the listed CWE IDs,
//! leaving any other finding on the same line intact.

use crate::models::Finding;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

static NOSEC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)#\s*nosec\b(?:\s+([\w,-]+))?").unwrap());

/// `None`: no `# nosec` comment on this line. `Some(empty set)`: bare
/// `# nosec`, suppress everything. `Some(non-empty set)`: suppress only
/// these CWE IDs.
fn nosec_scope(line: &str) -> Option<HashSet<String>> {
    let captures = NOSEC_RE.captures(line)?;
    let Some(scope) = captures.get(1) else {
        return Some(HashSet::new());
    };
    Some(
        scope
            .as_str()
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(|token| token.to_uppercase())
            .collect(),
    )
}

/// Filters `findings` (all from the same file) against `# nosec` comments in
/// `lines`. Returns `(kept, suppressed_count)`.
pub fn apply_suppressions(findings: Vec<Finding>, lines: &[String]) -> (Vec<Finding>, usize) {
    let mut kept = Vec::new();
    let mut suppressed = 0;
    for f in findings {
        let line_text = if f.line >= 1 && f.line <= lines.len() {
            lines[f.line - 1].as_str()
        } else {
            ""
        };
        let scope = nosec_scope(line_text);
        let keep = match &scope {
            None => true,
            Some(scope) if scope.is_empty() => false,
            Some(scope) => !scope.contains(&f.cwe_id.to_uppercase()),
        };
        if keep {
            kept.push(f);
        } else {
            suppressed += 1;
        }
    }
    (kept, suppressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, Severity};

    fn sample_finding(line: usize) -> Finding {
        Finding {
            cwe_id: "CWE-502",
            cwe_name: "Deserialization of Untrusted Data",
            severity: Severity::Critical,
            package: "pkg".to_string(),
            file: "a.py".to_string(),
            line,
            code_snippet: "pickle.loads(x)".to_string(),
            description: "unsafe".to_string(),
            zero_day_relevance: "",
            confidence: Confidence::High,
        }
    }

    #[test]
    fn bare_nosec_suppresses_everything_on_the_line() {
        let lines = vec!["pickle.loads(x)  # nosec".to_string()];
        let (kept, suppressed) = apply_suppressions(vec![sample_finding(1)], &lines);
        assert!(kept.is_empty());
        assert_eq!(suppressed, 1);
    }

    #[test]
    fn scoped_nosec_only_suppresses_listed_cwe() {
        let lines = vec!["pickle.loads(x)  # nosec CWE-94".to_string()];
        let (kept, suppressed) = apply_suppressions(vec![sample_finding(1)], &lines);
        assert_eq!(kept.len(), 1);
        assert_eq!(suppressed, 0);
    }

    #[test]
    fn scoped_nosec_matching_cwe_suppresses() {
        let lines = vec!["pickle.loads(x)  # nosec CWE-502,CWE-94".to_string()];
        let (kept, suppressed) = apply_suppressions(vec![sample_finding(1)], &lines);
        assert!(kept.is_empty());
        assert_eq!(suppressed, 1);
    }

    #[test]
    fn no_nosec_comment_keeps_finding() {
        let lines = vec!["pickle.loads(x)".to_string()];
        let (kept, suppressed) = apply_suppressions(vec![sample_finding(1)], &lines);
        assert_eq!(kept.len(), 1);
        assert_eq!(suppressed, 0);
    }

    #[test]
    fn out_of_range_line_treated_as_no_comment() {
        let lines: Vec<String> = vec![];
        let (kept, suppressed) = apply_suppressions(vec![sample_finding(1)], &lines);
        assert_eq!(kept.len(), 1);
        assert_eq!(suppressed, 0);
    }
}
