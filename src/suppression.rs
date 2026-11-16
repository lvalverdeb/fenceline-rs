//! Inline suppression comments -- mirrors `fenceline/suppression.py`.
//!
//! `# nosec` (bare) suppresses every finding on that line; `# nosec
//! CWE-502,CWE-94` suppresses only findings with one of the listed CWE IDs,
//! leaving any other finding on the same line intact. A Bandit rule code in
//! either comment (`# nosec B608`) or in a Ruff one (`# noqa: S608`)
//! suppresses the fenceline checks that cover the same shape.

use crate::models::Finding;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

static NOSEC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)#\s*nosec\b(?:\s+([\w,-]+))?").unwrap());
static NOQA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)#\s*noqa\s*:\s*([A-Z]+\d+(?:\s*,\s*[A-Z]+\d+)*)").unwrap());
static RULE_CODE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^[SB](\d{3})$").unwrap());

/// Bandit rule numbers (Ruff's `S` codes use the same numbers) and the
/// fenceline CWE IDs that report the same shape -- mirrors `_BANDIT_CWES`.
const BANDIT_CWES: &[(&str, &[&str])] = &[
    ("102", &["CWE-94"]),
    ("104", &["CWE-1327"]),
    ("105", &["CWE-798"]),
    ("106", &["CWE-798"]),
    ("107", &["CWE-798"]),
    ("108", &["CWE-377"]),
    ("110", &["CWE-391", "CWE-778"]),
    ("112", &["CWE-391", "CWE-778"]),
    ("113", &["CWE-1088"]),
    ("201", &["CWE-489"]),
    ("301", &["CWE-502"]),
    ("302", &["CWE-502"]),
    ("303", &["CWE-328", "CWE-327"]),
    ("304", &["CWE-327"]),
    ("305", &["CWE-327"]),
    ("306", &["CWE-377"]),
    ("307", &["CWE-94"]),
    ("308", &["CWE-79"]),
    ("310", &["CWE-918"]),
    ("311", &["CWE-338"]),
    ("313", &["CWE-611"]),
    ("314", &["CWE-611"]),
    ("315", &["CWE-611"]),
    ("316", &["CWE-611"]),
    ("317", &["CWE-611"]),
    ("318", &["CWE-611"]),
    ("319", &["CWE-611"]),
    ("320", &["CWE-611"]),
    ("323", &["CWE-295"]),
    ("324", &["CWE-328", "CWE-327"]),
    ("405", &["CWE-611"]),
    ("406", &["CWE-611"]),
    ("407", &["CWE-611"]),
    ("408", &["CWE-611"]),
    ("409", &["CWE-611"]),
    ("410", &["CWE-611"]),
    ("501", &["CWE-295"]),
    ("502", &["CWE-295"]),
    ("503", &["CWE-295"]),
    ("504", &["CWE-295"]),
    ("506", &["CWE-502"]),
    ("602", &["CWE-78"]),
    ("603", &["CWE-78"]),
    ("604", &["CWE-78"]),
    ("605", &["CWE-78"]),
    ("606", &["CWE-78"]),
    ("607", &["CWE-78"]),
    ("608", &["CWE-89"]),
    ("609", &["CWE-78"]),
    ("701", &["CWE-79"]),
    ("702", &["CWE-79"]),
    ("704", &["CWE-79"]),
];

/// `None`: no `# nosec` comment on this line. `Some(empty set)`: bare
/// `# nosec`, suppress everything. `Some(non-empty set)`: suppress only
/// these tokens.
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

fn expand_rule_codes(tokens: HashSet<String>) -> HashSet<String> {
    let mut out = HashSet::new();
    for token in tokens {
        match RULE_CODE_RE.captures(&token) {
            Some(m) => {
                if let Some((_, cwes)) = BANDIT_CWES.iter().find(|(n, _)| *n == &m[1]) {
                    out.extend(cwes.iter().map(|c| c.to_string()));
                }
            }
            None => {
                out.insert(token);
            }
        }
    }
    out
}

/// `None`: no suppression comment. `Some(empty)`: suppress everything.
/// `Some(set)`: the CWE IDs suppressed on this line -- mirrors
/// `_suppressed_cwes`.
fn suppressed_cwes(line: &str) -> Option<HashSet<String>> {
    let scope = nosec_scope(line);
    if scope.as_ref().is_some_and(|s| s.is_empty()) {
        return Some(HashSet::new());
    }
    let codes: HashSet<String> = NOQA_RE
        .captures(line)
        .map(|m| m[1].split(',').map(|t| t.trim().to_uppercase()).collect())
        .unwrap_or_default();
    if scope.is_none() && codes.is_empty() {
        return None;
    }
    let mut tokens = scope.unwrap_or_default();
    tokens.extend(codes);
    Some(expand_rule_codes(tokens))
}

/// Filters `findings` (all from the same file) against `# nosec` and
/// `# noqa` comments in `lines`. Returns `(kept, suppressed_count)`.
pub fn apply_suppressions(findings: Vec<Finding>, lines: &[String]) -> (Vec<Finding>, usize) {
    let mut kept = Vec::new();
    let mut suppressed = 0;
    for f in findings {
        let line_text = if f.line >= 1 && f.line <= lines.len() {
            lines[f.line - 1].as_str()
        } else {
            ""
        };
        let scope = suppressed_cwes(line_text);
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
    fn bandit_and_ruff_codes_map_to_cwes() {
        let lines = vec!["pickle.loads(x)  # noqa: S301, E501".to_string()];
        let (kept, suppressed) = apply_suppressions(vec![sample_finding(1)], &lines);
        assert!(kept.is_empty());
        assert_eq!(suppressed, 1);
        let lines = vec!["pickle.loads(x)  # nosec B608".to_string()];
        let (kept, _) = apply_suppressions(vec![sample_finding(1)], &lines);
        assert_eq!(kept.len(), 1);
        let lines = vec!["pickle.loads(x)  # noqa: E501".to_string()];
        let (kept, _) = apply_suppressions(vec![sample_finding(1)], &lines);
        assert_eq!(kept.len(), 1);
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
