//! Core data model — mirrors `fenceline/models.py`.

use serde::Serialize;

/// Ordered so a derived `Ord` matches Python's `SEVERITY_ORDER` dict exactly:
/// declaration order is ascending sort order, and `Critical` sorting first
/// is what `SEVERITY_ORDER = {"CRITICAL": 0, ...}` encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Upper-case string form -- must match Python's literal severity
    /// strings exactly, since this is what appears in JSON output that a
    /// conformance suite (or an external consumer) diffs against.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

/// How sure a check is that a finding is a real positive, independent of how
/// bad it would be if true (that's `Severity`). Mirrors
/// `models.py::CONFIDENCE_ORDER` -- declaration order is ascending sort
/// order, same convention as `Severity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::High => "HIGH",
            Confidence::Medium => "MEDIUM",
            Confidence::Low => "LOW",
        }
    }
}

impl Default for Confidence {
    /// Mirrors `Finding.confidence`'s Python default of `"MEDIUM"`.
    fn default() -> Self {
        Confidence::Medium
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub cwe_id: &'static str,
    pub cwe_name: &'static str,
    pub severity: Severity,
    pub package: String,
    pub file: String,
    pub line: usize,
    pub code_snippet: String,
    pub description: String,
    /// Mirrors the Python default of `""` (empty, not every check sets it).
    pub zero_day_relevance: &'static str,
    pub confidence: Confidence,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering_matches_python_severity_order() {
        // Mirrors SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
        // "LOW": 3, "INFO": 4} -- ascending Ord must match ascending order value.
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
        assert!(Severity::Low < Severity::Info);
    }

    #[test]
    fn confidence_ordering_matches_python_confidence_order() {
        // Mirrors CONFIDENCE_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.
        assert!(Confidence::High < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::Low);
    }

    #[test]
    fn confidence_default_is_medium() {
        assert_eq!(Confidence::default().as_str(), "MEDIUM");
    }

    #[test]
    fn severity_and_confidence_as_str_match_python_literals() {
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
        assert_eq!(Severity::High.as_str(), "HIGH");
        assert_eq!(Severity::Medium.as_str(), "MEDIUM");
        assert_eq!(Severity::Low.as_str(), "LOW");
        assert_eq!(Severity::Info.as_str(), "INFO");
        assert_eq!(Confidence::High.as_str(), "HIGH");
        assert_eq!(Confidence::Medium.as_str(), "MEDIUM");
        assert_eq!(Confidence::Low.as_str(), "LOW");
    }
}
