//! Human-readable and JSON report rendering -- mirrors `fenceline/reporting.py`.

use crate::models::{Finding, Severity};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};

const RESET: &str = "\x1b[0m";

fn color(severity_str: &str) -> &'static str {
    match severity_str {
        "CRITICAL" => "\x1b[1;31m",
        "HIGH" => "\x1b[31m",
        "MEDIUM" => "\x1b[33m",
        "LOW" => "\x1b[34m",
        "INFO" => "\x1b[37m",
        _ => RESET,
    }
}

/// Field order matches Python's dict-insertion order exactly (struct
/// serialization order is the field declaration order, not subject to the
/// map-ordering ambiguity a bare `serde_json::Value::Object` would have).
#[derive(Serialize)]
struct FindingJson<'a> {
    cwe_id: &'a str,
    cwe_name: &'a str,
    severity: &'a str,
    confidence: &'a str,
    package: &'a str,
    file: &'a str,
    line: usize,
    code: &'a str,
    description: &'a str,
    zero_day_relevance: &'a str,
}

#[derive(Serialize)]
struct ReportPayload<'a> {
    findings: Vec<FindingJson<'a>>,
    count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_suppressed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nosec_suppressed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    test_suppressed: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    skipped_files: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppression_hint: Option<&'static str>,
}

/// One line naming the Python files that failed to parse -- mirrors
/// `reporting._print_skipped`. The regex checks still ran on them, the AST
/// checks did not; a reader deciding whether a clean report means anything
/// needs to know which files it doesn't cover.
fn print_skipped(skipped_files: &[String]) {
    if skipped_files.is_empty() {
        return;
    }
    let mut shown = skipped_files
        .iter()
        .take(5)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if skipped_files.len() > 5 {
        shown.push_str(&format!(", +{} more", skipped_files.len() - 5));
    }
    println!(
        "  ({} file(s) could not be parsed — AST checks did not run on them: {shown})",
        skipped_files.len()
    );
}

// Real-world feedback: a reader who only ever looks at --json output has no
// way to discover # nosec/--baseline exist at all -- the equivalent
// text-mode footer hint never reaches them.
const SUPPRESSION_HINT: &str = "Confirmed a finding is a false positive or accepted risk? Suppress it with \
     # nosec [CWE-ID] on that line, or adopt fenceline on an existing codebase \
     with --write-baseline/--baseline — see README.md.";

fn suppression_hint(
    has_findings: bool,
    baseline_suppressed: usize,
    nosec_suppressed: usize,
) -> Option<&'static str> {
    (has_findings && baseline_suppressed == 0 && nosec_suppressed == 0).then_some(SUPPRESSION_HINT)
}

pub fn print_report(
    all_findings: &mut [Finding],
    json_output: bool,
    baseline_suppressed: usize,
    nosec_suppressed: usize,
    test_suppressed: usize,
    skipped_files: &[String],
) {
    if json_output {
        let payload = ReportPayload {
            findings: all_findings
                .iter()
                .map(|f| FindingJson {
                    cwe_id: f.cwe_id,
                    cwe_name: f.cwe_name,
                    severity: f.severity.as_str(),
                    confidence: f.confidence.as_str(),
                    package: &f.package,
                    file: &f.file,
                    line: f.line,
                    code: &f.code_snippet,
                    description: &f.description,
                    zero_day_relevance: f.zero_day_relevance,
                })
                .collect(),
            count: all_findings.len(),
            baseline_suppressed: (baseline_suppressed > 0).then_some(baseline_suppressed),
            nosec_suppressed: (nosec_suppressed > 0).then_some(nosec_suppressed),
            test_suppressed: (test_suppressed > 0).then_some(test_suppressed),
            skipped_files: skipped_files.iter().map(String::as_str).collect(),
            suppression_hint: suppression_hint(
                !all_findings.is_empty(),
                baseline_suppressed,
                nosec_suppressed,
            ),
        };
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        return;
    }

    if all_findings.is_empty() {
        println!("\n  {}", "=".repeat(72));
        println!("  SECURITY AUDIT RESULT: ALL CHECKS PASSED (0 findings)");
        if baseline_suppressed > 0 {
            println!("  ({baseline_suppressed} pre-existing finding(s) suppressed by baseline)");
        }
        if nosec_suppressed > 0 {
            println!("  ({nosec_suppressed} finding(s) suppressed by # nosec)");
        }
        if test_suppressed > 0 {
            println!(
                "  ({test_suppressed} finding(s) in test code suppressed — see --include-tests)"
            );
        }
        print_skipped(skipped_files);
        println!("  {}", "=".repeat(72));
        println!();
        return;
    }

    // Sort by severity, then file, then line -- mirrors
    // `all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(...), f.file, f.line))`.
    all_findings.sort_by(|a, b| (a.severity, &a.file, a.line).cmp(&(b.severity, &b.file, b.line)));

    println!("\n  {}", "=".repeat(72));
    println!("  SECURITY AUDIT RESULT: {} FINDING(S)", all_findings.len());
    if baseline_suppressed > 0 {
        println!("  ({baseline_suppressed} pre-existing finding(s) suppressed by baseline)");
    }
    if nosec_suppressed > 0 {
        println!("  ({nosec_suppressed} finding(s) suppressed by # nosec)");
    }
    if test_suppressed > 0 {
        println!("  ({test_suppressed} finding(s) in test code suppressed — see --include-tests)");
    }
    print_skipped(skipped_files);
    println!("  {}\n", "=".repeat(72));

    for f in all_findings.iter() {
        let c = color(f.severity.as_str());
        println!(
            "  {c}[{}/{}]{RESET} {} — {}",
            f.severity.as_str(),
            f.confidence.as_str(),
            f.cwe_id,
            f.cwe_name
        );
        println!("  File:    {}:{}", f.file, f.line);
        if !f.package.is_empty() {
            println!("  Package: {}", f.package);
        }
        println!("  Code:    {}", f.code_snippet);
        println!("  Detail:  {}", f.description);
        if !f.zero_day_relevance.is_empty() {
            println!("  ZeroDay: {}", f.zero_day_relevance);
        }
        println!();
    }

    // Summary
    let mut sev_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let mut conf_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for f in all_findings.iter() {
        *sev_counts.entry(f.severity.as_str()).or_insert(0) += 1;
        *conf_counts.entry(f.confidence.as_str()).or_insert(0) += 1;
    }
    println!("  {}", "─".repeat(72));
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] {
        if let Some(&c) = sev_counts.get(sev) {
            println!("  {}{c:>4} × {sev}{RESET}", color(sev));
        }
    }
    println!("  {}", "─".repeat(72));
    for conf in ["HIGH", "MEDIUM", "LOW"] {
        if let Some(&c) = conf_counts.get(conf) {
            println!("  {c:>4} × {conf} confidence");
        }
    }
    println!("  {}\n", "─".repeat(72));
    if baseline_suppressed == 0 && nosec_suppressed == 0 {
        println!(
            "  Confirmed a finding is a false positive or accepted risk? Suppress it with \
             `# nosec [CWE-ID]` on that line, or adopt fenceline on an existing codebase with \
             `--write-baseline`/`--baseline` — see README.md.\n"
        );
    }
    println!("{CWE_REFERENCE}");
}

pub const CWE_REFERENCE: &str = "\
2025 CWE Top 25 Coverage
=========================
Rank  CWE-ID   Name                                                  Status
----  -------  ----------------------------------------------------  ------
  1   CWE-79   XSS                                                   N/A (no web)
  2   CWE-89   SQL Injection                                         ✓
  3   CWE-352  CSRF                                                  N/A (no web)
   4   CWE-862  Missing Authorization                                 Partial (indirect via secret scan)
  5   CWE-787  Out-of-bounds Write                                   N/A (mem-safe)
  6   CWE-22   Path Traversal                                        ✓
  7   CWE-416  Use After Free                                        N/A (mem-safe)
  8   CWE-125  Out-of-bounds Read                                    N/A (mem-safe)
  9   CWE-78   OS Command Injection                                  ✓
 10   CWE-94   Code Injection                                        ✓
 11   CWE-120  Classic Buffer Overflow                               N/A (mem-safe)
 12   CWE-434  File Upload Dangerous                                 N/A (no upload)
 13   CWE-476  NULL Pointer Dereference                               N/A (mem-safe)
 14   CWE-121  Stack Buffer Overflow                                 N/A (mem-safe)
 15   CWE-502  Deserialization (Untrusted Data)                      ✓
 16   CWE-122  Heap Buffer Overflow                                  N/A (mem-safe)
  17   CWE-863  Incorrect Authorization                               Partial (indirect via secret scan)
  18   CWE-20   Improper Input Validation                             Partial (via path traversal + resource limits)
  19   CWE-284  Improper Access Control                               Partial (via assert + hardcoded secrets)
 20   CWE-200  Information Exposure                                  ✓
 21   CWE-306  Missing Authentication                                N/A (no auth)
 22   CWE-918  SSRF                                                  ✓
 23   CWE-77   Command Injection (general)                           ✓
  24   CWE-639  Authorization Bypass                                  Partial (indirect via secret scan)
 25   CWE-770  Resource Allocation (unbounded)                       ✓

Additional Zero-Day Coverage
=============================
CWE-1333 ReDoS                     ✓   CWE-1336 SSTI                ✓
CWE-1104 Dep Confusion + CVE Scan  ✓   CWE-117  Log Injection       ✓
CWE-93   CRLF Injection            ✓   CWE-90   LDAP Injection      ✓
CWE-61   Symlink Following          ✓   CWE-377  Temp File           ✓
CWE-158  NUL Byte Injection        ✓   CWE-338  Insecure Random     ✓
CWE-208  Timing Attack             ✓   CWE-617  Reachable Assert    ✓
CWE-489  Active Debug Code          ✓   CWE-73   File Write          ✓
CWE-778  Insufficient Logging       ✓   CWE-134  Format String       ✓
CWE-453  Insecure Default           ✓   CWE-328  Weak Hash           ✓
CWE-601  Open Redirect             ✓   CWE-532  Log Secrets          ✓
CWE-295  Disabled TLS Verify        ✓   CWE-327  Weak Crypto          ✓
CWE-22   ZipSlip / TarSlip          ✓   CWE-798  Hardcoded Tokens     ✓
CWE-1007 Trojan Source (B613)      ✓   CWE-1088 Request Timeout     ✓
CWE-322  SSH Host Key Verify        ✓   CWE-391  except:pass/continue ✓
CWE-502  torch.load (ML pickle)     ✓   CWE-94   pandas eval/query    ✓
CWE-502  numpy.load + read_pickle   ✓   CWE-114  numpy lib injection  ✓
CWE-611  pandas read_xml XXE        ✓
CWE-829  .pth Startup Hooks         ✓   CWE-502  Parquet Arrow Ext     ✓
CWE-1104 Unbounded Dep Pins        ✓   CWE-502  ML Model File Load    ✓
CWE-94   Decode-then-Execute Chains ✓   CWE-1327 Bind All Interfaces (B104) ✓
CWE-326  Weak TLS Version (B502-504) ✓   CWE-1104 Legacy PyCrypto Import   ✓
CWE-94   HF trust_remote_code (B615)  ✓   CWE-1104 HF Unpinned Revision     ✓

Referenced CVE Database
=======================
CVE-2026-56315  picklescan <1.0.4 bypass                   (Python stdlib)
CVE-2026-24009  Docling RCE via PyYAML shadow vulnerability  (YAML)
CVE-2025-68664  LangChain Core SSTI/RCE deserialisation     (SSTI)
CVE-2026-0763   GPT Academic pickle RCE (CVSS 9.8)          (pickle)
CVE-2025-61774  PyVista dependency confusion RCE            (supply-chain)
CVE-2026-27834  Python urllib CERT_NONE MITM                (TLS)
CVE-2026-20624  Python tarfile path traversal RCE           (ZipSlip)
CVE-2024-37891  urllib3 HTTP redirect race condition        (dep)
CVE-2024-45187  Dask YAML RCE (CVSS 9.8)                   (dep)
CVE-2025-27516  Jinja2 SSTI via template filename           (dep)
CVE-2026-41486  Ray Parquet cloudpickle.loads RCE (CVSS 10) (parquet)
CVE-2025-30065  Apache Parquet Avro schema RCE (CVSS 10)   (parquet)
CVE-2026-41205  Mako template double-slash path traversal   (mako)
CVE-2026-44307  Mako template backslash path traversal      (mako)
CVE-2024-9880   pandas.eval/df.query sandbox bypass RCE     (pandas)
CVE-2019-6446   numpy.load pickle RCE                       (numpy)
dill-4vulns     dill: 4 extra RCE vectors beyond pickle     (dill)
CVE-2026-42208  LiteLLM .pth backdoor via transitive dep    (.pth / supply-chain)
CVE-2026-41486  Ray Parquet cloudpickle.loads RCE (CVSS 10) (parquet-ext)
OWASP ML06     ML model pickle-based formats RCE            (ML supply-chain)
pydepgate       decode-then-execute chains on PyPI           (supply-chain)
";

// ── SARIF 2.1.0 (GitHub code scanning, VS Code SARIF viewer, etc.) ─────────
// Mirrors `reporting.sarif_report`. Built with `json!`, so object keys come
// out sorted rather than in the Python insertion order; SARIF consumers do
// not care, and the parity test compares parsed documents.

/// SARIF has three result levels; fenceline's five severities fold into them.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub reads `security-severity` (0-10) off the rule to label alerts
/// critical (>= 9.0) / high (>= 7.0) / medium (>= 4.0) / low.
fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "2.5",
        Severity::Info => "1.0",
    }
}

fn sarif_uri(file: &str) -> String {
    file.replace('\\', "/")
}

/// The scan as a SARIF 2.1.0 log: one rule per CWE (its severity is the
/// highest seen for that CWE), one result per finding in report order,
/// unparseable files as tool notifications. Suppressed findings are simply
/// absent; SARIF consumers keep their own suppression state.
pub fn sarif_report(all_findings: &[Finding], skipped_files: &[String]) -> serde_json::Value {
    let mut ordered: Vec<&Finding> = all_findings.iter().collect();
    ordered.sort_by(|a, b| (a.severity, &a.file, a.line).cmp(&(b.severity, &b.file, b.line)));
    // First in report order = highest severity for that CWE.
    let mut rules: BTreeMap<&str, &Finding> = BTreeMap::new();
    for f in &ordered {
        rules.entry(f.cwe_id).or_insert(f);
    }
    let rule_index: HashMap<&str, usize> = rules.keys().enumerate().map(|(i, k)| (*k, i)).collect();

    let rule_objects: Vec<serde_json::Value> = rules
        .iter()
        .map(|(cwe, f)| {
            let number = cwe.rsplit('-').next().unwrap_or(cwe);
            json!({
                "id": cwe,
                "name": f.cwe_name,
                "shortDescription": {"text": f.cwe_name},
                "helpUri": format!("https://cwe.mitre.org/data/definitions/{number}.html"),
                "properties": {"security-severity": security_severity(f.severity), "tags": ["security", cwe]},
            })
        })
        .collect();
    let results: Vec<serde_json::Value> = ordered
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.cwe_id,
                "ruleIndex": rule_index[f.cwe_id],
                "level": sarif_level(f.severity),
                "message": {"text": f.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": sarif_uri(&f.file), "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": f.line, "snippet": {"text": f.code_snippet}},
                    }
                }],
                "properties": {
                    "severity": f.severity.as_str(),
                    "confidence": f.confidence.as_str(),
                    "package": f.package,
                },
            })
        })
        .collect();
    let mut invocation = json!({"executionSuccessful": true});
    if !skipped_files.is_empty() {
        let notes: Vec<serde_json::Value> = skipped_files
            .iter()
            .map(|name| {
                json!({
                    "level": "warning",
                    "message": {"text": format!("{name} could not be parsed; AST checks did not run on it.")},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": sarif_uri(name), "uriBaseId": "%SRCROOT%"}}}],
                })
            })
            .collect();
        invocation["toolExecutionNotifications"] = serde_json::Value::Array(notes);
    }
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "fenceline",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/lvalverdeb/fenceline-rs",
                "rules": rule_objects,
            }},
            "invocations": [invocation],
            "results": results,
        }],
    })
}

pub fn print_sarif(all_findings: &[Finding], skipped_files: &[String]) {
    println!(
        "{}",
        serde_json::to_string_pretty(&sarif_report(all_findings, skipped_files)).unwrap()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, Severity};

    fn sample_finding() -> Finding {
        Finding {
            cwe_id: "CWE-502",
            cwe_name: "Deserialization of Untrusted Data",
            severity: Severity::Critical,
            package: "pkg".to_string(),
            file: "mod.py".to_string(),
            line: 1,
            code_snippet: "pickle.loads(data)".to_string(),
            description: "unsafe".to_string(),
            zero_day_relevance: "",
            confidence: Confidence::High,
        }
    }

    /// Field order in the serialized JSON must match Python's dict
    /// insertion order exactly (cwe_id, cwe_name, severity, confidence,
    /// package, file, line, code, description, zero_day_relevance).
    #[test]
    fn finding_json_field_order_matches_python() {
        let f = sample_finding();
        let json = FindingJson {
            cwe_id: f.cwe_id,
            cwe_name: f.cwe_name,
            severity: f.severity.as_str(),
            confidence: f.confidence.as_str(),
            package: &f.package,
            file: &f.file,
            line: f.line,
            code: &f.code_snippet,
            description: &f.description,
            zero_day_relevance: f.zero_day_relevance,
        };
        let serialized = serde_json::to_string(&json).unwrap();
        let expected_order = [
            "cwe_id",
            "cwe_name",
            "severity",
            "confidence",
            "package",
            "file",
            "line",
            "code",
            "description",
            "zero_day_relevance",
        ];
        let mut last_pos = 0;
        for key in expected_order {
            let pos = serialized.find(&format!("\"{key}\"")).unwrap();
            assert!(pos >= last_pos, "key {key} out of order in {serialized}");
            last_pos = pos;
        }
    }

    #[test]
    fn payload_omits_suppression_counts_when_zero() {
        let payload = ReportPayload {
            findings: vec![],
            count: 0,
            baseline_suppressed: None,
            nosec_suppressed: None,
            test_suppressed: None,
            skipped_files: vec![],
            suppression_hint: None,
        };
        let serialized = serde_json::to_string(&payload).unwrap();
        assert!(!serialized.contains("baseline_suppressed"));
        assert!(!serialized.contains("nosec_suppressed"));
        assert!(!serialized.contains("test_suppressed"));
        assert!(!serialized.contains("suppression_hint"));
        assert!(!serialized.contains("skipped_files"));
    }

    #[test]
    fn payload_includes_suppression_counts_when_nonzero() {
        let payload = ReportPayload {
            findings: vec![],
            count: 0,
            baseline_suppressed: Some(3),
            nosec_suppressed: Some(2),
            test_suppressed: Some(1),
            skipped_files: vec!["pkg/broken.py"],
            suppression_hint: None,
        };
        let serialized = serde_json::to_string(&payload).unwrap();
        assert!(serialized.contains("\"baseline_suppressed\":3"));
        assert!(serialized.contains("\"nosec_suppressed\":2"));
        assert!(serialized.contains("\"test_suppressed\":1"));
        assert!(serialized.contains("\"skipped_files\":[\"pkg/broken.py\"]"));
    }

    #[test]
    fn suppression_hint_present_when_findings_exist_and_none_suppressed_yet() {
        let hint = suppression_hint(true, 0, 0).unwrap();
        assert!(hint.contains("# nosec"));
        assert!(hint.contains("--baseline"));
    }

    #[test]
    fn suppression_hint_absent_once_suppression_is_already_in_use() {
        assert!(suppression_hint(true, 0, 2).is_none());
        assert!(suppression_hint(true, 3, 0).is_none());
    }

    #[test]
    fn suppression_hint_absent_when_no_findings() {
        assert!(suppression_hint(false, 0, 0).is_none());
    }

    #[test]
    fn sarif_report_maps_findings_to_rules_results_and_notifications() {
        let low = Finding {
            cwe_id: "CWE-117",
            cwe_name: "Log Injection / Forging",
            severity: Severity::Low,
            package: "pkg".into(),
            file: "sub\\mod.py".into(),
            line: 7,
            code_snippet: "logger.info(f'{x}')".into(),
            description: "f-string in logger call".into(),
            zero_day_relevance: "",
            confidence: Confidence::High,
        };
        let critical = Finding {
            cwe_id: "CWE-502",
            cwe_name: "Deserialization of Untrusted Data",
            severity: Severity::Critical,
            package: "pkg".into(),
            file: "mod.py".into(),
            line: 1,
            code_snippet: "pickle.loads(data)".into(),
            description: "...".into(),
            zero_day_relevance: "",
            confidence: Confidence::Medium,
        };
        let log = sarif_report(&[low, critical], &["pkg/broken.py".to_string()]);
        assert_eq!(log["version"], "2.1.0");
        let run = &log["runs"][0];
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["id"], "CWE-117");
        assert_eq!(rules[1]["id"], "CWE-502");
        assert_eq!(rules[1]["properties"]["security-severity"], "9.5");
        assert!(rules[1]["helpUri"].as_str().unwrap().ends_with("/502.html"));
        let results = run["results"].as_array().unwrap();
        assert_eq!(results[0]["ruleId"], "CWE-502"); // severity order
        assert_eq!(results[0]["ruleIndex"], 1);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "note");
        assert_eq!(
            results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "sub/mod.py"
        );
        assert_eq!(
            results[1]["locations"][0]["physicalLocation"]["region"]["startLine"],
            7
        );
        assert_eq!(results[0]["properties"]["confidence"], "MEDIUM");
        let notes = run["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap();
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0]["message"]["text"]
                .as_str()
                .unwrap()
                .contains("pkg/broken.py")
        );
    }
}
