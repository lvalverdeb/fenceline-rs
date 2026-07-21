//! Human-readable and JSON report rendering -- mirrors `fenceline/reporting.py`.

use crate::models::Finding;
use serde::Serialize;

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
}

pub fn print_report(
    all_findings: &mut [Finding],
    json_output: bool,
    baseline_suppressed: usize,
    nosec_suppressed: usize,
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
        };
        let serialized = serde_json::to_string(&payload).unwrap();
        assert!(!serialized.contains("baseline_suppressed"));
        assert!(!serialized.contains("nosec_suppressed"));
    }

    #[test]
    fn payload_includes_suppression_counts_when_nonzero() {
        let payload = ReportPayload {
            findings: vec![],
            count: 0,
            baseline_suppressed: Some(3),
            nosec_suppressed: Some(2),
        };
        let serialized = serde_json::to_string(&payload).unwrap();
        assert!(serialized.contains("\"baseline_suppressed\":3"));
        assert!(serialized.contains("\"nosec_suppressed\":2"));
    }
}
