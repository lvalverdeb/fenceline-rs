//! Line-regex-based check functions -- mirrors
//! `fenceline/checks/text_checks.py`.
//!
//! These checks scan raw source text rather than the AST -- faster to write
//! for surface-syntax patterns but can't distinguish real code from a
//! mention inside a comment or string (only full-line comments are
//! filtered via `skip()`).

use crate::ast_helpers::{LOG_METHOD_CALL_ANY_RE, LOG_METHOD_CALL_RE, skip};
use crate::models::{Confidence, Finding, Severity};
use regex::{Regex, RegexBuilder};
use rustpython_ast::ModModule;
use std::path::Path;
use std::sync::LazyLock;

type Lines<'a> = &'a [String];

// Argument count mirrors Finding's own field count -- a builder would be
// over-engineering for a straightforward positional constructor used
// identically ~40 times below.
#[allow(clippy::too_many_arguments)]
fn finding(
    cwe_id: &'static str,
    cwe_name: &'static str,
    severity: Severity,
    confidence: Confidence,
    pk: &str,
    line: usize,
    code_snippet: &str,
    description: String,
    zero_day_relevance: &'static str,
) -> Finding {
    Finding {
        cwe_id,
        cwe_name,
        severity,
        confidence,
        package: String::new(),
        file: pk.to_string(),
        line,
        code_snippet: code_snippet.to_string(),
        description,
        zero_day_relevance,
    }
}

/// Shared false-positive guard for hardcoded-secret-shaped patterns --
/// mirrors `_is_secret_false_positive`.
fn is_secret_false_positive(line: &str) -> bool {
    let low = line.to_lowercase();
    if low.contains("environ") || low.contains("getenv") || low.contains("config") {
        return true;
    }
    if ["your-", "placeholder", "...", "example", "xxxx", "****"]
        .iter()
        .any(|x| low.contains(x))
    {
        return true;
    }
    if low.contains("connection_url")
        && (line.contains('{') || line.contains('}') || low.contains("dialect"))
    {
        return true;
    }
    false
}

// ── check_pickle (CWE-502) ───────────────────────────────────────────────

static PICKLE_PATTERNS: LazyLock<Vec<(Regex, &'static str, Severity)>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r"pickle\.loads?\s*\(").unwrap(),
            "pickle.loads() / pickle.load()",
            Severity::Critical,
        ),
        (
            Regex::new(r"pickle\.Unpickler\s*\(").unwrap(),
            "pickle.Unpickler()",
            Severity::Critical,
        ),
        (
            Regex::new(r"cloudpickle\.loads?\s*\(").unwrap(),
            "cloudpickle.loads() / cloudpickle.load()",
            Severity::Critical,
        ),
        (
            Regex::new(r"dill\.loads?\s*\(").unwrap(),
            "dill.loads() / dill.load()",
            Severity::Critical,
        ),
        (
            Regex::new(r"joblib\.load\s*\(").unwrap(),
            "joblib.load()",
            Severity::High,
        ),
        (
            Regex::new(r"shelve\.open\s*\(").unwrap(),
            "shelve.open()",
            Severity::High,
        ),
        (
            Regex::new(r"marshal\.loads?\s*\(").unwrap(),
            "marshal.loads() / marshal.load()",
            Severity::High,
        ),
    ]
});

pub fn check_pickle(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        for (pat, label, sev) in PICKLE_PATTERNS.iter() {
            if pat.is_match(line) {
                results.push(finding(
                    "CWE-502", "Deserialization of Untrusted Data", *sev, Confidence::default(),
                    pk, i + 1, line.trim(),
                    format!("Unsafe deserialisation via {label}. Allows arbitrary code execution."),
                    "CVE-2026-56315 picklescan <1.0.4 bypass (uuid, imaplib etc. unblocked); CVE-2026-0763 GPT Academic CVSS 9.8; LangChain CVE-2025-68664 SSTI+pickle chain",
                ));
                break;
            }
        }
    }
    results
}

// ── check_command_injection (CWE-78) ─────────────────────────────────────

const COMMAND_CALLS: &[(&str, Severity)] = &[
    ("os.system", Severity::Critical),
    ("os.popen", Severity::Critical),
    ("subprocess.call", Severity::High),
    ("subprocess.Popen", Severity::High),
    ("subprocess.run", Severity::High),
    ("subprocess.check_output", Severity::High),
    ("subprocess.getoutput", Severity::High),
    ("subprocess.getstatusoutput", Severity::High),
    ("os.execv", Severity::High),
    ("os.execl", Severity::High),
    ("os.execve", Severity::High),
    ("os.execvp", Severity::High),
    ("pty.spawn", Severity::High),
    ("asyncio.create_subprocess_shell", Severity::High),
];

static SHELL_TRUE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"shell\s*=\s*True").unwrap());

pub fn check_command_injection(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        for (call, sev) in COMMAND_CALLS {
            let pat = format!(r"\b{}\s*\(", regex::escape(call));
            if Regex::new(&pat).unwrap().is_match(line) {
                results.push(finding(
                    "CWE-78", "OS Command Injection", *sev, Confidence::default(),
                    pk, i + 1, line.trim(),
                    format!("{call}() spawns subprocesses; may allow command injection if arguments are unvalidated."),
                    "CWE-78: 20 CVEs in KEV. Still a top Python zero-day vector.",
                ));
                break;
            }
        }
        if SHELL_TRUE_RE.is_match(line) {
            results.push(finding(
                "CWE-78",
                "OS Command Injection",
                Severity::High,
                Confidence::default(),
                pk,
                i + 1,
                line.trim(),
                "shell=True enables shell injection in subprocess calls.".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_sql_injection (CWE-89) ─────────────────────────────────────────

static SQL_INJECTION_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r#"execute\s*\(\s*f["']"#).unwrap(),
            "f-string in execute() — probable SQL injection",
        ),
        (
            Regex::new(r#"exec_driver_sql\s*\(\s*f["']"#).unwrap(),
            "f-string in exec_driver_sql() — probable SQL injection",
        ),
        (
            Regex::new(r"\.execute\s*\([^)]*\+").unwrap(),
            "String concatenation in execute() — probable SQL injection",
        ),
    ]
});

pub fn check_sql_injection(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        for (pat, desc) in SQL_INJECTION_PATTERNS.iter() {
            if pat.is_match(line) {
                results.push(finding(
                    "CWE-89",
                    "SQL Injection",
                    Severity::Critical,
                    Confidence::default(),
                    pk,
                    i + 1,
                    line.trim(),
                    desc.to_string(),
                    "CWE-89 rose to #2 in 2025 Top 25. Most exploited injection class after XSS.",
                ));
                break;
            }
        }
    }
    results
}

// ── check_path_traversal (CWE-22) ────────────────────────────────────────

static LSTRIP_SLASH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"lstrip\(['"]/['"]\)"#).unwrap());
static RELATIVE_PATH_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"relative_path").unwrap());
static OPEN_CALL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"open\s*\(").unwrap());

pub fn check_path_traversal(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if LSTRIP_SLASH_RE.is_match(line) {
            results.push(finding(
                "CWE-22", "Path Traversal", Severity::High, Confidence::default(),
                pk, i + 1, line.trim(),
                "lstrip('/') does NOT prevent ../ traversal — use Path.resolve() + is_relative_to().".to_string(),
                "CWE-22 is #6 in Top 25 with 10 CVEs in KEV.",
            ));
        }
        if RELATIVE_PATH_RE.is_match(line) && OPEN_CALL_RE.is_match(line) {
            results.push(finding(
                "CWE-22", "Path Traversal", Severity::Medium, Confidence::default(),
                pk, i + 1, line.trim(),
                "Variable named 'relative_path' used in open() — verify ../ is rejected with Path.resolve().".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_hardcoded_secrets (CWE-798) ────────────────────────────────────

static HARDCODED_SECRET_PATTERNS: LazyLock<Vec<(Regex, Severity, &'static str)>> =
    LazyLock::new(|| {
        vec![
            (
                Regex::new(r#"(?:private_key|ssh_key|pem)\s*[:=]\s*["'][^"']+["']"#).unwrap(),
                Severity::Critical,
                "Hardcoded private key",
            ),
            (
                Regex::new(r#"connection_url\s*=\s*["'][^"']*://[^"']+:[^"']+@"#).unwrap(),
                Severity::Critical,
                "Connection URL with embedded credentials",
            ),
            (
                Regex::new(r#"(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']"#).unwrap(),
                Severity::High,
                "Hardcoded password",
            ),
        ]
    });

pub fn check_hardcoded_secrets(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        for (pat, sev, desc) in HARDCODED_SECRET_PATTERNS.iter() {
            if pat.is_match(line) && !is_secret_false_positive(line) {
                results.push(finding(
                    "CWE-798", "Use of Hard-coded Credentials", *sev, Confidence::default(),
                    pk, i + 1, line.trim(), desc.to_string(),
                    "Leaked creds in source code are the #1 initial access vector in supply-chain attacks.",
                ));
                break;
            }
        }
    }
    results
}

// ── check_yaml_deserialize (CWE-502) ─────────────────────────────────────

static YAML_LOAD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"yaml\.load\s*\(").unwrap());

pub fn check_yaml_deserialize(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if YAML_LOAD_RE.is_match(line) && !line.contains("SafeLoader") {
            results.push(finding(
                "CWE-502", "Deserialization of Untrusted Data", Severity::Critical, Confidence::default(),
                pk, i + 1, line.trim(),
                "yaml.load() without SafeLoader — enables arbitrary code execution.".to_string(),
                "CVE-2026-24009: Docling RCE via PyYAML shadow vulnerability. Transitive YAML deps can introduce RCE without a direct yaml import.",
            ));
        }
    }
    results
}

// ── check_xxe (CWE-611) ──────────────────────────────────────────────────

static XXE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:xml\.etree|xml\.dom|xml\.sax)\.").unwrap());

pub fn check_xxe(_path: &Path, pk: &str, lines: Lines, _tree: Option<&ModModule>) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if XXE_RE.is_match(line) {
            results.push(finding(
                "CWE-611",
                "XXE (XML External Entity)",
                Severity::High,
                Confidence::default(),
                pk,
                i + 1,
                line.trim(),
                "XML parser without external entity protection. Use defusedxml.".to_string(),
                "XXE remains a zero-day vector for data-processing pipelines.",
            ));
        }
    }
    results
}

// ── check_ssrf (CWE-918) ─────────────────────────────────────────────────

static SSRF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:requests|httpx)\.(?:get|post|put|patch|delete|head|options|request)\s*\(|urllib\.request\.urlopen\s*\(|aiohttp\.ClientSession",
    )
    .unwrap()
});

pub fn check_ssrf(_path: &Path, pk: &str, lines: Lines, _tree: Option<&ModModule>) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if SSRF_RE.is_match(line) {
            results.push(finding(
                "CWE-918", "Server-Side Request Forgery", Severity::High, Confidence::default(),
                pk, i + 1, line.trim(),
                "HTTP request — verify URL is validated against allowlist; SSRF if user-controlled.".to_string(),
                "CWE-918 fell to #22 but SSRF zero-days (cloud metadata exfiltration) remain critical.",
            ));
        }
    }
    results
}

// ── check_tempfile (CWE-377) ─────────────────────────────────────────────

pub fn check_tempfile(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if line.contains("tempfile.mktemp") {
            results.push(finding(
                "CWE-377", "Insecure Temporary File", Severity::High, Confidence::default(),
                pk, i + 1, line.trim(),
                "tempfile.mktemp() is insecure (TOCTOU race). Use TemporaryFile or NamedTemporaryFile.".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_symlink (CWE-61) ───────────────────────────────────────────────

pub fn check_symlink(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if line.contains(".symlink_to") || line.contains("os.symlink") {
            results.push(finding(
                "CWE-61",
                "UNIX Symbolic Link Following",
                Severity::Medium,
                Confidence::default(),
                pk,
                i + 1,
                line.trim(),
                "Creating symlink — verify target is validated to prevent path escape.".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_redos (CWE-1333) ───────────────────────────────────────────────

static RE_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"re\.(?:compile|match|search)").unwrap());
static NESTED_QUANTIFIER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\([^)]+[+*?]\)[+*?{]").unwrap());

pub fn check_redos(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if RE_CALL_RE.is_match(line) && NESTED_QUANTIFIER_RE.is_match(line) {
            results.push(finding(
                "CWE-1333",
                "ReDoS (Catastrophic Backtracking)",
                Severity::Medium,
                Confidence::Low,
                pk,
                i + 1,
                line.trim(),
                "Nested quantifier pattern — potential ReDoS (catastrophic backtracking)."
                    .to_string(),
                "ReDoS zero-days have been used to DoS auth gateways. CWE-1333 new to OWASP 2025.",
            ));
        }
    }
    results
}

// ── check_assert_security (CWE-617) ──────────────────────────────────────

static ASSERT_OPERATOR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(is|==|!=|in)\b").unwrap());
static ASSERT_KEYWORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r"(?:admin|owner|role|permission|authorized|authenticated)")
        .case_insensitive(true)
        .build()
        .unwrap()
});

pub fn check_assert_security(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let stripped = line.trim();
        if stripped.starts_with("assert ")
            && !stripped.starts_with("assert_")
            && !stripped.contains("isinstance")
            && ASSERT_OPERATOR_RE.is_match(stripped)
            && ASSERT_KEYWORD_RE.is_match(stripped)
        {
            results.push(finding(
                "CWE-617", "Reachable Assertion", Severity::Medium, Confidence::default(),
                pk, i + 1, stripped,
                "Assert used for access control check — stripped with python -O. Use proper if/raise.".to_string(),
                "Assert-based security checks are a known zero-day bypass pattern.",
            ));
        }
    }
    results
}

// ── check_exec_driver_sql (CWE-89) ───────────────────────────────────────

static EXEC_DRIVER_SQL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"exec_driver_sql\s*\(\s*f["']"#).unwrap());

pub fn check_exec_driver_sql(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if EXEC_DRIVER_SQL_RE.is_match(line) {
            results.push(finding(
                "CWE-89",
                "SQL Injection",
                Severity::Critical,
                Confidence::default(),
                pk,
                i + 1,
                line.trim(),
                "exec_driver_sql() with f-string — direct SQL injection.".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_supply_chain (CWE-1104) ────────────────────────────────────────

pub fn check_supply_chain(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if line.contains("--extra-index-url") {
            results.push(finding(
                "CWE-1104", "Supply Chain — Dependency Confusion", Severity::High, Confidence::default(),
                pk, i + 1, line.trim(),
                "--extra-index-url enables dependency confusion. Use --index-url instead.".to_string(),
                "CVE-2025-61774: PyVista dependency confusion RCE. Supply-chain attacks on PyPI surged in 2025-2026.",
            ));
        }
    }
    results
}

// ── check_debug_mode (CWE-489) ───────────────────────────────────────────

static DEBUG_TRUE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"debug\s*=\s*True").unwrap());

pub fn check_debug_mode(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if DEBUG_TRUE_RE.is_match(line) && !line.to_lowercase().contains("docstring") {
            results.push(finding(
                "CWE-489",
                "Active Debug Code",
                Severity::Medium,
                Confidence::Low,
                pk,
                i + 1,
                line.trim(),
                "Hardcoded debug=True — may expose sensitive info in production.".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_timing_attack (CWE-208) ────────────────────────────────────────

static EQUALITY_QUOTE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"==\s*['"]"#).unwrap());
static SECRET_WORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r"(?:token|secret|password|auth)")
        .case_insensitive(true)
        .build()
        .unwrap()
});

pub fn check_timing_attack(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if EQUALITY_QUOTE_RE.is_match(line) && SECRET_WORD_RE.is_match(line) {
            results.push(finding(
                "CWE-208", "Timing Attack", Severity::Low, Confidence::Low,
                pk, i + 1, line.trim(),
                "String comparison with == may leak timing information for secret comparison. Use secrets.compare_digest().".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_sensitive_exposure (CWE-200) ───────────────────────────────────

pub fn check_sensitive_exposure(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if line.contains("traceback.print_exc") || line.contains("traceback.print_exception") {
            results.push(finding(
                "CWE-200",
                "Information Exposure",
                Severity::Medium,
                Confidence::default(),
                pk,
                i + 1,
                line.trim(),
                "traceback.print_exc() may leak internal paths / stack traces to users."
                    .to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_null_byte (CWE-158) ────────────────────────────────────────────

static NULL_BYTE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\x00|\\0").unwrap());

pub fn check_null_byte(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if NULL_BYTE_RE.is_match(line) {
            results.push(finding(
                "CWE-158", "NUL Byte Injection", Severity::Info, Confidence::default(),
                pk, i + 1, line.trim(),
                "NUL byte detected — ensure it is rejected/validated before passing to C-based runtimes.".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_resource_limits (CWE-770) ──────────────────────────────────────

static UNBOUNDED_READ_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.read\(\)").unwrap());
static BOUNDED_READ_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"read\(\d").unwrap());
static STREAMING_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r"(?:chunk|iter_content|stream)")
        .case_insensitive(true)
        .build()
        .unwrap()
});

pub fn check_resource_limits(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if UNBOUNDED_READ_RE.is_match(line)
            && !BOUNDED_READ_RE.is_match(line)
            && !STREAMING_RE.is_match(line)
        {
            results.push(finding(
                "CWE-770", "Unbounded Resource Allocation", Severity::Info, Confidence::default(),
                pk, i + 1, line.trim(),
                "Unbounded .read() — may exhaust memory on large inputs. Use .read(n) or streaming.".to_string(),
                "CWE-770 entered Top 25 at #25 in 2025.",
            ));
        }
    }
    results
}

// ── check_ssti (CWE-1336) ────────────────────────────────────────────────

static TEMPLATE_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:Jinja2?\.Template|Template)\s*\(").unwrap());

pub fn check_ssti(_path: &Path, pk: &str, lines: Lines, _tree: Option<&ModModule>) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if TEMPLATE_CALL_RE.is_match(line) {
            results.push(finding(
                "CWE-1336", "Server-Side Template Injection", Severity::High, Confidence::default(),
                pk, i + 1, line.trim(),
                "Template instantiation — SSTI if template string is user-controlled.".to_string(),
                "CVE-2025-68664: LangChain Core SSTI zero-day chaining deserialisation + Jinja2 for RCE.",
            ));
        }
    }
    results
}

// ── check_crlf (CWE-93) ──────────────────────────────────────────────────

static CRLF_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\r\\n|%0d%0a|%0D%0A").unwrap());

pub fn check_crlf(_path: &Path, pk: &str, lines: Lines, _tree: Option<&ModModule>) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if CRLF_RE.is_match(line) {
            results.push(finding(
                "CWE-93",
                "CRLF Injection",
                Severity::High,
                Confidence::default(),
                pk,
                i + 1,
                line.trim(),
                "CRLF sequence — may enable HTTP response splitting / log injection.".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_ldap (CWE-90) ──────────────────────────────────────────────────

pub fn check_ldap(_path: &Path, pk: &str, lines: Lines, _tree: Option<&ModModule>) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if line.contains("ldap.initialize") || line.contains("ldap3") {
            results.push(finding(
                "CWE-90",
                "LDAP Injection",
                Severity::High,
                Confidence::default(),
                pk,
                i + 1,
                line.trim(),
                "LDAP connection — verify queries are parameterised.".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_weak_hash (CWE-328) ────────────────────────────────────────────

static WEAK_HASH_DIRECT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"hashlib\.(?:md5|sha1)\s*\(").unwrap());
static WEAK_HASH_NEW_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r#"hashlib\.new\s*\(\s*["'](?:md5|md4|md2|sha1)["']"#)
        .case_insensitive(true)
        .build()
        .unwrap()
});

pub fn check_weak_hash(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if WEAK_HASH_DIRECT_RE.is_match(line) {
            results.push(finding(
                "CWE-328",
                "Weak Cryptographic Hash",
                Severity::Medium,
                Confidence::default(),
                pk,
                i + 1,
                line.trim(),
                "Use of MD5/SHA-1 — collision-prone, use SHA-256 or better.".to_string(),
                "",
            ));
        }
        if WEAK_HASH_NEW_RE.is_match(line) {
            results.push(finding(
                "CWE-328", "Weak Cryptographic Hash", Severity::Medium, Confidence::default(),
                pk, i + 1, line.trim(),
                "hashlib.new() with a weak algorithm name (MD5/MD4/MD2/SHA-1) — same collision risk as calling hashlib.md5()/sha1() directly, just reached through the generic constructor. Use SHA-256 or better.".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_open_redirect (CWE-601) ────────────────────────────────────────

static REDIRECT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:redirect|Redirect)\s*\(").unwrap());

pub fn check_open_redirect(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if REDIRECT_RE.is_match(line) {
            results.push(finding(
                "CWE-601",
                "Open Redirect",
                Severity::Medium,
                Confidence::default(),
                pk,
                i + 1,
                line.trim(),
                "URL redirect — ensure destination is validated against an allowlist.".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_log_injection (CWE-117) ────────────────────────────────────────

static LOG_FORMAT_SPECIFIER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"%[srd]|\{!r\}|\{!s\}").unwrap());

pub fn check_log_injection(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if LOG_METHOD_CALL_RE.is_match(line) && !LOG_FORMAT_SPECIFIER_RE.is_match(line) {
            results.push(finding(
                "CWE-117", "Log Injection / Forging", Severity::Low, Confidence::default(),
                pk, i + 1, line.trim(),
                "f-string in logger call — may embed newlines/CRLF from user input, forging log entries.".to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_arbitrary_write (CWE-73) ───────────────────────────────────────

static FILE_OP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:shutil\.copy|shutil\.move|os\.rename)\s*\(").unwrap());

pub fn check_arbitrary_write(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if FILE_OP_RE.is_match(line) {
            results.push(finding(
                "CWE-73",
                "External Control of File Name",
                Severity::Medium,
                Confidence::default(),
                pk,
                i + 1,
                line.trim(),
                "File operation — verify destination path is validated to prevent arbitrary write."
                    .to_string(),
                "",
            ));
        }
    }
    results
}

// ── check_log_secrets (CWE-532) ──────────────────────────────────────────

static SECRET_KEYWORDS_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(
        r"(password|passwd|secret|token|api_key|apikey|auth_token|access_key|private_key)",
    )
    .case_insensitive(true)
    .build()
    .unwrap()
});

pub fn check_log_secrets(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        if LOG_METHOD_CALL_ANY_RE.is_match(stripped) && SECRET_KEYWORDS_RE.is_match(stripped) {
            results.push(finding(
                "CWE-532", "Insertion of Sensitive Information into Logs", Severity::High, Confidence::default(),
                pk, i + 1, stripped,
                "Logger call includes a variable whose name suggests it holds a secret — potential credential leakage in logs.".to_string(),
                "CWE-532: leaked creds in logs are a common zero-day discovery vector (GitHub secret scanning, SIEM alerts).",
            ));
        }
    }
    results
}

// ── check_tls_verify (CWE-295) ───────────────────────────────────────────

static TLS_VERIFY_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r"verify\s*=\s*False").unwrap(),
            "HTTP/S3 client with verify=False — TLS certificate validation disabled.",
        ),
        (
            Regex::new(r"check_hostname\s*=\s*False").unwrap(),
            "Hostname verification disabled — no TLS identity check.",
        ),
        (
            Regex::new(r"CERT_NONE").unwrap(),
            "ssl.CERT_NONE — peer certificate not verified, man-in-the-middle possible.",
        ),
        (
            Regex::new(r"_create_unverified_context").unwrap(),
            "ssl._create_unverified_context() — creates unverified TLS context.",
        ),
    ]
});

pub fn check_tls_verify(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        for (pat, desc) in TLS_VERIFY_PATTERNS.iter() {
            if pat.is_match(stripped) {
                results.push(finding(
                    "CWE-295", "Improper Certificate Validation", Severity::Critical, Confidence::default(),
                    pk, i + 1, stripped, desc.to_string(),
                    "CWE-295 is #8 in CWE Top 25. TLS bypass zero-days (e.g. CVE-2026-27834 Python CERT_NONE in urllib) enable MITM on every connection.",
                ));
                break;
            }
        }
    }
    results
}

// ── check_zipslip (CWE-22) ───────────────────────────────────────────────

static EXTRACTALL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.extractall\s*\(").unwrap());
static EXTRACTALL_GUARD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(resolve|is_relative_to|member.*safe)").unwrap());

pub fn check_zipslip(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        if EXTRACTALL_RE.is_match(stripped) && !EXTRACTALL_GUARD_RE.is_match(stripped) {
            results.push(finding(
                "CWE-22", "Path Traversal — ZipSlip / TarSlip", Severity::High, Confidence::default(),
                pk, i + 1, stripped,
                "extractall() without path traversal guard — an archive with ../ entries can overwrite arbitrary files.".to_string(),
                "ZipSlip zero-day pattern: path traversal in archive extraction enables RCE via overwritten binaries (CVE-2026-20624 Python tarfile).",
            ));
        }
    }
    results
}

// ── check_hardcoded_tokens (CWE-798) ─────────────────────────────────────

static HARDCODED_TOKEN_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (Regex::new(r#"(?:api_key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-=]{16,}["']"#).unwrap(), "Hardcoded API key"),
        (Regex::new(r#"(?:token|jwt)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+["']"#).unwrap(), "Hardcoded JWT token"),
        (Regex::new(r#"(?:bearer|auth_token)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']"#).unwrap(), "Hardcoded bearer / auth token"),
        (Regex::new(r#"(?:secret|client_secret)\s*[:=]\s*["'][A-Za-z0-9_\-+/=]{16,}["']"#).unwrap(), "Hardcoded secret"),
    ]
});

pub fn check_hardcoded_tokens(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        for (pat, desc) in HARDCODED_TOKEN_PATTERNS.iter() {
            if pat.is_match(stripped) && !is_secret_false_positive(stripped) {
                results.push(finding(
                    "CWE-798", "Use of Hard-coded Credentials", Severity::Critical, Confidence::default(),
                    pk, i + 1, stripped,
                    format!("{desc} — plaintext credential in source code."),
                    "Hardcoded cloud API keys are the #1 initial-access vector in supply-chain attacks. Attackers scan public repos for these patterns.",
                ));
                break;
            }
        }
    }
    results
}

// ── check_weak_crypto (CWE-327) ──────────────────────────────────────────

static WEAK_CRYPTO_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            RegexBuilder::new(r"Crypto\.Cipher\.DES\b|pycryptodome.*DES\b")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "DES — 56-bit key, bruteforceable. Use AES-256.",
        ),
        (
            RegexBuilder::new(r"ARC4\b|RC4\b")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "RC4 — biased output, completely broken. Use ChaCha20 or AES-GCM.",
        ),
        (
            RegexBuilder::new(r"MODE_ECB\b")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "AES ECB mode — deterministic, leaks plaintext structure. Use GCM or CBC.",
        ),
        (
            RegexBuilder::new(r"PKCS1_v1_5\b")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "PKCS1_v1_5 padding — vulnerable to Bleichenbacher oracle attack. Use OAEP.",
        ),
        (
            // Lookahead rewritten (RUST_PORT_PROPOSAL.md §7.1): the outer
            // `.*` before the original lookahead was already redundant with
            // the `.*` inside it, so this consuming form is equivalent for
            // a pure search()-truthiness check.
            RegexBuilder::new(r"hashlib\.md5\b.*\b(?:sign|hmac|sig|token|password|hash\b)")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "MD5 used in a security context (signing/hashing secrets) — collision-broken.",
        ),
    ]
});

pub fn check_weak_crypto(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        for (pat, desc) in WEAK_CRYPTO_PATTERNS.iter() {
            if pat.is_match(stripped) {
                results.push(finding(
                    "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", Severity::High, Confidence::default(),
                    pk, i + 1, stripped, desc.to_string(),
                    "CWE-327: Weak crypto zero-days (Bleichenbacher, Padding Oracle) remain exploitable decades after disclosure.",
                ));
                break;
            }
        }
    }
    results
}

// ── check_trojan_source (CWE-1007) ───────────────────────────────────────

static BIDI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("[\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}]")
        .unwrap()
});

pub fn check_trojan_source(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    // Deliberately does not call skip() -- Trojan Source characters hidden
    // in a comment are exactly the attack this check must still catch.
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if BIDI_RE.is_match(line) {
            results.push(finding(
                "CWE-1007", "Trojan Source (Bidirectional Override)", Severity::Critical, Confidence::default(),
                pk, i + 1, &format!("{:?}", line.trim()),
                "Unicode bidi override character — enables Trojan Source attacks: code appears different than it executes.".to_string(),
                "CVE-2021-42574: bidi overrides hide malicious code in plain sight. Bypasses code review.",
            ));
        }
    }
    results
}

// ── check_ssh_host_key (CWE-322) ─────────────────────────────────────────

static SSH_HOST_KEY_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r"AutoAddPolicy").unwrap(),
            "paramiko AutoAddPolicy — auto-accepts any unknown host key (MITM).",
        ),
        (
            Regex::new(r"WarningPolicy").unwrap(),
            "paramiko WarningPolicy — warns but allows connection with unknown host key (MITM).",
        ),
        (
            Regex::new(r"sshtunnel\.open_tunnel").unwrap(),
            "sshtunnel.open_tunnel — verify host_key is explicitly set.",
        ),
    ]
});

pub fn check_ssh_host_key(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        for (pat, desc) in SSH_HOST_KEY_PATTERNS.iter() {
            if pat.is_match(stripped) {
                results.push(finding(
                    "CWE-322", "Key Exchange without Entity Authentication", Severity::High, Confidence::default(),
                    pk, i + 1, stripped, desc.to_string(),
                    "SSH MITM allows credential interception and lateral movement. Common zero-day chain component.",
                ));
                break;
            }
        }
    }
    results
}

// ── check_pandas_pickle (CWE-502) ────────────────────────────────────────

static READ_PICKLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:pd|pandas)\.read_pickle\s*\(").unwrap());

pub fn check_pandas_pickle(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        if READ_PICKLE_RE.is_match(line) {
            results.push(finding(
                "CWE-502", "Deserialization of Untrusted Data (read_pickle)", Severity::Critical, Confidence::default(),
                pk, i + 1, line.trim(),
                "pd.read_pickle() deserializes Python objects via pickle — arbitrary code execution if file is untrusted.".to_string(),
                "Trail of Bits: pandas.read_pickle() uses pickle.load() under the hood — standard pickle RCE.",
            ));
        }
    }
    results
}

// ── check_numpy_load_lib (CWE-114) ───────────────────────────────────────

static NUMPY_LOAD_LIB_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"numpy\.(?:load|ctypeslib)\.").unwrap());
static SHARED_LIB_EXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(so|dll|dylib)").unwrap());

pub fn check_numpy_load_lib(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        if NUMPY_LOAD_LIB_RE.is_match(stripped) && SHARED_LIB_EXT_RE.is_match(stripped) {
            results.push(finding(
                "CWE-114", "Process Control (numpy library loading)", Severity::High, Confidence::default(),
                pk, i + 1, stripped,
                "numpy.load() loading a shared library (.so/.dll) — arbitrary code execution if path is user-controlled.".to_string(),
                "Trail of Bits: numpy.load() on .so files enables arbitrary code execution during array deserialization.",
            ));
        }
    }
    results
}

// ── check_pandas_xml_xxe (CWE-611) ───────────────────────────────────────

static READ_XML_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:pd|pandas)\.read_xml\s*\(").unwrap());

pub fn check_pandas_xml_xxe(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        if READ_XML_RE.is_match(stripped) && !stripped.contains("parser") {
            results.push(finding(
                "CWE-611", "XXE via pandas.read_xml", Severity::High, Confidence::default(),
                pk, i + 1, stripped,
                "pd.read_xml() defaults to lxml parser — may be vulnerable to XXE. Use parser='etree' or defusedxml.".to_string(),
                "Trail of Bits: pandas.read_xml with lxml parser enables XXE attacks on XML data pipelines.",
            ));
        }
    }
    results
}

// ── check_pth_startup_hooks (CWE-829) ────────────────────────────────────

static ADDSITEDIR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"site\.addsitedir\s*\(").unwrap());
static EXEC_DYNAMIC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"exec\s*\(\s*(?:compile|open|base64)").unwrap());
static PTH_MENTION_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.pth").unwrap());

pub fn check_pth_startup_hooks(
    path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();

    if path.extension().is_some_and(|e| e == "pth") {
        for (i, line) in lines.iter().enumerate() {
            let stripped = line.trim();
            if !stripped.is_empty() && !stripped.starts_with('#') {
                results.push(finding(
                    "CWE-829", "Inclusion of Functionality from Untrusted Control Sphere", Severity::Critical, Confidence::default(),
                    pk, i + 1, stripped,
                    ".pth file executes arbitrary Python at interpreter startup — MITRE ATT&CK T1546.018. LiteLLM CVE-2026-42208 vector.".to_string(),
                    "CVE-2026-42208: .pth in litellm >=1.61.3. Hades campaign: 26+ PyPI packages hijacked via .pth. CPython issue #113659 acknowledges gap.",
                ));
                break;
            }
        }
        return results;
    }

    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        if ADDSITEDIR_RE.is_match(stripped) {
            results.push(finding(
                "CWE-829", ".pth Directory Added to sys.path", Severity::High, Confidence::default(),
                pk, i + 1, stripped,
                "site.addsitedir() processes .pth files from the given directory — enables startup code execution if any .pth file is present.".to_string(),
                "MITRE ATT&CK T1546.018: .pth files execute at Python startup before any application code runs.",
            ));
        }
        if EXEC_DYNAMIC_RE.is_match(stripped) && PTH_MENTION_RE.is_match(line) {
            results.push(finding(
                "CWE-829",
                "Dynamic .pth Execution",
                Severity::Critical,
                Confidence::default(),
                pk,
                i + 1,
                stripped,
                "Dynamic .pth installation with exec() — classic supply-chain pivot.".to_string(),
                "ChocoPoC: .pth files used to maintain persistence after initial compromise.",
            ));
        }
    }
    results
}

// ── check_model_file_load (CWE-502) ──────────────────────────────────────

static TORCH_LOAD_TEXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"torch\.load\s*\(").unwrap());
static TORCH_MODEL_EXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\.(?:pt|pth|ckpt)["']"#).unwrap());
static PICKLE_LOAD_FAMILY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:joblib|pickle|cloudpickle|dill)\.load\s*\(").unwrap());
static KERAS_LOAD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:tf|keras)\.(?:models\.)?load_model\s*\(").unwrap());
const MODEL_EXTS: &[&str] = &[
    r#".pt["']"#,
    r#".pkl["']"#,
    r#".h5["']"#,
    r#".joblib["']"#,
    r#".ckpt["']"#,
];

pub fn check_model_file_load(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();

        if TORCH_LOAD_TEXT_RE.is_match(stripped) && TORCH_MODEL_EXT_RE.is_match(stripped) {
            let has_weights_only = stripped.contains("weights_only");
            results.push(finding(
                "CWE-502", "Deserialization of Untrusted Data (ML Model)",
                if has_weights_only { Severity::Low } else { Severity::Critical },
                Confidence::default(),
                pk, i + 1, stripped,
                format!(
                    "torch.load() on model file{}. Prefer SafeTensors format for untrusted model files.",
                    if has_weights_only { "" } else { " without weights_only=True" }
                ),
                "OWASP ML06: pickle-based model formats enable RCE via malicious model files. SafeTensors mitigates this by design.",
            ));
        }

        if PICKLE_LOAD_FAMILY_RE.is_match(stripped) {
            for ext_pat in MODEL_EXTS {
                if Regex::new(ext_pat).unwrap().is_match(stripped) {
                    results.push(finding(
                        "CWE-502", "Deserialization of Untrusted Data (ML Model)", Severity::High, Confidence::default(),
                        pk, i + 1, stripped,
                        format!("pickle-based load on {ext_pat} file — arbitrary code execution via malicious model. Prefer SafeTensors for untrusted model files."),
                        "OWASP ML06: 80% of ML supply-chain attacks exploit pickle-based model formats.",
                    ));
                    break;
                }
            }
        }

        if KERAS_LOAD_RE.is_match(stripped) {
            results.push(finding(
                "CWE-502", "Deserialization of Untrusted Data (Keras Model)", Severity::High, Confidence::default(),
                pk, i + 1, stripped,
                "tf.keras.models.load_model() can deserialize arbitrary Python objects via custom layers/optimizers. Prefer SafeTensors for untrusted models.".to_string(),
                "OWASP ML06: Keras H5 format carries pickle-like deserialization risk.",
            ));
        }
    }
    results
}

// ── check_legacy_pycrypto (CWE-1104) ─────────────────────────────────────

static LEGACY_PYCRYPTO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:from|import)\s+Crypto\b").unwrap());

pub fn check_legacy_pycrypto(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        if LEGACY_PYCRYPTO_RE.is_match(stripped) {
            results.push(finding(
                "CWE-1104", "Supply Chain — Unmaintained Dependency", Severity::Medium, Confidence::default(),
                pk, i + 1, stripped,
                "Imports the old PyCrypto package (unmaintained since 2013, several unpatched CVEs) — migrate to pycryptodome (`import Cryptodome` / `from Cryptodome import ...`), a maintained drop-in replacement.".to_string(),
                "PyCrypto has no security fixes for over a decade; several known vulnerabilities (e.g. weak RNG seeding in old releases) remain unpatched.",
            ));
        }
    }
    results
}

// ── check_weak_tls_version (CWE-326) ─────────────────────────────────────

static WEAK_TLS_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"PROTOCOL_(?:SSLv2|SSLv3|TLSv1)\b").unwrap());

pub fn check_weak_tls_version(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        if let Some(m) = WEAK_TLS_VERSION_RE.find(stripped) {
            results.push(finding(
                "CWE-326", "Inadequate Encryption Strength", Severity::High, Confidence::default(),
                pk, i + 1, stripped,
                format!("{} — explicitly requests a deprecated, broken SSL/TLS protocol version. Use ssl.PROTOCOL_TLS_CLIENT/SERVER (or omit ssl_version entirely) to let Python negotiate the strongest mutually-supported version.", m.as_str()),
                "B502/B503/B504: SSLv3 enables POODLE, TLSv1.0/1.1 are formally deprecated by RFC 8996 — still found in legacy integration code talking to old servers.",
            ));
        }
    }
    results
}

// ── check_bind_all_interfaces (CWE-1327) ─────────────────────────────────

static BIND_ALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["']0\.0\.0\.0["']"#).unwrap());

pub fn check_bind_all_interfaces(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        if BIND_ALL_RE.is_match(stripped) {
            results.push(finding(
                "CWE-1327", "Binding to an Unrestricted IP Address", Severity::Medium, Confidence::default(),
                pk, i + 1, stripped,
                "Host bound to 0.0.0.0 — listens on every network interface, not just localhost. Bind to 127.0.0.1 unless external access is actually required.".to_string(),
                "B104: services accidentally exposed on all interfaces are a common initial-access vector once a container/VM's network boundary is misconfigured.",
            ));
        }
    }
    results
}
