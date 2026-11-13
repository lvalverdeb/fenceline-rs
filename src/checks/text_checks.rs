//! Line-regex-based check functions -- mirrors
//! `fenceline/checks/text_checks.py`.
//!
//! These checks scan raw source text rather than the AST -- faster to write
//! for surface-syntax patterns but can't distinguish real code from a
//! mention inside a comment or string (only full-line comments are
//! filtered via `skip()`).

use crate::analysis::ParsedFile;
use crate::ast_helpers::{LOG_METHOD_CALL_ANY_RE, LOG_METHOD_CALL_RE, skip};
use crate::models::{Confidence, Finding, Severity};
use regex::{Regex, RegexBuilder};
use rustpython_ast::{ModModule, StmtImport, StmtImportFrom, Visitor};
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

// ── check_hardcoded_secrets (CWE-798) ────────────────────────────────────
//
// Matched case-insensitively (`(?i)`) -- UPPER_SNAKE_CASE module constants
// (`PASSWORD = "..."`) are the standard Python convention for exactly this
// kind of value and were otherwise invisible. Mirrors the Python fix.

static HARDCODED_SECRET_PATTERNS: LazyLock<Vec<(Regex, Severity, &'static str)>> =
    LazyLock::new(|| {
        vec![
            (
                Regex::new(r#"(?i)(?:private_key|ssh_key|pem)\s*[:=]\s*["'][^"']+["']"#).unwrap(),
                Severity::Critical,
                "Hardcoded private key",
            ),
            (
                Regex::new(r#"(?i)connection_url\s*=\s*["'][^"']*://[^"']+:[^"']+@"#).unwrap(),
                Severity::Critical,
                "Connection URL with embedded credentials",
            ),
            (
                Regex::new(r#"(?i)(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']"#).unwrap(),
                Severity::High,
                "Hardcoded password",
            ),
        ]
    });

pub fn check_hardcoded_secrets(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ParsedFile>,
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

// ── check_xxe (CWE-611) ──────────────────────────────────────────────────

static XXE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:xml\.etree|xml\.dom|xml\.sax)\.").unwrap());

#[derive(Default)]
struct LxmlAliasFinder {
    alias: Option<String>,
}

impl Visitor for LxmlAliasFinder {
    fn visit_stmt_import_from(&mut self, node: StmtImportFrom) {
        if node.module.as_deref() == Some("lxml") {
            for a in &node.names {
                if a.name.as_str() == "etree" {
                    self.alias = Some(a.asname.as_deref().unwrap_or("etree").to_string());
                }
            }
        }
    }
    fn visit_stmt_import(&mut self, node: StmtImport) {
        for a in &node.names {
            if a.name.as_str() == "lxml.etree" {
                self.alias = Some(a.asname.as_deref().unwrap_or("lxml.etree").to_string());
            }
        }
    }
}

/// Local name bound to `lxml.etree` -- `from lxml import etree` (optionally
/// aliased) or `import lxml.etree` (optionally aliased) -- or `None` if not
/// imported.
///
/// `lxml.etree` is the standard XML library alternative to the stdlib
/// `xml.etree`/`xml.dom`/`xml.sax` modules XXE_RE already covers, and in
/// production code is more common than any of them -- but it's almost
/// always imported under a bare `etree` name, so XXE_RE's
/// `xml.etree.`-style prefix match never fires on lxml usage (including the
/// textbook OWASP XXE-enabling pattern, `etree.XMLParser(resolve_entities=True)`).
/// Mirrors the Python fix.
fn lxml_etree_alias(tree: &ModModule) -> Option<String> {
    let mut finder = LxmlAliasFinder::default();
    for stmt in tree.body.clone() {
        finder.visit_stmt(stmt);
    }
    finder.alias
}

pub fn check_xxe(_path: &Path, pk: &str, lines: Lines, tree: Option<&ParsedFile>) -> Vec<Finding> {
    let lxml_pattern = tree
        .and_then(|t| lxml_etree_alias(&t.module))
        .map(|alias| Regex::new(&format!(r"\b{}\.", regex::escape(&alias))).unwrap());
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let lxml_hit = lxml_pattern.as_ref().is_some_and(|p| p.is_match(line));
        if XXE_RE.is_match(line) || lxml_hit {
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

// ── check_tempfile (CWE-377) ─────────────────────────────────────────────

pub fn check_tempfile(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ParsedFile>,
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
    _tree: Option<&ParsedFile>,
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
    _tree: Option<&ParsedFile>,
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

// ── check_supply_chain (CWE-1104) ────────────────────────────────────────

pub fn check_supply_chain(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ParsedFile>,
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
    _tree: Option<&ParsedFile>,
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
    _tree: Option<&ParsedFile>,
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
    _tree: Option<&ParsedFile>,
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

// ── check_ldap (CWE-90) ──────────────────────────────────────────────────

pub fn check_ldap(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ParsedFile>,
) -> Vec<Finding> {
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

// ── check_log_injection (CWE-117) ────────────────────────────────────────

static LOG_FORMAT_SPECIFIER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"%[srd]|\{!r\}|\{!s\}").unwrap());

pub fn check_log_injection(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ParsedFile>,
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
    _tree: Option<&ParsedFile>,
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

// ── check_hardcoded_tokens (CWE-798) ─────────────────────────────────────

// Matched case-insensitively (`(?i)`) -- UPPER_SNAKE_CASE module constants
// (`API_KEY = "..."`) are the standard Python convention for exactly this
// kind of value and were otherwise invisible. Mirrors the Python fix.
static HARDCODED_TOKEN_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (Regex::new(r#"(?i)(?:api_key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-=]{16,}["']"#).unwrap(), "Hardcoded API key"),
        (Regex::new(r#"(?i)(?:token|jwt)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+["']"#).unwrap(), "Hardcoded JWT token"),
        (Regex::new(r#"(?i)(?:bearer|auth_token)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']"#).unwrap(), "Hardcoded bearer / auth token"),
        (Regex::new(r#"(?i)(?:secret|client_secret)\s*[:=]\s*["'][A-Za-z0-9_\-+/=]{16,}["']"#).unwrap(), "Hardcoded secret"),
    ]
});

pub fn check_hardcoded_tokens(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ParsedFile>,
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
    _tree: Option<&ParsedFile>,
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
    _tree: Option<&ParsedFile>,
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
    _tree: Option<&ParsedFile>,
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

// ── check_numpy_load_lib (CWE-114) ───────────────────────────────────────

static NUMPY_LOAD_LIB_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"numpy\.(?:load|ctypeslib)\.").unwrap());
static SHARED_LIB_EXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(so|dll|dylib)").unwrap());

pub fn check_numpy_load_lib(
    _path: &Path,
    pk: &str,
    lines: Lines,
    _tree: Option<&ParsedFile>,
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
    _tree: Option<&ParsedFile>,
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
