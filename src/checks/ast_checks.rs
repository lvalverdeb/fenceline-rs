//! AST-based check functions -- mirrors `fenceline/checks/ast_checks.py`.
//!
//! Each check filters/maps over the record tables `analysis::ParsedFile`
//! builds once per file (see that module) rather than walking the tree
//! itself.

use crate::analysis::ParsedFile;
use crate::ast_helpers::{call_name, dotted_matches, full_attr, resolve_dotted, skip};
use crate::models::{Confidence, Finding, Severity};
use crate::taint::{Taint, confidence_for};
use regex::{Regex, RegexBuilder};
use rustpython_ast::{Expr, ExprCall, Ranged};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

fn code_at(lines: &[String], line: usize) -> String {
    lines
        .get(line.wrapping_sub(1))
        .map(|l| l.trim().to_string())
        .unwrap_or_default()
}

// ── check_eval_exec (CWE-94) ─────────────────────────────────────────────

pub fn check_eval_exec(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    let mut results = Vec::new();
    for call in &collected.calls {
        let (severity, description) = match call.full_attr.as_str() {
            "eval" | "exec" => (
                Severity::Critical,
                format!(
                    "{}() with dynamic input allows arbitrary code execution.",
                    call.full_attr
                ),
            ),
            "compile" if !call.is_excluded_compile && call.func_is_bare_name => (
                Severity::Critical,
                "compile() with dynamic input can enable arbitrary code execution.".to_string(),
            ),
            "__import__" => (
                Severity::High,
                "Dynamic __import__() can import arbitrary modules if argument is user-controlled."
                    .to_string(),
            ),
            _ => continue,
        };
        let Some((confidence, note)) = confidence_for(call.data_taint) else {
            continue;
        };
        results.push(ast_finding(
            "CWE-94",
            "Code Injection",
            severity,
            confidence,
            pk,
            lines,
            call.line,
            description + note,
            "",
        ));
    }
    results
}

// ── check_insufficient_logging (CWE-778) ─────────────────────────────────

pub fn check_insufficient_logging(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    collected
        .excepts
        .iter()
        .filter(|e| (e.is_bare || e.is_exception_name) && !e.has_diagnostic)
        .map(|e| Finding {
            cwe_id: "CWE-778",
            cwe_name: "Insufficient Logging",
            severity: Severity::Low,
            confidence: Confidence::High,
            package: String::new(),
            file: pk.to_string(),
            line: e.line,
            code_snippet: code_at(lines, e.line),
            description: "Bare except: or except Exception: — should at minimum log the exception."
                .to_string(),
            zero_day_relevance: "Insufficient logging delays zero-day attack detection by months.",
        })
        .collect()
}

// ── check_insecure_random (CWE-338) ──────────────────────────────────────

const RANDOM_UNSAFE_FNS: &[&str] = &[
    "random",
    "randint",
    "choice",
    "uniform",
    "shuffle",
    "sample",
    "randrange",
];

pub fn check_insecure_random(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    collected
        .calls
        .iter()
        .filter(|c| {
            c.full_attr.starts_with("random.")
                && c.full_attr != "random.SystemRandom"
                && c.full_attr != "random.secrets"
                && RANDOM_UNSAFE_FNS.contains(&c.full_attr.rsplit('.').next().unwrap_or(""))
        })
        .map(|c| {
            let base = c.full_attr.rsplit('.').next().unwrap_or("");
            Finding {
                cwe_id: "CWE-338",
                cwe_name: "Insecure Randomness",
                severity: Severity::Low,
                confidence: Confidence::High,
                package: String::new(),
                file: pk.to_string(),
                line: c.line,
                code_snippet: code_at(lines, c.line),
                description: format!(
                    "random.{base}() uses Mersenne Twister (not crypto-secure). Use secrets module for security-sensitive contexts."
                ),
                zero_day_relevance: "",
            }
        })
        .collect()
}

// ── check_format_string (CWE-134) ────────────────────────────────────────

pub fn check_format_string(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    collected
        .calls
        .iter()
        .filter(|c| c.full_attr == "str.format" && c.args_dynamic)
        .map(|c| Finding {
            cwe_id: "CWE-134",
            cwe_name: "Externally-Controlled Format String",
            severity: Severity::Medium,
            confidence: Confidence::High,
            package: String::new(),
            file: pk.to_string(),
            line: c.line,
            code_snippet: code_at(lines, c.line),
            description:
                "str.format() with dynamic format string — potential format string vulnerability."
                    .to_string(),
            zero_day_relevance: "",
        })
        .collect()
}

// ── check_insecure_default (CWE-453) ─────────────────────────────────────

fn allow_pickle_finding(pk: &str, lines: &[String], line: usize) -> Finding {
    Finding {
        cwe_id: "CWE-453",
        cwe_name: "Insecure Default",
        severity: Severity::High,
        confidence: Confidence::High,
        package: String::new(),
        file: pk.to_string(),
        line,
        code_snippet: code_at(lines, line),
        description:
            "allow_pickle=True enables pickle deserialisation — verify strict input gating."
                .to_string(),
        zero_day_relevance: "CVE-2026-56315: picklescan bypass. Allow-pickle flags are a common zero-day entry point.",
    }
}

pub fn check_insecure_default(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    let mut flagged_lines: Vec<usize> = Vec::new();

    for call in &collected.calls {
        if let Some(line) = call.allow_pickle_kw_line {
            flagged_lines.push(line);
        }
    }
    for a in collected.assigns.iter().chain(collected.ann_assigns.iter()) {
        if a.is_allow_pickle_true {
            flagged_lines.push(a.line);
        }
    }
    for f in &collected.funcdefs {
        for (name, is_true, default_line) in &f.params {
            if name == "allow_pickle" && *is_true == Some(true) {
                flagged_lines.push(default_line.unwrap_or(f.line));
            }
        }
    }
    flagged_lines.sort_unstable();
    flagged_lines
        .into_iter()
        .map(|line| allow_pickle_finding(pk, lines, line))
        .collect()
}

// ── check_request_timeout (CWE-1088) ─────────────────────────────────────

const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "request",
];

pub fn check_request_timeout(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    collected
        .calls
        .iter()
        .filter(|c| {
            let parts: Vec<&str> = c.full_attr.split('.').collect();
            parts.len() == 2
                && parts[0] == "requests"
                && HTTP_METHODS.contains(&parts[1])
                && !c.keyword_names.iter().any(|n| n == "timeout")
        })
        .map(|c| {
            let method = c.full_attr.rsplit('.').next().unwrap_or("");
            Finding {
                cwe_id: "CWE-1088",
                cwe_name: "Synchronous Access without Timeout",
                severity: Severity::High,
                confidence: Confidence::High,
                package: String::new(),
                file: pk.to_string(),
                line: c.line,
                code_snippet: code_at(lines, c.line),
                description: format!(
                    "requests.{method}(...) without timeout= — may hang indefinitely. Add timeout=30."
                ),
                zero_day_relevance: "CWE-1088: hung connections enable resource-exhaustion DoS. Zero-day botnets use this for unauthenticated amplification.",
            }
        })
        .collect()
}

// ── check_torch_load (CWE-502) ───────────────────────────────────────────

pub fn check_torch_load(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    collected
        .calls
        .iter()
        .filter(|c| c.full_attr == "torch.load" && !c.keyword_true_names.iter().any(|n| n == "weights_only"))
        .map(|c| Finding {
            cwe_id: "CWE-502",
            cwe_name: "Deserialization of Untrusted Data (torch.load)",
            severity: Severity::Critical,
            confidence: Confidence::High,
            package: String::new(),
            file: pk.to_string(),
            line: c.line,
            code_snippet: code_at(lines, c.line),
            description: "torch.load() without weights_only=True — enables arbitrary code execution via pickle deserialisation.".to_string(),
            zero_day_relevance: "B614: torch.load defaults to pickle. ML model poisoning attacks exploit this for RCE in data pipelines.",
        })
        .collect()
}

// ── check_except_pass (CWE-391) ──────────────────────────────────────────

pub fn check_except_pass(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    let mut results = Vec::new();
    for e in &collected.excepts {
        if e.single_pass {
            results.push(Finding {
                cwe_id: "CWE-391",
                cwe_name: "Unchecked Error Condition",
                severity: Severity::Medium,
                confidence: Confidence::High,
                package: String::new(),
                file: pk.to_string(),
                line: e.line,
                code_snippet: code_at(lines, e.line),
                description:
                    "except: pass — silently swallows all exceptions. At minimum log the exception."
                        .to_string(),
                zero_day_relevance: "",
            });
        } else if e.single_continue {
            results.push(Finding {
                cwe_id: "CWE-391",
                cwe_name: "Unchecked Error Condition",
                severity: Severity::Medium,
                confidence: Confidence::High,
                package: String::new(),
                file: pk.to_string(),
                line: e.line,
                code_snippet: code_at(lines, e.line),
                description: "except: continue — silently swallows exceptions in a loop. At minimum log the exception.".to_string(),
                zero_day_relevance: "",
            });
        }
    }
    results
}

// ── check_pandas_eval (CWE-94) ───────────────────────────────────────────

pub fn check_pandas_eval(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    let mut results = Vec::new();
    for c in &collected.calls {
        let (cwe_name, severity, description, zero_day) = if c.full_attr == "pandas.eval"
            || c.full_attr == "pd.eval"
        {
            (
                "Code Injection (pandas eval)",
                Severity::Critical,
                "pandas.eval() evaluates arbitrary Python expressions — code injection if user input reaches the expression.",
                "CVE-2024-9880 / Trail of Bits: pandas.eval() / df.query() sandbox bypass via dunder methods. Pandas docs now warn explicitly.",
            )
        } else if matches!(c.full_attr.rsplit('.').next(), Some("eval") | Some("query"))
            && c.full_attr.contains('.')
        {
            (
                "Code Injection (DataFrame eval/query)",
                Severity::High,
                "DataFrame.eval() or DataFrame.query() evaluates Python expressions — code injection if user-controlled input reaches the expression.",
                "CVE-2024-9880: pandas.DataFrame.query() sandbox bypass. Thousands of attribute chains lead to os.system.",
            )
        } else {
            continue;
        };
        let Some((confidence, note)) = confidence_for(c.data_taint) else {
            continue;
        };
        results.push(ast_finding(
            "CWE-94",
            cwe_name,
            severity,
            confidence,
            pk,
            lines,
            c.line,
            format!("{description}{note}"),
            zero_day,
        ));
    }
    results
}

// ── check_numpy_load (CWE-502) ───────────────────────────────────────────

pub fn check_numpy_load(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    collected
        .calls
        .iter()
        .filter(|c| {
            (c.full_attr == "numpy.load" || c.full_attr == "np.load")
                && c.keyword_true_names.iter().any(|n| n == "allow_pickle")
        })
        .map(|c| Finding {
            cwe_id: "CWE-502",
            cwe_name: "Deserialization of Untrusted Data (numpy.load)",
            severity: Severity::High,
            confidence: Confidence::High,
            package: String::new(),
            file: pk.to_string(),
            line: c.line,
            code_snippet: code_at(lines, c.line),
            description: "np.load(allow_pickle=True) may load pickled object arrays enabling RCE. Only use with trusted data; numpy's own default is allow_pickle=False.".to_string(),
            zero_day_relevance: "CVE-2019-6446: numpy.load() RCE via pickle. numpy docs now recommend allow_pickle=False for untrusted sources.",
        })
        .collect()
}

// ── check_parquet_arrow_deserialize (CWE-502) ────────────────────────────

static CLOUDPICKLE_LOADS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"cloudpickle\.loads?\s*\(").unwrap());
static ARROW_CONTEXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:py)?arrow|parquet|arrow_ext|deserialize").unwrap());

pub fn check_parquet_arrow_deserialize(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    if let Some(tree) = tree {
        let collected = tree.collected();
        for f in &collected.funcdefs {
            if f.is_plain_function_def && f.name == "__arrow_ext_deserialize__" {
                results.push(Finding {
                    cwe_id: "CWE-502",
                    cwe_name: "Deserialization of Untrusted Data (Arrow Extension)",
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    package: String::new(),
                    file: pk.to_string(),
                    line: f.line,
                    code_snippet: code_at(lines, f.line),
                    description: "__arrow_ext_deserialize__ method defined — if it calls cloudpickle.loads() on metadata bytes, grants RCE during schema parsing (CVE-2026-41486).".to_string(),
                    zero_day_relevance: "CVE-2026-41486: Ray Parquet cloudpickle.loads RCE (CVSS 10). CVE-2025-30065: Apache Parquet Avro schema RCE (CVSS 10).",
                });
            }
        }
    }

    for (i, line) in lines.iter().enumerate() {
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        if CLOUDPICKLE_LOADS_RE.is_match(stripped)
            && ARROW_CONTEXT_RE.is_match(&line.to_lowercase())
        {
            results.push(Finding {
                cwe_id: "CWE-502",
                cwe_name: "Deserialization of Untrusted Data (Parquet+cloudpickle)",
                severity: Severity::Critical,
                confidence: Confidence::High,
                package: String::new(),
                file: pk.to_string(),
                line: i + 1,
                code_snippet: stripped.to_string(),
                description: "cloudpickle.loads() near parquet/arrow code — potential RCE if deserializing untrusted metadata bytes (CVE-2026-41486 pattern).".to_string(),
                zero_day_relevance: "CVE-2026-41486: cloudpickle.loads on arrow extension metadata (CVSS 10).",
            });
        }
    }
    results
}

// ── check_decode_exec_chains (CWE-94) ────────────────────────────────────

static DECODE_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:base64\.(?:b64decode|urlsafe_b64decode|decodestring)|zlib\.decompress|bz2\.decompress|codecs\.decode)\s*\(",
    )
    .unwrap()
});
static EXEC_EVAL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:exec|eval)\s*\(").unwrap());
const DECODE_FN_NAMES: &[&str] = &[
    "base64.b64decode",
    "base64.urlsafe_b64decode",
    "base64.decodestring",
    "zlib.decompress",
    "bz2.decompress",
    "codecs.decode",
];

pub fn check_decode_exec_chains(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let mut results = Vec::new();

    // Multi-line chain detection: decode call followed by exec/eval within 5 lines.
    let mut decode_calls: Vec<usize> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let lineno = i + 1;
        if skip(line) {
            continue;
        }
        let stripped = line.trim();
        if DECODE_CALL_RE.is_match(stripped) {
            decode_calls.push(lineno);
        }
        if EXEC_EVAL_RE.is_match(stripped) && !decode_calls.is_empty() {
            let mut matched_dl: Option<usize> = None;
            for &dl in decode_calls.iter().rev() {
                if lineno - dl <= 5 {
                    matched_dl = Some(dl);
                    break;
                }
            }
            if let Some(dl) = matched_dl {
                results.push(Finding {
                    cwe_id: "CWE-94",
                    cwe_name: "Code Injection (decode-then-execute)",
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    package: String::new(),
                    file: pk.to_string(),
                    line: lineno,
                    code_snippet: format!("decode at line {dl}, exec at line {lineno}"),
                    description: "decode() followed by exec/eval within 5 lines — classic supply-chain obfuscation pattern (pydepgate-style).".to_string(),
                    zero_day_relevance: "pydepgate: decode-then-execute chains used in 60% of PyPI supply-chain attacks (2025-2026). Hades campaign, ChocoPoC.",
                });
                decode_calls.retain(|&d| d != dl);
            }
        }
    }

    // AST-based detection for same-line patterns.
    if let Some(tree) = tree {
        let collected = tree.collected();
        for c in &collected.calls {
            if c.func_is_bare_name
                && (c.full_attr == "exec" || c.full_attr == "eval")
                && let Some(call_fn) = &c.first_arg_call_full_attr
                && DECODE_FN_NAMES.contains(&call_fn.as_str())
            {
                results.push(Finding {
                    cwe_id: "CWE-94",
                    cwe_name: "Code Injection (inline decode-exec)",
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    package: String::new(),
                    file: pk.to_string(),
                    line: c.line,
                    code_snippet: code_at(lines, c.line),
                    description: format!(
                        "exec({call_fn}(...)) inline — direct decode-then-execute chain. Obfuscated malware delivery."
                    ),
                    zero_day_relevance: "pydepgate: inline decode-exec chains found in compromised wheels.",
                });
            }
        }
    }
    results
}

// ── check_huggingface_unsafe_download (CWE-94 / CWE-1104) ───────────────

pub fn check_huggingface_unsafe_download(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    let mut results = Vec::new();
    for c in &collected.calls {
        // Recover the bare call name the way check_name() would (last
        // dotted segment, or the whole thing if it wasn't a dotted attr
        // access) -- collected.calls only stores full_attr, so reconstruct.
        let name = c.full_attr.rsplit('.').next().unwrap_or(&c.full_attr);
        // trust_remote_code=True carries the same RCE risk on
        // datasets.load_dataset()/transformers.pipeline() as it does on
        // from_pretrained() -- not just from_pretrained -- so all three
        // call names are checked for it. The unpinned-revision heuristic
        // (CWE-1104) below stays scoped to from_pretrained only, the call
        // name it was written against. Mirrors the Python fix.
        if !matches!(name, "from_pretrained" | "load_dataset" | "pipeline") {
            continue;
        }
        let trust_remote_code = c
            .keyword_true_names
            .iter()
            .any(|n| n == "trust_remote_code");
        if trust_remote_code {
            results.push(Finding {
                cwe_id: "CWE-94",
                cwe_name: "Code Injection (HuggingFace trust_remote_code)",
                severity: Severity::Critical,
                confidence: Confidence::High,
                package: String::new(),
                file: pk.to_string(),
                line: c.line,
                code_snippet: code_at(lines, c.line),
                description: "from_pretrained(trust_remote_code=True) executes arbitrary Python shipped in the model repo at load time — equivalent to running code from an untrusted third party.".to_string(),
                zero_day_relevance: "Malicious HuggingFace repos with trust_remote_code payloads have been used for real supply-chain RCE against ML pipelines.",
            });
        } else if name == "from_pretrained" && !c.keyword_names.iter().any(|n| n == "revision") {
            results.push(Finding {
                cwe_id: "CWE-1104",
                cwe_name: "Supply Chain — Unpinned Model Revision",
                severity: Severity::Medium,
                confidence: Confidence::High,
                package: String::new(),
                file: pk.to_string(),
                line: c.line,
                code_snippet: code_at(lines, c.line),
                description: "from_pretrained(...) with no revision= pin follows the model repo's moving main ref — weights or code can change under this call site with no local diff to review. Pin revision= to a specific commit SHA or tag.".to_string(),
                zero_day_relevance: "OWASP ML06: unpinned model sources are a supply-chain vector — a compromised or malicious upstream repo push propagates silently on next load.",
            });
        }
    }
    results
}

// ── check_unbounded_pydantic_field (CWE-770 / OWASP API4:2023) ───────────

pub fn check_unbounded_pydantic_field(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();

    collected
        .pydantic_fields
        .iter()
        .filter(|f| !f.has_constraint)
        .map(|f| Finding {
            cwe_id: "CWE-770",
            cwe_name: "Unbounded Request Field Size",
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            package: String::new(),
            file: pk.to_string(),
            line: f.line,
            code_snippet: code_at(lines, f.line),
            description: format!(
                "'{}: {}' has no length constraint — a client can send an arbitrarily large value, forcing expensive decode/validation work before any handler logic runs. Add Field(max_length=...) or an Annotated[str, StringConstraints(max_length=...)].",
                f.field_name, f.base_type
            ),
            zero_day_relevance: "OWASP API4:2023: Unrestricted Resource Consumption — unbounded request fields are a common DoS vector in FastAPI/Pydantic APIs.",
        })
        .collect()
}

// ── Converted from line-regex checks (Phase 2) ────────────────────────────
//
// Mirrors the same block in `ast_checks.py`: each of these used to regex a
// line of source. Matching the AST means a quoted mention can't match,
// `pkg.pickle.loads(...)` is recognised while `cloudpickle.loads(...)` is
// kept distinct, keywords are inspected rather than pattern-matched, and a
// call with only literal arguments can be told apart from one fed data.

#[allow(clippy::too_many_arguments)]
fn ast_finding(
    cwe_id: &'static str,
    cwe_name: &'static str,
    severity: Severity,
    confidence: Confidence,
    pk: &str,
    lines: &[String],
    line: usize,
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
        code_snippet: code_at(lines, line),
        description,
        zero_day_relevance,
    }
}

const PICKLE_ZERO_DAY: &str = "CVE-2026-56315 picklescan <1.0.4 bypass (uuid, imaplib etc. unblocked); \
CVE-2026-0763 GPT Academic CVSS 9.8; LangChain CVE-2025-68664 SSTI+pickle chain";

const PICKLE_CALLS: &[(&str, &str, Severity)] = &[
    (
        "pickle.loads",
        "pickle.loads() / pickle.load()",
        Severity::Critical,
    ),
    (
        "pickle.load",
        "pickle.loads() / pickle.load()",
        Severity::Critical,
    ),
    ("pickle.Unpickler", "pickle.Unpickler()", Severity::Critical),
    (
        "cloudpickle.loads",
        "cloudpickle.loads() / cloudpickle.load()",
        Severity::Critical,
    ),
    (
        "cloudpickle.load",
        "cloudpickle.loads() / cloudpickle.load()",
        Severity::Critical,
    ),
    (
        "dill.loads",
        "dill.loads() / dill.load()",
        Severity::Critical,
    ),
    (
        "dill.load",
        "dill.loads() / dill.load()",
        Severity::Critical,
    ),
    ("joblib.load", "joblib.load()", Severity::High),
    ("shelve.open", "shelve.open()", Severity::High),
    (
        "marshal.loads",
        "marshal.loads() / marshal.load()",
        Severity::High,
    ),
    (
        "marshal.load",
        "marshal.loads() / marshal.load()",
        Severity::High,
    ),
];

pub fn check_pickle(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    let mut results = Vec::new();
    for call in &collected.calls {
        if let Some((_, label, sev)) = PICKLE_CALLS
            .iter()
            .find(|(name, _, _)| dotted_matches(&call.full_attr, name))
        {
            results.push(ast_finding(
                "CWE-502",
                "Deserialization of Untrusted Data",
                *sev,
                Confidence::High,
                pk,
                lines,
                call.line,
                format!("Unsafe deserialisation via {label}. Allows arbitrary code execution."),
                PICKLE_ZERO_DAY,
            ));
        }
    }
    results
}

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

pub fn check_command_injection(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    let mut results = Vec::new();
    for call in &collected.calls {
        let matched = COMMAND_CALLS
            .iter()
            .find(|(name, _)| dotted_matches(&call.full_attr, name));
        let shell = call.keyword_true_names.iter().any(|k| k == "shell");
        if matched.is_none() && !shell {
            continue;
        }
        let Some((confidence, note)) = confidence_for(call.command_taint) else {
            continue;
        };
        if let Some((name, sev)) = matched {
            results.push(ast_finding(
                "CWE-78",
                "OS Command Injection",
                *sev,
                confidence,
                pk,
                lines,
                call.line,
                format!("{name}() spawns subprocesses; may allow command injection if arguments are unvalidated.{note}"),
                "CWE-78: 20 CVEs in KEV. Still a top Python zero-day vector.",
            ));
        }
        if shell {
            results.push(ast_finding(
                "CWE-78",
                "OS Command Injection",
                Severity::High,
                confidence,
                pk,
                lines,
                call.line,
                format!("shell=True enables shell injection in subprocess calls.{note}"),
                "",
            ));
        }
    }
    results
}

pub fn check_yaml_deserialize(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    let mut results = Vec::new();
    for call in &collected.calls {
        let flagged = if dotted_matches(&call.full_attr, "yaml.load") {
            !call
                .arg_dotted_names
                .iter()
                .any(|d| d.contains("SafeLoader"))
        } else {
            dotted_matches(&call.full_attr, "yaml.unsafe_load")
        };
        if flagged {
            results.push(ast_finding(
                "CWE-502",
                "Deserialization of Untrusted Data",
                Severity::Critical,
                Confidence::High,
                pk,
                lines,
                call.line,
                "yaml.load()/yaml.unsafe_load() without SafeLoader — enables arbitrary code execution.".to_string(),
                "CVE-2026-24009: Docling RCE via PyYAML shadow vulnerability. \
Transitive YAML deps can introduce RCE without a direct yaml import.",
            ));
        }
    }
    results
}

pub fn check_ssti(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    collected
        .calls
        .iter()
        .filter(|c| c.call_name == "Template")
        .filter_map(|c| confidence_for(c.data_taint).map(|t| (c, t)))
        .map(|(c, (confidence, note))| {
            ast_finding(
                "CWE-1336",
                "Server-Side Template Injection",
                Severity::High,
                confidence,
                pk,
                lines,
                c.line,
                format!("Template instantiation — SSTI if template string is user-controlled.{note}"),
                "CVE-2025-68664: LangChain Core SSTI zero-day chaining deserialisation + Jinja2 for RCE.",
            )
        })
        .collect()
}

pub fn check_crlf(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    // Several hits on one line report once, at the worst taint among them.
    let mut by_line: BTreeMap<usize, Taint> = BTreeMap::new();
    let format_calls = collected
        .calls
        .iter()
        .filter(|c| c.is_crlf_format_call)
        .map(|c| (c.line, c.data_taint));
    for (line, taint) in collected.crlf_combos.iter().copied().chain(format_calls) {
        let worst = by_line.entry(line).or_insert(Taint::Clean);
        *worst = (*worst).max(taint);
    }
    by_line
        .into_iter()
        .filter_map(|(line, taint)| confidence_for(taint).map(|t| (line, t)))
        .map(|(line, (confidence, note))| {
            ast_finding(
                "CWE-93",
                "CRLF Injection",
                Severity::High,
                confidence,
                pk,
                lines,
                line,
                format!("CRLF sequence combined with non-literal data — may enable HTTP response splitting / log injection.{note}"),
                "",
            )
        })
        .collect()
}

const WEAK_HASH_NAMES: &[&str] = &["md5", "md4", "md2", "sha1"];

pub fn check_weak_hash(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    let mut results = Vec::new();
    for call in &collected.calls {
        if call
            .keyword_false_names
            .iter()
            .any(|k| k == "usedforsecurity")
        {
            continue;
        }
        let fa = call.full_attr.as_str();
        if dotted_matches(fa, "hashlib.md5") || dotted_matches(fa, "hashlib.sha1") {
            results.push(ast_finding(
                "CWE-328",
                "Weak Cryptographic Hash",
                Severity::Medium,
                Confidence::High,
                pk,
                lines,
                call.line,
                "Use of MD5/SHA-1 — collision-prone, use SHA-256 or better.".to_string(),
                "",
            ));
        } else if dotted_matches(fa, "hashlib.new")
            && call
                .first_arg_str
                .as_deref()
                .is_some_and(|a| WEAK_HASH_NAMES.contains(&a.to_ascii_lowercase().as_str()))
        {
            results.push(ast_finding(
                "CWE-328",
                "Weak Cryptographic Hash",
                Severity::Medium,
                Confidence::High,
                pk,
                lines,
                call.line,
                "hashlib.new() with a weak algorithm name (MD5/MD4/MD2/SHA-1) — \
same collision risk as calling hashlib.md5()/sha1() directly, \
just reached through the generic constructor. Use SHA-256 or better."
                    .to_string(),
                "",
            ));
        }
    }
    results
}

pub fn check_open_redirect(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    collected
        .calls
        .iter()
        .filter(|c| c.call_name == "redirect" || c.call_name == "Redirect")
        .filter_map(|c| confidence_for(c.data_taint).map(|t| (c, t)))
        .map(|(c, (confidence, note))| {
            ast_finding(
                "CWE-601",
                "Open Redirect",
                Severity::Medium,
                confidence,
                pk,
                lines,
                c.line,
                format!(
                    "URL redirect — ensure destination is validated against an allowlist.{note}"
                ),
                "",
            )
        })
        .collect()
}

const TLS_ZERO_DAY: &str = "CWE-295 is #8 in CWE Top 25. TLS bypass zero-days (e.g. CVE-2026-27834 Python \
CERT_NONE in urllib) enable MITM on every connection.";

pub fn check_tls_verify(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    // (line, description) in source order, first description per line wins --
    // mirrors the Python version's walk order closely enough that the
    // conformance corpus (which compares line/severity/confidence, not
    // message text) can't tell them apart.
    let mut hits: Vec<(usize, &'static str)> = Vec::new();
    for call in &collected.calls {
        if call.keyword_false_names.iter().any(|k| k == "verify") {
            hits.push((
                call.line,
                "HTTP/S3 client with verify=False — TLS certificate validation disabled.",
            ));
        }
        if call
            .keyword_false_names
            .iter()
            .any(|k| k == "check_hostname")
        {
            hits.push((
                call.line,
                "Hostname verification disabled — no TLS identity check.",
            ));
        }
        if call.call_name == "_create_unverified_context" {
            hits.push((
                call.line,
                "ssl._create_unverified_context() — creates unverified TLS context.",
            ));
        }
    }
    for &(line, ref name, value) in &collected.bool_assigns {
        if name == "check_hostname" && !value {
            hits.push((
                line,
                "Hostname verification disabled — no TLS identity check.",
            ));
        }
    }
    for &(line, in_compare) in &collected.cert_none_refs {
        if !in_compare {
            hits.push((
                line,
                "ssl.CERT_NONE — peer certificate not verified, man-in-the-middle possible.",
            ));
        }
    }
    hits.sort_by_key(|(line, _)| *line);
    let mut seen = HashSet::new();
    hits.into_iter()
        .filter(|(line, _)| seen.insert(*line))
        .map(|(line, desc)| {
            ast_finding(
                "CWE-295",
                "Improper Certificate Validation",
                Severity::Critical,
                Confidence::High,
                pk,
                lines,
                line,
                desc.to_string(),
                TLS_ZERO_DAY,
            )
        })
        .collect()
}

// ── Phase 2, second increment ─────────────────────────────────────────────

const SQL_EXEC_METHOD_NAMES: &[&str] = &["execute", "exec_driver_sql"];

pub fn check_sql_injection(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let mut results = Vec::new();
    for call in &tree.collected().calls {
        let name = call.call_name.as_str();
        if !SQL_EXEC_METHOD_NAMES.contains(&name) {
            continue;
        }
        let (Some(shape), Some(taint)) = (call.first_arg_sql_shape, call.first_arg_taint) else {
            continue;
        };
        let Some((confidence, note)) = confidence_for(taint) else {
            continue;
        };
        let desc = if shape == "f-string" {
            format!("f-string in {name}() — probable SQL injection{note}")
        } else {
            format!(
                "String concatenation or %-formatting in {name}() — probable SQL injection{note}"
            )
        };
        results.push(ast_finding(
            "CWE-89",
            "SQL Injection",
            Severity::Critical,
            confidence,
            pk,
            lines,
            call.line,
            desc,
            "CWE-89 rose to #2 in 2025 Top 25. Most exploited injection class after XSS.",
        ));
    }
    results
}

pub fn check_exec_driver_sql(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let mut results = Vec::new();
    for call in &tree.collected().calls {
        if call.call_name != "exec_driver_sql" || call.first_arg_sql_shape != Some("f-string") {
            continue;
        }
        let Some((confidence, note)) = call.first_arg_taint.and_then(confidence_for) else {
            continue;
        };
        results.push(ast_finding(
            "CWE-89",
            "SQL Injection",
            Severity::Critical,
            confidence,
            pk,
            lines,
            call.line,
            format!("exec_driver_sql() with f-string — direct SQL injection.{note}"),
            "",
        ));
    }
    results
}

const SSRF_METHOD_NAMES: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "request",
];
const SSRF_SESSION_CONSTRUCTORS: &[&str] = &[
    "requests.Session",
    "httpx.Client",
    "httpx.AsyncClient",
    "aiohttp.ClientSession",
];

fn ssrf_url_arg(call: &ExprCall) -> Option<&Expr> {
    call.args.first().or_else(|| {
        call.keywords
            .iter()
            .find(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == "url"))
            .map(|kw| &kw.value)
    })
}

pub fn check_ssrf(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let li = tree.line_index();
    let aliases = &tree.collected().aliases;
    let mut results = Vec::new();
    for scoped in tree.scoped_calls() {
        let fa = resolve_dotted(&full_attr(&scoped.call.func), aliases);
        let method = call_name(&scoped.call);
        let is_method = SSRF_METHOD_NAMES.contains(&method.as_str());
        let is_module_call = fa == "urllib.request.urlopen"
            || (is_method
                && ["requests", "httpx"]
                    .iter()
                    .any(|m| dotted_matches(&fa, &format!("{m}.{method}"))));
        let mut is_session_call = false;
        if !is_module_call
            && is_method
            && let Expr::Attribute(attr) = scoped.call.func.as_ref()
            && let Expr::Name(base) = attr.value.as_ref()
            && let Some(Expr::Call(bound)) = scoped.literals.get(base.id.as_str())
        {
            let ctor = resolve_dotted(&full_attr(&bound.func), aliases);
            is_session_call = SSRF_SESSION_CONSTRUCTORS.contains(&ctor.as_str());
        }
        if !(is_module_call || is_session_call) {
            continue;
        }
        let Some(url) = ssrf_url_arg(&scoped.call) else {
            continue;
        };
        let taint = tree.taint().classify(scoped.call.start(), [url]);
        let Some((confidence, note)) = confidence_for(taint) else {
            continue;
        };
        results.push(ast_finding(
            "CWE-918",
            "Server-Side Request Forgery",
            Severity::High,
            confidence,
            pk,
            lines,
            li.line_number(scoped.call.start()),
            format!("HTTP request — verify URL is validated against allowlist; SSRF if user-controlled.{note}"),
            "CWE-918 fell to #22 but SSRF zero-days (cloud metadata exfiltration) remain critical.",
        ));
    }
    results
}

static NESTED_QUANTIFIER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\([^)]+[+*?]\)[+*?{]").unwrap());
const REGEX_COMPILE_CALLS: &[&str] = &["re.compile", "re.match", "re.search"];

pub fn check_redos(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    tree.collected()
        .calls
        .iter()
        .filter(|c| {
            REGEX_COMPILE_CALLS
                .iter()
                .any(|n| dotted_matches(&c.full_attr, n))
        })
        .filter(|c| {
            c.first_arg_str
                .as_deref()
                .is_some_and(|p| NESTED_QUANTIFIER_RE.is_match(p))
        })
        .map(|c| {
            ast_finding(
                "CWE-1333",
                "ReDoS (Catastrophic Backtracking)",
                Severity::Medium,
                Confidence::Low,
                pk,
                lines,
                c.line,
                "Nested quantifier pattern — potential ReDoS (catastrophic backtracking)."
                    .to_string(),
                "ReDoS zero-days have been used to DoS auth gateways. CWE-1333 new to OWASP 2025.",
            )
        })
        .collect()
}

static STREAMING_CONTEXT_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r"chunk|iter_content|stream")
        .case_insensitive(true)
        .build()
        .unwrap()
});

pub fn check_resource_limits(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    tree.collected()
        .calls
        .iter()
        .filter(|c| !c.func_is_bare_name && c.call_name == "read" && !c.has_args)
        .filter(|c| !STREAMING_CONTEXT_RE.is_match(&code_at(lines, c.line)))
        .map(|c| {
            ast_finding(
                "CWE-770",
                "Unbounded Resource Allocation",
                Severity::Info,
                Confidence::High,
                pk,
                lines,
                c.line,
                "Unbounded .read() — may exhaust memory on large inputs. Use .read(n) or streaming.".to_string(),
                "CWE-770 entered Top 25 at #25 in 2025.",
            )
        })
        .collect()
}

fn is_file_move_or_copy(fa: &str) -> bool {
    let (head, tail) = fa.rsplit_once('.').unwrap_or(("", fa));
    dotted_matches(fa, "shutil.move")
        || dotted_matches(fa, "os.rename")
        || (tail.starts_with("copy") && (head == "shutil" || head.ends_with(".shutil")))
}

pub fn check_arbitrary_write(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    tree.collected()
        .calls
        .iter()
        .filter(|c| is_file_move_or_copy(&c.full_attr))
        .filter_map(|c| confidence_for(c.data_taint).map(|t| (c, t)))
        .map(|(c, (confidence, note))| {
            ast_finding(
                "CWE-73",
                "External Control of File Name",
                Severity::Medium,
                confidence,
                pk,
                lines,
                c.line,
                format!("File operation — verify destination path is validated to prevent arbitrary write.{note}"),
                "",
            )
        })
        .collect()
}

pub fn check_zipslip(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    tree.collected()
        .calls
        .iter()
        .filter(|c| !c.func_is_bare_name && c.call_name == "extractall")
        .filter(|c| {
            c.n_positional < 2 && !c.keyword_names.iter().any(|k| k == "members" || k == "filter")
        })
        .map(|c| {
            ast_finding(
                "CWE-22",
                "Path Traversal — ZipSlip / TarSlip",
                Severity::High,
                Confidence::High,
                pk,
                lines,
                c.line,
                "extractall() without path traversal guard — an archive with ../ entries can overwrite arbitrary files.".to_string(),
                "ZipSlip zero-day pattern: path traversal in archive extraction enables RCE via overwritten binaries (CVE-2026-20624 Python tarfile).",
            )
        })
        .collect()
}

fn is_pandas_fn(fa: &str, name: &str) -> bool {
    dotted_matches(fa, &format!("pandas.{name}")) || dotted_matches(fa, &format!("pd.{name}"))
}

pub fn check_pandas_pickle(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    tree.collected()
        .calls
        .iter()
        .filter(|c| is_pandas_fn(&c.full_attr, "read_pickle"))
        .map(|c| {
            ast_finding(
                "CWE-502",
                "Deserialization of Untrusted Data (read_pickle)",
                Severity::Critical,
                Confidence::High,
                pk,
                lines,
                c.line,
                "pd.read_pickle() deserializes Python objects via pickle — arbitrary code execution if file is untrusted.".to_string(),
                "Trail of Bits: pandas.read_pickle() uses pickle.load() under the hood — standard pickle RCE.",
            )
        })
        .collect()
}

pub fn check_pandas_xml_xxe(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    tree.collected()
        .calls
        .iter()
        .filter(|c| is_pandas_fn(&c.full_attr, "read_xml"))
        .filter(|c| !c.keyword_names.iter().any(|k| k == "parser"))
        .map(|c| {
            ast_finding(
                "CWE-611",
                "XXE via pandas.read_xml",
                Severity::High,
                Confidence::High,
                pk,
                lines,
                c.line,
                "pd.read_xml() defaults to lxml parser — may be vulnerable to XXE. Use parser='etree' or defusedxml.".to_string(),
                "Trail of Bits: pandas.read_xml with lxml parser enables XXE attacks on XML data pipelines.",
            )
        })
        .collect()
}

const TORCH_MODEL_EXTS: &[&str] = &[".pt", ".pth", ".ckpt"];
const PICKLE_MODEL_EXTS: &[&str] = &[".pt", ".pkl", ".h5", ".joblib", ".ckpt"];
const PICKLE_LOAD_FAMILY: &[&str] = &[
    "joblib.load",
    "pickle.load",
    "cloudpickle.load",
    "dill.load",
];
const KERAS_LOAD_MODEL: &[&str] = &[
    "tf.load_model",
    "tf.models.load_model",
    "keras.load_model",
    "keras.models.load_model",
];

pub fn check_model_file_load(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let mut results = Vec::new();
    for c in &tree.collected().calls {
        let fa = c.full_attr.as_str();
        if dotted_matches(fa, "torch.load")
            && c.str_args
                .iter()
                .any(|s| TORCH_MODEL_EXTS.iter().any(|e| s.ends_with(e)))
        {
            let guarded = c.keyword_names.iter().any(|k| k == "weights_only")
                && !c.keyword_false_names.iter().any(|k| k == "weights_only");
            results.push(ast_finding(
                "CWE-502",
                "Deserialization of Untrusted Data (ML Model)",
                if guarded { Severity::Low } else { Severity::Critical },
                Confidence::High,
                pk,
                lines,
                c.line,
                format!(
                    "torch.load() on model file{}. Prefer SafeTensors format for untrusted model files.",
                    if guarded { "" } else { " without weights_only=True" }
                ),
                "OWASP ML06: pickle-based model formats enable RCE via malicious model files. SafeTensors mitigates this by design.",
            ));
        } else if PICKLE_LOAD_FAMILY.iter().any(|n| dotted_matches(fa, n))
            && let Some(ext) = c
                .str_args
                .iter()
                .find_map(|s| PICKLE_MODEL_EXTS.iter().find(|e| s.ends_with(*e)))
        {
            results.push(ast_finding(
                "CWE-502",
                "Deserialization of Untrusted Data (ML Model)",
                Severity::High,
                Confidence::High,
                pk,
                lines,
                c.line,
                format!("pickle-based load on {ext} file — arbitrary code execution via malicious model. Prefer SafeTensors for untrusted model files."),
                "OWASP ML06: 80% of ML supply-chain attacks exploit pickle-based model formats.",
            ));
        } else if KERAS_LOAD_MODEL.iter().any(|n| dotted_matches(fa, n)) {
            results.push(ast_finding(
                "CWE-502",
                "Deserialization of Untrusted Data (Keras Model)",
                Severity::High,
                Confidence::High,
                pk,
                lines,
                c.line,
                "tf.keras.models.load_model() can deserialize arbitrary Python objects via custom layers/optimizers. Prefer SafeTensors for untrusted models.".to_string(),
                "OWASP ML06: Keras H5 format carries pickle-like deserialization risk.",
            ));
        }
    }
    results
}

pub fn check_path_traversal(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let mut results = Vec::new();
    for c in &tree.collected().calls {
        // For `x.lstrip("/")` the value being "sanitised" is the receiver.
        let (taint, severity, description, zero_day) = if c.call_name == "lstrip"
            && c.first_arg_str.as_deref() == Some("/")
            && let Some(receiver) = c.receiver_taint
        {
            (
                receiver,
                Severity::High,
                "lstrip('/') does NOT prevent ../ traversal — use Path.resolve() + is_relative_to().",
                "CWE-22 is #6 in Top 25 with 10 CVEs in KEV.",
            )
        } else if c.call_name == "open" && c.arg_names.iter().any(|n| n.contains("relative_path")) {
            (
                c.data_taint,
                Severity::Medium,
                "Variable named 'relative_path' used in open() — verify ../ is rejected with Path.resolve().",
                "",
            )
        } else {
            continue;
        };
        let Some((confidence, note)) = confidence_for(taint) else {
            continue;
        };
        results.push(ast_finding(
            "CWE-22",
            "Path Traversal",
            severity,
            confidence,
            pk,
            lines,
            c.line,
            format!("{description}{note}"),
            zero_day,
        ));
    }
    results
}

pub fn check_debug_mode(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let collected = tree.collected();
    let mut hit_lines: Vec<usize> = collected
        .calls
        .iter()
        .filter(|c| c.keyword_true_names.iter().any(|k| k == "debug"))
        .map(|c| c.line)
        .collect();
    hit_lines.extend(
        collected
            .bool_assigns
            .iter()
            .filter(|(_, name, value)| name == "debug" && *value)
            .map(|(line, _, _)| *line),
    );
    hit_lines.sort_unstable();
    hit_lines
        .into_iter()
        .map(|line| {
            ast_finding(
                "CWE-489",
                "Active Debug Code",
                Severity::Medium,
                Confidence::Low,
                pk,
                lines,
                line,
                "Hardcoded debug=True — may expose sensitive info in production.".to_string(),
                "",
            )
        })
        .collect()
}

pub fn check_bind_all_interfaces(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let mut hit_lines = tree.collected().bind_all_lines.clone();
    hit_lines.sort_unstable();
    hit_lines.dedup();
    hit_lines
        .into_iter()
        .map(|line| {
            ast_finding(
                "CWE-1327",
                "Binding to an Unrestricted IP Address",
                Severity::Medium,
                Confidence::High,
                pk,
                lines,
                line,
                "Host bound to 0.0.0.0 — listens on every network interface, not just localhost. Bind to 127.0.0.1 unless external access is actually required.".to_string(),
                "B104: services accidentally exposed on all interfaces are a common initial-access vector once a container/VM's network boundary is misconfigured.",
            )
        })
        .collect()
}

pub fn check_weak_tls_version(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let mut seen = HashSet::new();
    tree.collected()
        .weak_tls_refs
        .iter()
        .filter(|(line, _)| seen.insert(*line))
        .map(|(line, name)| {
            ast_finding(
                "CWE-326",
                "Inadequate Encryption Strength",
                Severity::High,
                Confidence::High,
                pk,
                lines,
                *line,
                format!("{name} — explicitly requests a deprecated, broken SSL/TLS protocol version. Use ssl.PROTOCOL_TLS_CLIENT/SERVER (or omit ssl_version entirely) to let Python negotiate the strongest mutually-supported version."),
                "B502/B503/B504: SSLv3 enables POODLE, TLSv1.0/1.1 are formally deprecated by RFC 8996 — still found in legacy integration code talking to old servers.",
            )
        })
        .collect()
}

pub fn check_legacy_pycrypto(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    tree.collected()
        .import_stmts
        .iter()
        .filter(|(_, roots)| roots.iter().any(|r| r == "Crypto"))
        .map(|(line, _)| {
            ast_finding(
                "CWE-1104",
                "Supply Chain — Unmaintained Dependency",
                Severity::Medium,
                Confidence::High,
                pk,
                lines,
                *line,
                "Imports the old PyCrypto package (unmaintained since 2013, several unpatched CVEs) — migrate to pycryptodome (`import Cryptodome` / `from Cryptodome import ...`), a maintained drop-in replacement.".to_string(),
                "PyCrypto has no security fixes for over a decade; several known vulnerabilities (e.g. weak RNG seeding in old releases) remain unpatched.",
            )
        })
        .collect()
}
