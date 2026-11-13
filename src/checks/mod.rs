//! Aggregates every check function into a single ordered registry
//! -- mirrors `fenceline/checks/__init__.py`. Same order as the Python
//! `_BUILTIN_CHECKS` list, for easy side-by-side diffing.

pub mod ast_checks;
pub mod manifest_checks;
pub mod text_checks;

use crate::analysis::ParsedFile;
use crate::models::Finding;
use std::path::Path;

/// `(path, package-relative-path, lines, parsed AST or None)` -> findings.
/// Matches Python's `(path, lines, tree) -> list[Finding]` shape, plus an
/// already-computed relative path string (`pk` in the Python original, but
/// computed once per file here rather than once per check call).
pub type CheckFn = fn(&Path, &str, &[String], Option<&ParsedFile>) -> Vec<Finding>;

/// Which view of the file a check scans -- mirrors
/// `checks/__init__.py::lines_for`. Line-regex checks can't tell code from
/// prose, so they get `CodeOnly`: comments and string-only statements
/// (docstrings, bare `"..."` block comments) blanked to spaces by
/// `scanner::mask_non_code`, columns preserved. AST and manifest checks get
/// the raw lines. Trojan Source is the deliberate exception among the text
/// checks: bidi overrides hidden *inside* comments and strings are exactly
/// what it exists to catch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineView {
    Raw,
    CodeOnly,
}

pub struct Check {
    pub display: &'static str,
    /// The Rust function name (== the Python function it mirrors). Fixture
    /// directories are keyed by it (`fixtures/check_pickle/...`), not by the
    /// display string; `stringify!` guarantees it can't drift.
    pub fn_name: &'static str,
    pub run: CheckFn,
    pub view: LineView,
}

macro_rules! check {
    ($display:expr, $name:ident, $view:ident) => {
        Check {
            display: $display,
            fn_name: stringify!($name),
            run: $name as CheckFn,
            view: LineView::$view,
        }
    };
}

pub fn checks() -> Vec<Check> {
    use ast_checks::*;
    use manifest_checks::*;
    use text_checks::*;

    vec![
        check!("Pickle Deserialization (CWE-502)", check_pickle, Raw),
        check!("eval/exec/compile Injection (CWE-94)", check_eval_exec, Raw),
        check!("Command Injection (CWE-78)", check_command_injection, Raw),
        check!("SQL Injection (CWE-89)", check_sql_injection, Raw),
        check!("Path Traversal (CWE-22)", check_path_traversal, Raw),
        check!("Hardcoded Secrets (CWE-798)", check_hardcoded_secrets, Raw),
        check!(
            "YAML Unsafe Deserialization (CWE-502)",
            check_yaml_deserialize,
            Raw
        ),
        check!("XXE (CWE-611)", check_xxe, CodeOnly),
        check!("SSRF (CWE-918)", check_ssrf, Raw),
        check!("Insecure Temp File (CWE-377)", check_tempfile, Raw),
        check!("Symlink Following (CWE-61)", check_symlink, CodeOnly),
        check!("ReDoS (CWE-1333)", check_redos, Raw),
        check!(
            "Assert Security (CWE-617/670)",
            check_assert_security,
            CodeOnly
        ),
        check!(
            "exec_driver_sql Safety (CWE-89)",
            check_exec_driver_sql,
            Raw
        ),
        check!(
            "Supply Chain Dep Confusion (CWE-1104)",
            check_supply_chain,
            CodeOnly
        ),
        check!("Active Debug Code (CWE-489)", check_debug_mode, Raw),
        check!(
            "Insufficient Logging (CWE-778)",
            check_insufficient_logging,
            Raw
        ),
        check!("Timing Attack (CWE-208)", check_timing_attack, CodeOnly),
        check!(
            "Sensitive Exposure (CWE-200)",
            check_sensitive_exposure,
            CodeOnly
        ),
        check!("NUL Byte Injection (CWE-158)", check_null_byte, CodeOnly),
        check!("Resource Limits (CWE-770)", check_resource_limits, Raw),
        check!("Insecure Random (CWE-338)", check_insecure_random, Raw),
        check!("SSTI (CWE-1336)", check_ssti, Raw),
        check!("CRLF Injection (CWE-93)", check_crlf, Raw),
        check!("LDAP Injection (CWE-90)", check_ldap, CodeOnly),
        check!("Weak Hash (CWE-328)", check_weak_hash, Raw),
        check!("Open Redirect (CWE-601)", check_open_redirect, Raw),
        check!("Log Injection (CWE-117)", check_log_injection, Raw),
        check!("Format String (CWE-134)", check_format_string, Raw),
        check!("Arbitrary File Write (CWE-73)", check_arbitrary_write, Raw),
        check!("Insecure Default (CWE-453)", check_insecure_default, Raw),
        check!("Log Secrets (CWE-532)", check_log_secrets, Raw),
        check!("Disabled TLS Verify (CWE-295)", check_tls_verify, Raw),
        check!("ZipSlip / TarSlip (CWE-22)", check_zipslip, Raw),
        check!("Hardcoded API Keys (CWE-798)", check_hardcoded_tokens, Raw),
        check!("Weak Crypto (CWE-327)", check_weak_crypto, CodeOnly),
        check!("Dependency CVE Scan (CWE-1104)", check_dependency_cve, Raw),
        check!("Trojan Source (CWE-1007)", check_trojan_source, Raw),
        check!(
            "HTTP Request Timeout (CWE-1088)",
            check_request_timeout,
            Raw
        ),
        check!("torch.load weights_only (CWE-502)", check_torch_load, Raw),
        check!(
            "SSH Host Key Verification (CWE-322)",
            check_ssh_host_key,
            CodeOnly
        ),
        check!("except:pass/continue (CWE-391)", check_except_pass, Raw),
        check!(
            "pandas eval/query Code Injection (CWE-94)",
            check_pandas_eval,
            Raw
        ),
        check!("numpy.load allow_pickle (CWE-502)", check_numpy_load, Raw),
        check!("pandas.read_pickle (CWE-502)", check_pandas_pickle, Raw),
        check!(
            "numpy.load library injection (CWE-114)",
            check_numpy_load_lib,
            Raw
        ),
        check!("pandas.read_xml XXE (CWE-611)", check_pandas_xml_xxe, Raw),
        check!(
            ".pth Startup Hooks (CWE-829 / T1546.018)",
            check_pth_startup_hooks,
            CodeOnly
        ),
        check!(
            "Parquet Arrow Deserialization (CWE-502 / CVE-2026-41486)",
            check_parquet_arrow_deserialize,
            Raw
        ),
        check!(
            "Unbounded Dependency Pins (CWE-1104)",
            check_unbounded_pins,
            Raw
        ),
        check!(
            "ML Model File Loading (OWASP ML06 / CWE-502)",
            check_model_file_load,
            Raw
        ),
        check!(
            "Decode-then-Execute Chains (CWE-94)",
            check_decode_exec_chains,
            Raw
        ),
        check!(
            "Binding to All Interfaces (CWE-1327)",
            check_bind_all_interfaces,
            Raw
        ),
        check!(
            "Weak TLS Protocol Version (CWE-326)",
            check_weak_tls_version,
            Raw
        ),
        check!(
            "Legacy PyCrypto Import (CWE-1104)",
            check_legacy_pycrypto,
            Raw
        ),
        check!(
            "HuggingFace Unsafe Download (OWASP ML06 / B615)",
            check_huggingface_unsafe_download,
            Raw
        ),
        check!(
            "Unbounded Request Field Size (OWASP API4:2023 / CWE-770)",
            check_unbounded_pydantic_field,
            Raw
        ),
    ]
}
