//! Aggregates every check function into a single ordered `CHECKS` registry
//! -- mirrors `fenceline/checks/__init__.py`. Same order as the Python
//! `_BUILTIN_CHECKS` list, for easy side-by-side diffing.

pub mod ast_checks;
pub mod manifest_checks;
pub mod text_checks;

use crate::models::Finding;
use rustpython_ast::ModModule;
use std::path::Path;

/// `(path, package-relative-path, lines, parsed AST or None)` -> findings.
/// Matches Python's `(path, lines, tree) -> list[Finding]` shape, plus an
/// already-computed relative path string (`pk` in the Python original, but
/// computed once per file here rather than once per check call).
pub type CheckFn = fn(&Path, &str, &[String], Option<&ModModule>) -> Vec<Finding>;

pub fn checks() -> Vec<(&'static str, CheckFn)> {
    use ast_checks::*;
    use manifest_checks::*;
    use text_checks::*;

    vec![
        ("Pickle Deserialization (CWE-502)", check_pickle),
        ("eval/exec/compile Injection (CWE-94)", check_eval_exec),
        ("Command Injection (CWE-78)", check_command_injection),
        ("SQL Injection (CWE-89)", check_sql_injection),
        ("Path Traversal (CWE-22)", check_path_traversal),
        ("Hardcoded Secrets (CWE-798)", check_hardcoded_secrets),
        (
            "YAML Unsafe Deserialization (CWE-502)",
            check_yaml_deserialize,
        ),
        ("XXE (CWE-611)", check_xxe),
        ("SSRF (CWE-918)", check_ssrf),
        ("Insecure Temp File (CWE-377)", check_tempfile),
        ("Symlink Following (CWE-61)", check_symlink),
        ("ReDoS (CWE-1333)", check_redos),
        ("Assert Security (CWE-617/670)", check_assert_security),
        ("exec_driver_sql Safety (CWE-89)", check_exec_driver_sql),
        ("Supply Chain Dep Confusion (CWE-1104)", check_supply_chain),
        ("Active Debug Code (CWE-489)", check_debug_mode),
        ("Insufficient Logging (CWE-778)", check_insufficient_logging),
        ("Timing Attack (CWE-208)", check_timing_attack),
        ("Sensitive Exposure (CWE-200)", check_sensitive_exposure),
        ("NUL Byte Injection (CWE-158)", check_null_byte),
        ("Resource Limits (CWE-770)", check_resource_limits),
        ("Insecure Random (CWE-338)", check_insecure_random),
        ("SSTI (CWE-1336)", check_ssti),
        ("CRLF Injection (CWE-93)", check_crlf),
        ("LDAP Injection (CWE-90)", check_ldap),
        ("Weak Hash (CWE-328)", check_weak_hash),
        ("Open Redirect (CWE-601)", check_open_redirect),
        ("Log Injection (CWE-117)", check_log_injection),
        ("Format String (CWE-134)", check_format_string),
        ("Arbitrary File Write (CWE-73)", check_arbitrary_write),
        ("Insecure Default (CWE-453)", check_insecure_default),
        ("Log Secrets (CWE-532)", check_log_secrets),
        ("Disabled TLS Verify (CWE-295)", check_tls_verify),
        ("ZipSlip / TarSlip (CWE-22)", check_zipslip),
        ("Hardcoded API Keys (CWE-798)", check_hardcoded_tokens),
        ("Weak Crypto (CWE-327)", check_weak_crypto),
        ("Dependency CVE Scan (CWE-1104)", check_dependency_cve),
        ("Trojan Source (CWE-1007)", check_trojan_source),
        ("HTTP Request Timeout (CWE-1088)", check_request_timeout),
        ("torch.load weights_only (CWE-502)", check_torch_load),
        ("SSH Host Key Verification (CWE-322)", check_ssh_host_key),
        ("except:pass/continue (CWE-391)", check_except_pass),
        (
            "pandas eval/query Code Injection (CWE-94)",
            check_pandas_eval,
        ),
        ("numpy.load allow_pickle (CWE-502)", check_numpy_load),
        ("pandas.read_pickle (CWE-502)", check_pandas_pickle),
        (
            "numpy.load library injection (CWE-114)",
            check_numpy_load_lib,
        ),
        ("pandas.read_xml XXE (CWE-611)", check_pandas_xml_xxe),
        (
            ".pth Startup Hooks (CWE-829 / T1546.018)",
            check_pth_startup_hooks,
        ),
        (
            "Parquet Arrow Deserialization (CWE-502 / CVE-2026-41486)",
            check_parquet_arrow_deserialize,
        ),
        ("Unbounded Dependency Pins (CWE-1104)", check_unbounded_pins),
        (
            "ML Model File Loading (OWASP ML06 / CWE-502)",
            check_model_file_load,
        ),
        (
            "Decode-then-Execute Chains (CWE-94)",
            check_decode_exec_chains,
        ),
        (
            "Binding to All Interfaces (CWE-1327)",
            check_bind_all_interfaces,
        ),
        (
            "Weak TLS Protocol Version (CWE-326)",
            check_weak_tls_version,
        ),
        ("Legacy PyCrypto Import (CWE-1104)", check_legacy_pycrypto),
        (
            "HuggingFace Unsafe Download (OWASP ML06 / B615)",
            check_huggingface_unsafe_download,
        ),
    ]
}

/// Same 56 checks, keyed by their Rust function name (== the Python
/// function name each mirrors) rather than display name -- used by the
/// fixture conformance test, whose fixture directories are named after the
/// Python function (`fixtures/check_pickle/...`), not the display string.
/// `stringify!` guarantees the key can't drift from the identifier.
macro_rules! named_checks {
    ($($name:ident),* $(,)?) => {
        vec![$((stringify!($name), $name as CheckFn)),*]
    };
}

pub fn checks_by_name() -> Vec<(&'static str, CheckFn)> {
    use ast_checks::*;
    use manifest_checks::*;
    use text_checks::*;

    named_checks![
        check_pickle,
        check_eval_exec,
        check_command_injection,
        check_sql_injection,
        check_path_traversal,
        check_hardcoded_secrets,
        check_yaml_deserialize,
        check_xxe,
        check_ssrf,
        check_tempfile,
        check_symlink,
        check_redos,
        check_assert_security,
        check_exec_driver_sql,
        check_supply_chain,
        check_debug_mode,
        check_insufficient_logging,
        check_timing_attack,
        check_sensitive_exposure,
        check_null_byte,
        check_resource_limits,
        check_insecure_random,
        check_ssti,
        check_crlf,
        check_ldap,
        check_weak_hash,
        check_open_redirect,
        check_log_injection,
        check_format_string,
        check_arbitrary_write,
        check_insecure_default,
        check_log_secrets,
        check_tls_verify,
        check_zipslip,
        check_hardcoded_tokens,
        check_weak_crypto,
        check_dependency_cve,
        check_trojan_source,
        check_request_timeout,
        check_torch_load,
        check_ssh_host_key,
        check_except_pass,
        check_pandas_eval,
        check_numpy_load,
        check_pandas_pickle,
        check_numpy_load_lib,
        check_pandas_xml_xxe,
        check_pth_startup_hooks,
        check_parquet_arrow_deserialize,
        check_unbounded_pins,
        check_model_file_load,
        check_decode_exec_chains,
        check_bind_all_interfaces,
        check_weak_tls_version,
        check_legacy_pycrypto,
        check_huggingface_unsafe_download,
    ]
}
