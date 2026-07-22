//! AST-based check functions -- mirrors `fenceline/checks/ast_checks.py`.
//!
//! A single `Collector` Visitor walks the whole module once, recording
//! every `Call`/`ExceptHandler`/`FunctionDef`/`Assign`/`AnnAssign` node's
//! relevant fields; each check function below filters/maps over the
//! collected records rather than re-walking the tree itself. This design
//! (and the four walk-fix overrides it depends on) was validated in the
//! Phase 0 parser spike against real Python output before being used here.

use crate::ast_helpers::{
    LineIndex, full_attr, has_dynamic_arg, is_re_compile, is_sqlalchemy_compile, skip,
    walk_arguments_children, walk_comprehension_children, walk_keyword_children,
    walk_withitem_children,
};
use crate::models::{Confidence, Finding, Severity};
use regex::Regex;
use rustpython_ast::{
    Arguments, Comprehension, Constant, ExceptHandlerExceptHandler, Expr, ExprCall, Keyword,
    ModModule, Ranged, Stmt, StmtAnnAssign, StmtAssign, StmtAsyncFunctionDef, StmtFunctionDef,
    Visitor, WithItem,
};
use std::path::Path;
use std::sync::LazyLock;

fn is_true_constant(e: &Expr) -> bool {
    matches!(e, Expr::Constant(c) if matches!(c.value, Constant::Bool(true)))
}

fn target_is_allow_pickle(target: &Expr) -> bool {
    match target {
        Expr::Name(n) => n.id.as_str() == "allow_pickle",
        Expr::Attribute(a) => a.attr.as_str() == "allow_pickle",
        _ => false,
    }
}

struct CallRec {
    line: usize,
    full_attr: String,
    func_is_bare_name: bool,
    args_dynamic: bool,
    keyword_names: Vec<String>,
    keyword_true_names: Vec<String>,
    first_arg_call_full_attr: Option<String>,
    /// Only meaningful when `full_attr == "compile"`: true if this is
    /// `re.compile(...)` or a SQLAlchemy-style `.compile()` -- both
    /// excluded from `check_eval_exec`'s bare-`compile()` rule.
    is_excluded_compile: bool,
    /// Line of the `allow_pickle=True` keyword's own *value* node, if
    /// present -- mirrors `ast_checks.py::_allow_pickle_kw_line`, which
    /// deliberately reports the value's line rather than the call's own
    /// (opening-paren) line, so a multi-line call flags the line the
    /// dangerous keyword actually sits on.
    allow_pickle_kw_line: Option<usize>,
}

struct ExceptRec {
    line: usize,
    is_bare: bool,
    is_exception_name: bool,
    single_pass: bool,
    single_continue: bool,
    has_diagnostic: bool,
}

struct FuncDefRec {
    line: usize,
    name: String,
    is_plain_function_def: bool,
    /// `(param name, is-default-True, default's own line)` -- the third
    /// field mirrors `ast_checks.py::_allow_pickle_default_lines`, which
    /// reports the default value's own line rather than the `def`
    /// statement's line, so a multi-line signature flags the line the
    /// dangerous default actually sits on.
    params: Vec<(String, Option<bool>, Option<usize>)>,
}

struct AssignRec {
    line: usize,
    is_allow_pickle_true: bool,
}

#[derive(Default)]
struct Collected {
    calls: Vec<CallRec>,
    excepts: Vec<ExceptRec>,
    funcdefs: Vec<FuncDefRec>,
    assigns: Vec<AssignRec>,
    ann_assigns: Vec<AssignRec>,
}

struct Collector<'a> {
    li: &'a LineIndex,
    out: Collected,
}

fn params_from_arguments(
    args: &Arguments,
    li: &LineIndex,
) -> Vec<(String, Option<bool>, Option<usize>)> {
    args.posonlyargs
        .iter()
        .chain(args.args.iter())
        .chain(args.kwonlyargs.iter())
        .map(|a| {
            let is_true = a.default.as_deref().map(is_true_constant);
            let default_line = a.default.as_deref().map(|d| li.line_number(d.start()));
            (a.def.arg.to_string(), is_true, default_line)
        })
        .collect()
}

impl<'a> Visitor for Collector<'a> {
    fn visit_expr_call(&mut self, node: ExprCall) {
        let line = self.li.line_number(node.start());
        let fa = full_attr(&node.func);
        let func_is_bare_name = matches!(node.func.as_ref(), Expr::Name(_));
        let args_dynamic = has_dynamic_arg(&node);
        let keyword_names: Vec<String> = node
            .keywords
            .iter()
            .filter_map(|kw| kw.arg.as_ref().map(|a| a.to_string()))
            .collect();
        let keyword_true_names: Vec<String> = node
            .keywords
            .iter()
            .filter(|kw| is_true_constant(&kw.value))
            .filter_map(|kw| kw.arg.as_ref().map(|a| a.to_string()))
            .collect();
        let allow_pickle_kw_line = node
            .keywords
            .iter()
            .find(|kw| {
                kw.arg
                    .as_ref()
                    .is_some_and(|a| a.as_str() == "allow_pickle")
                    && is_true_constant(&kw.value)
            })
            .map(|kw| self.li.line_number(kw.value.start()));
        let first_arg_call_full_attr = node.args.first().and_then(|a| {
            if let Expr::Call(c) = a {
                Some(full_attr(&c.func))
            } else {
                None
            }
        });
        // Needed by check_eval_exec (re.compile/sqlalchemy .compile()
        // exclusion) -- computed here since it needs the *whole* Call node,
        // not just the recorded fields.
        let is_excluded_compile =
            fa == "compile" && (is_re_compile(&node) || is_sqlalchemy_compile(&node));

        self.out.calls.push(CallRec {
            line,
            full_attr: fa,
            func_is_bare_name,
            args_dynamic,
            keyword_names,
            keyword_true_names,
            first_arg_call_full_attr,
            is_excluded_compile,
            allow_pickle_kw_line,
        });
        self.generic_visit_expr_call(node);
    }

    fn visit_excepthandler_except_handler(&mut self, node: ExceptHandlerExceptHandler) {
        let line = self.li.line_number(node.start());
        let is_bare = node.type_.is_none();
        let is_exception_name =
            matches!(node.type_.as_deref(), Some(Expr::Name(n)) if n.id.as_str() == "Exception");
        let single_pass = node.body.len() == 1 && matches!(node.body[0], Stmt::Pass(_));
        let single_continue = node.body.len() == 1 && matches!(node.body[0], Stmt::Continue(_));
        let has_diagnostic = crate::ast_helpers::handler_has_diagnostic(&node.body);
        self.out.excepts.push(ExceptRec {
            line,
            is_bare,
            is_exception_name,
            single_pass,
            single_continue,
            has_diagnostic,
        });
        self.generic_visit_excepthandler_except_handler(node);
    }

    fn visit_stmt_function_def(&mut self, node: StmtFunctionDef) {
        let line = self.li.line_number(node.start());
        self.out.funcdefs.push(FuncDefRec {
            line,
            name: node.name.to_string(),
            is_plain_function_def: true,
            params: params_from_arguments(&node.args, self.li),
        });
        self.generic_visit_stmt_function_def(node);
    }

    fn visit_stmt_async_function_def(&mut self, node: StmtAsyncFunctionDef) {
        let line = self.li.line_number(node.start());
        self.out.funcdefs.push(FuncDefRec {
            line,
            name: node.name.to_string(),
            is_plain_function_def: false,
            params: params_from_arguments(&node.args, self.li),
        });
        self.generic_visit_stmt_async_function_def(node);
    }

    fn visit_stmt_assign(&mut self, node: StmtAssign) {
        let line = self.li.line_number(node.start());
        if node.targets.iter().any(target_is_allow_pickle) {
            self.out.assigns.push(AssignRec {
                line,
                is_allow_pickle_true: is_true_constant(&node.value),
            });
        }
        self.generic_visit_stmt_assign(node);
    }

    fn visit_stmt_ann_assign(&mut self, node: StmtAnnAssign) {
        let line = self.li.line_number(node.start());
        if target_is_allow_pickle(&node.target)
            && let Some(value) = node.value.as_deref()
        {
            self.out.ann_assigns.push(AssignRec {
                line,
                is_allow_pickle_true: is_true_constant(value),
            });
        }
        self.generic_visit_stmt_ann_assign(node);
    }

    fn visit_arguments(&mut self, node: Arguments) {
        walk_arguments_children(self, node);
    }
    fn visit_comprehension(&mut self, node: Comprehension) {
        walk_comprehension_children(self, node);
    }
    fn visit_keyword(&mut self, node: Keyword) {
        walk_keyword_children(self, node);
    }
    fn visit_withitem(&mut self, node: WithItem) {
        walk_withitem_children(self, node);
    }
}

fn collect(tree: &ModModule, source: &str) -> Collected {
    let li = LineIndex::new(source);
    let mut collector = Collector {
        li: &li,
        out: Collected::default(),
    };
    for stmt in tree.body.clone() {
        collector.visit_stmt(stmt);
    }
    collector.out
}

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
    tree: Option<&ModModule>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let source = lines.join("\n");
    let collected = collect(tree, &source);
    let mut results = Vec::new();
    for call in &collected.calls {
        match call.full_attr.as_str() {
            "eval" | "exec" => results.push(Finding {
                cwe_id: "CWE-94",
                cwe_name: "Code Injection",
                severity: Severity::Critical,
                confidence: Confidence::High,
                package: String::new(),
                file: pk.to_string(),
                line: call.line,
                code_snippet: code_at(lines, call.line),
                description: "eval()/exec() with dynamic input allows arbitrary code execution."
                    .to_string(),
                zero_day_relevance: "",
            }),
            "compile" if !call.is_excluded_compile && call.func_is_bare_name && call.args_dynamic => results.push(Finding {
                cwe_id: "CWE-94",
                cwe_name: "Code Injection",
                severity: Severity::Critical,
                confidence: Confidence::High,
                package: String::new(),
                file: pk.to_string(),
                line: call.line,
                code_snippet: code_at(lines, call.line),
                description: "compile() with dynamic input can enable arbitrary code execution."
                    .to_string(),
                zero_day_relevance: "",
            }),
            "__import__" => results.push(Finding {
                cwe_id: "CWE-94",
                cwe_name: "Code Injection",
                severity: Severity::High,
                confidence: Confidence::High,
                package: String::new(),
                file: pk.to_string(),
                line: call.line,
                code_snippet: code_at(lines, call.line),
                description: "Dynamic __import__() can import arbitrary modules if argument is user-controlled.".to_string(),
                zero_day_relevance: "",
            }),
            _ => {}
        }
    }
    results
}

// ── check_insufficient_logging (CWE-778) ─────────────────────────────────

pub fn check_insufficient_logging(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ModModule>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let source = lines.join("\n");
    let collected = collect(tree, &source);
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
    tree: Option<&ModModule>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let source = lines.join("\n");
    let collected = collect(tree, &source);
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
    tree: Option<&ModModule>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let source = lines.join("\n");
    let collected = collect(tree, &source);
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
    tree: Option<&ModModule>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let source = lines.join("\n");
    let collected = collect(tree, &source);
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
    tree: Option<&ModModule>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let source = lines.join("\n");
    let collected = collect(tree, &source);
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
    tree: Option<&ModModule>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let source = lines.join("\n");
    let collected = collect(tree, &source);
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
    tree: Option<&ModModule>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let source = lines.join("\n");
    let collected = collect(tree, &source);
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
    tree: Option<&ModModule>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let source = lines.join("\n");
    let collected = collect(tree, &source);
    let mut results = Vec::new();
    for c in &collected.calls {
        if c.full_attr == "pandas.eval" || c.full_attr == "pd.eval" {
            results.push(Finding {
                cwe_id: "CWE-94",
                cwe_name: "Code Injection (pandas eval)",
                severity: Severity::Critical,
                confidence: Confidence::High,
                package: String::new(),
                file: pk.to_string(),
                line: c.line,
                code_snippet: code_at(lines, c.line),
                description: "pandas.eval() evaluates arbitrary Python expressions — code injection if user input reaches the expression.".to_string(),
                zero_day_relevance: "CVE-2024-9880 / Trail of Bits: pandas.eval() / df.query() sandbox bypass via dunder methods. Pandas docs now warn explicitly.",
            });
        } else if matches!(c.full_attr.rsplit('.').next(), Some("eval") | Some("query"))
            && c.full_attr != "pandas.eval"
            && c.full_attr != "pd.eval"
            && c.full_attr.contains('.')
        {
            results.push(Finding {
                cwe_id: "CWE-94",
                cwe_name: "Code Injection (DataFrame eval/query)",
                severity: Severity::High,
                confidence: Confidence::High,
                package: String::new(),
                file: pk.to_string(),
                line: c.line,
                code_snippet: code_at(lines, c.line),
                description: "DataFrame.eval() or DataFrame.query() evaluates Python expressions — code injection if user-controlled input reaches the expression.".to_string(),
                zero_day_relevance: "CVE-2024-9880: pandas.DataFrame.query() sandbox bypass. Thousands of attribute chains lead to os.system.",
            });
        }
    }
    results
}

// ── check_numpy_load (CWE-502) ───────────────────────────────────────────

pub fn check_numpy_load(
    _path: &Path,
    pk: &str,
    lines: &[String],
    tree: Option<&ModModule>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let source = lines.join("\n");
    let collected = collect(tree, &source);
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
    tree: Option<&ModModule>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    if let Some(tree) = tree {
        let source = lines.join("\n");
        let collected = collect(tree, &source);
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
    tree: Option<&ModModule>,
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
        let source = lines.join("\n");
        let collected = collect(tree, &source);
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
    tree: Option<&ModModule>,
) -> Vec<Finding> {
    let Some(tree) = tree else { return vec![] };
    let source = lines.join("\n");
    let collected = collect(tree, &source);
    let mut results = Vec::new();
    for c in &collected.calls {
        // Recover the bare call name the way check_name() would (last
        // dotted segment, or the whole thing if it wasn't a dotted attr
        // access) -- collected.calls only stores full_attr, so reconstruct.
        let name = c.full_attr.rsplit('.').next().unwrap_or(&c.full_attr);
        if name != "from_pretrained" {
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
        } else if !c.keyword_names.iter().any(|n| n == "revision") {
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
