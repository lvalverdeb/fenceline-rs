//! AST and text-matching helpers shared by the check functions -- mirrors
//! `fenceline/ast_helpers.py`.
//!
//! rustpython-ast tracks byte offsets (`TextSize`/`TextRange`) rather than
//! Python's native `lineno`, so `LineIndex` bridges the two.

use regex::Regex;
use rustpython_ast::text_size::TextSize;
use rustpython_ast::{
    Arguments, Comprehension, Expr, ExprCall, Keyword, Stmt, StmtAsyncFunctionDef, StmtClassDef,
    StmtFunctionDef, Visitor, WithItem,
};
use std::sync::LazyLock;

pub struct LineIndex {
    line_starts: Vec<u32>,
}

impl LineIndex {
    pub fn new(source: &str) -> Self {
        let mut line_starts = vec![0u32];
        for (i, b) in source.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push((i + 1) as u32);
            }
        }
        LineIndex { line_starts }
    }

    /// 1-indexed line number containing byte offset `offset`.
    pub fn line_number(&self, offset: TextSize) -> usize {
        let offset: u32 = offset.into();
        match self.line_starts.binary_search(&offset) {
            Ok(i) => i + 1,
            Err(i) => i,
        }
    }
}

// ── Logging method names, shared so checks can't drift on which method
// names count as "logging" -- mirrors _LOGGING_METHOD_NAMES.
pub const LOGGING_METHOD_NAMES: &[&str] = &[
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "critical",
    "exception",
    "log",
];

const LOG_NAME_TOKENS: &[&str] = &["log", "logs", "logger", "logging"];

/// Matches a logging call whose argument is an f-string, e.g.
/// `logger.error(f"...")` -- mirrors `_LOG_METHOD_CALL_RE`.
pub static LOG_METHOD_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    let alt = LOGGING_METHOD_NAMES.join("|");
    Regex::new(&format!(r#"\.(?:{alt})\s*\(\s*f["']"#)).unwrap()
});

/// Same method-name set, without the f-string requirement -- mirrors
/// `_LOG_METHOD_CALL_ANY_RE`.
pub static LOG_METHOD_CALL_ANY_RE: LazyLock<Regex> = LazyLock::new(|| {
    let alt = LOGGING_METHOD_NAMES.join("|");
    Regex::new(&format!(r"\.(?:{alt})\s*\(")).unwrap()
});

pub fn call_name(node: &ExprCall) -> String {
    match node.func.as_ref() {
        Expr::Name(n) => n.id.to_string(),
        Expr::Attribute(a) => a.attr.to_string(),
        _ => String::new(),
    }
}

pub fn full_attr(func: &Expr) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = func;
    loop {
        match cur {
            Expr::Attribute(a) => {
                parts.push(a.attr.to_string());
                cur = &a.value;
            }
            Expr::Name(n) => {
                parts.push(n.id.to_string());
                break;
            }
            _ => break,
        }
    }
    parts.reverse();
    parts.join(".")
}

pub fn is_re_compile(node: &ExprCall) -> bool {
    let name = full_attr(&node.func);
    if name == "re.compile" {
        return true;
    }
    call_name(node) == "compile"
        && matches!(
            node.func.as_ref(),
            Expr::Attribute(a) if matches!(a.value.as_ref(), Expr::Name(n) if n.id.as_str() == "re")
        )
}

pub fn is_sqlalchemy_compile(node: &ExprCall) -> bool {
    let name = full_attr(&node.func);
    name.contains("compile")
        && ["statement", "query", "select", "sql"]
            .iter()
            .any(|x| name.contains(x))
}

fn is_dynamic_expr(e: &Expr) -> bool {
    !matches!(e, Expr::Constant(_))
}

pub fn has_dynamic_arg(node: &ExprCall) -> bool {
    node.args.iter().any(is_dynamic_expr)
        || node.keywords.iter().any(|kw| is_dynamic_expr(&kw.value))
}

pub fn has_log_like_token(full_name: &str) -> bool {
    full_name
        .to_lowercase()
        .split(['.', '_'])
        .any(|tok| LOG_NAME_TOKENS.contains(&tok))
}

/// True if an `except` block logs, re-raises, or otherwise surfaces the
/// exception rather than silently swallowing it -- mirrors
/// `_handler_has_diagnostic`. Walks the whole subtree (not just top-level
/// statements) but does not descend into nested function/lambda/class
/// bodies, the same "skip nested scopes" rule Python's version applies,
/// since code merely *defined* there doesn't run as part of this handler.
pub fn handler_has_diagnostic(body: &[Stmt]) -> bool {
    let mut visitor = DiagnosticVisitor { found: false };
    for stmt in body {
        if visitor.found {
            break;
        }
        visitor.visit_stmt(stmt.clone());
    }
    visitor.found
}

struct DiagnosticVisitor {
    found: bool,
}

impl Visitor for DiagnosticVisitor {
    fn visit_stmt_raise(&mut self, _node: rustpython_ast::StmtRaise) {
        self.found = true;
    }

    fn visit_stmt_function_def(&mut self, _node: StmtFunctionDef) {
        // Nested scope boundary -- do not descend (mirrors _NESTED_SCOPE_TYPES).
    }

    fn visit_stmt_async_function_def(&mut self, _node: StmtAsyncFunctionDef) {
        // Nested scope boundary -- do not descend.
    }

    fn visit_stmt_class_def(&mut self, _node: StmtClassDef) {
        // Nested scope boundary -- do not descend.
    }

    fn visit_expr_lambda(&mut self, _node: rustpython_ast::ExprLambda) {
        // Nested scope boundary -- do not descend.
    }

    fn visit_expr_call(&mut self, node: ExprCall) {
        if let Expr::Attribute(a) = node.func.as_ref()
            && LOGGING_METHOD_NAMES.contains(&a.attr.as_str())
        {
            self.found = true;
        }
        let full = full_attr(&node.func);
        if full == "warnings.warn" || has_log_like_token(&full) {
            self.found = true;
        }
        self.generic_visit_expr_call(node);
    }

    // ── The four walk-fix overrides (spaghetti-rs's ast_helpers.rs §7.6):
    // rustpython-ast 0.4.0's generated `generic_visit_*` for these four
    // "support struct" node kinds are no-op stubs, so a Call buried in a
    // comprehension filter, a default value, a call keyword, or a with-item
    // expression would otherwise never be reached.
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

pub fn walk_comprehension_children<V: Visitor + ?Sized>(visitor: &mut V, node: Comprehension) {
    visitor.visit_expr(node.target);
    visitor.visit_expr(node.iter);
    for if_expr in node.ifs {
        visitor.visit_expr(if_expr);
    }
}

pub fn walk_arguments_children<V: Visitor + ?Sized>(visitor: &mut V, node: Arguments) {
    for arg in node
        .posonlyargs
        .into_iter()
        .chain(node.args)
        .chain(node.kwonlyargs)
    {
        if let Some(annotation) = arg.def.annotation {
            visitor.visit_expr(*annotation);
        }
        if let Some(default) = arg.default {
            visitor.visit_expr(*default);
        }
    }
    if let Some(vararg) = node.vararg
        && let Some(annotation) = vararg.annotation
    {
        visitor.visit_expr(*annotation);
    }
    if let Some(kwarg) = node.kwarg
        && let Some(annotation) = kwarg.annotation
    {
        visitor.visit_expr(*annotation);
    }
}

pub fn walk_keyword_children<V: Visitor + ?Sized>(visitor: &mut V, node: Keyword) {
    visitor.visit_expr(node.value);
}

pub fn walk_withitem_children<V: Visitor + ?Sized>(visitor: &mut V, node: WithItem) {
    visitor.visit_expr(node.context_expr);
    if let Some(vars) = node.optional_vars {
        visitor.visit_expr(*vars);
    }
}

pub fn skip(line: &str) -> bool {
    line.trim_start().starts_with('#')
}
