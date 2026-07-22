//! AST and text-matching helpers shared by the check functions -- mirrors
//! `fenceline/ast_helpers.py`.
//!
//! rustpython-ast tracks byte offsets (`TextSize`/`TextRange`) rather than
//! Python's native `lineno`, so `LineIndex` bridges the two.

use regex::Regex;
use rustpython_ast::text_size::TextSize;
use rustpython_ast::{
    Arguments, Comprehension, Expr, ExprCall, ExprLambda, Keyword, ModModule, Stmt, StmtAnnAssign,
    StmtAssign, StmtAsyncFunctionDef, StmtClassDef, StmtFunctionDef, StmtImport, StmtImportFrom,
    Visitor, WithItem,
};
use std::collections::{HashMap, HashSet};
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
///
/// `bound_name` is the handler's own bound exception name (`except
/// Exception as exc:` -> `Some("exc")`), if any. A later reference to it
/// anywhere in the body -- `print(f"...{exc}")`, `metrics.record(exc)`,
/// not just a `logging`-module call -- counts as surfacing the exception
/// through some other mechanism, not silently swallowing it.
pub fn handler_has_diagnostic(body: &[Stmt], bound_name: Option<&str>) -> bool {
    let mut visitor = DiagnosticVisitor {
        found: false,
        bound_name: bound_name.map(str::to_string),
    };
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
    bound_name: Option<String>,
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

    fn visit_expr_name(&mut self, node: rustpython_ast::ExprName) {
        if self.bound_name.as_deref() == Some(node.id.as_str()) {
            self.found = true;
        }
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

// ── Local (same-function-scope) constant resolution ──────────────────────
//
// Mirrors `ast_helpers.py`'s own local-resolution helpers. Deliberately
// NOT full taint tracking: this only ever looks at the same function's own
// body plus the enclosing module's top-level constants and imports -- never
// across a function/call boundary. It exists to answer one narrow question
// well: "is this expression built entirely from string literals,
// module-level constants, and library references, with no dependency on
// this function's own parameters or any other name we can't account for?"

/// `(name -> assigned value, names bound by import statements)` for every
/// simple `Name = value`/`Name: T = value` assignment and
/// `import`/`from ... import` statement directly in `stmts` -- mirrors
/// `ast_helpers._collect_scope_names`.
pub fn collect_scope_names(stmts: &[Stmt]) -> (HashMap<String, Expr>, HashSet<String>) {
    let mut collector = ScopeNamesCollector {
        literals: HashMap::new(),
        imports: HashSet::new(),
    };
    for stmt in stmts {
        collector.visit_stmt(stmt.clone());
    }
    (collector.literals, collector.imports)
}

struct ScopeNamesCollector {
    literals: HashMap<String, Expr>,
    imports: HashSet<String>,
}

impl Visitor for ScopeNamesCollector {
    fn visit_stmt_function_def(&mut self, _node: StmtFunctionDef) {}
    fn visit_stmt_async_function_def(&mut self, _node: StmtAsyncFunctionDef) {}
    fn visit_stmt_class_def(&mut self, _node: StmtClassDef) {}
    fn visit_expr_lambda(&mut self, _node: ExprLambda) {}

    fn visit_stmt_assign(&mut self, node: StmtAssign) {
        for target in &node.targets {
            if let Expr::Name(n) = target {
                self.literals
                    .insert(n.id.to_string(), (*node.value).clone());
            }
        }
        self.generic_visit_stmt_assign(node);
    }

    fn visit_stmt_ann_assign(&mut self, node: StmtAnnAssign) {
        if let Expr::Name(n) = node.target.as_ref()
            && let Some(value) = &node.value
        {
            self.literals.insert(n.id.to_string(), (**value).clone());
        }
        self.generic_visit_stmt_ann_assign(node);
    }

    fn visit_stmt_import(&mut self, node: StmtImport) {
        for alias in &node.names {
            let bound = alias
                .asname
                .as_deref()
                .unwrap_or_else(|| alias.name.split('.').next().unwrap_or(&alias.name));
            self.imports.insert(bound.to_string());
        }
    }

    fn visit_stmt_import_from(&mut self, node: StmtImportFrom) {
        for alias in &node.names {
            let bound = alias.asname.as_deref().unwrap_or(&alias.name);
            self.imports.insert(bound.to_string());
        }
    }
}

fn param_names_from_arguments(args: &Arguments) -> HashSet<String> {
    args.posonlyargs
        .iter()
        .chain(args.args.iter())
        .chain(args.kwonlyargs.iter())
        .map(|a| a.def.arg.to_string())
        .collect()
}

/// One scoped call: the `Call` node itself, its enclosing function's own
/// parameter names (empty at module scope), and the merged
/// (module-level + this scope's own) literals/imports available to
/// resolve names against.
pub struct ScopedCall {
    pub call: ExprCall,
    pub params: HashSet<String>,
    pub literals: HashMap<String, Expr>,
    pub imports: HashSet<String>,
}

struct FunctionScopeCollector {
    scopes: Vec<(Vec<Stmt>, HashSet<String>)>,
}

impl Visitor for FunctionScopeCollector {
    fn visit_stmt_function_def(&mut self, node: StmtFunctionDef) {
        self.scopes
            .push((node.body.clone(), param_names_from_arguments(&node.args)));
        self.generic_visit_stmt_function_def(node);
    }

    fn visit_stmt_async_function_def(&mut self, node: StmtAsyncFunctionDef) {
        self.scopes
            .push((node.body.clone(), param_names_from_arguments(&node.args)));
        self.generic_visit_stmt_async_function_def(node);
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

struct CallCollector {
    calls: Vec<ExprCall>,
}

impl Visitor for CallCollector {
    fn visit_stmt_function_def(&mut self, _node: StmtFunctionDef) {}
    fn visit_stmt_async_function_def(&mut self, _node: StmtAsyncFunctionDef) {}
    fn visit_stmt_class_def(&mut self, _node: StmtClassDef) {}
    fn visit_expr_lambda(&mut self, _node: ExprLambda) {}

    fn visit_expr_call(&mut self, node: ExprCall) {
        self.calls.push(node.clone());
        self.generic_visit_expr_call(node);
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

fn calls_in_stmts(stmts: &[Stmt]) -> Vec<ExprCall> {
    let mut collector = CallCollector { calls: Vec::new() };
    for stmt in stmts {
        collector.visit_stmt(stmt.clone());
    }
    collector.calls
}

/// Every `Call` in `tree`, each correctly scoped to its own immediately
/// enclosing function (or the module, if not inside any function) --
/// mirrors `ast_helpers._iter_calls_in_scope`.
///
/// Uses `CallCollector`'s nested-scope-stopping walk (not a raw traversal)
/// when hunting for calls within one scope's statements -- critical for
/// correctness, not just tidiness: a call inside a nested inner function
/// must be scoped to *that* function's own parameters/locals, not the
/// outer one, and must be yielded exactly once (found when that inner
/// function's own turn comes up via `FunctionScopeCollector`, not also
/// under the outer scope).
pub fn iter_calls_in_scope(tree: &ModModule) -> Vec<ScopedCall> {
    let (module_literals, module_imports) = collect_scope_names(&tree.body);

    let mut function_collector = FunctionScopeCollector { scopes: Vec::new() };
    for stmt in &tree.body {
        function_collector.visit_stmt(stmt.clone());
    }

    let mut scopes = vec![(tree.body.clone(), HashSet::new())];
    scopes.extend(function_collector.scopes);

    let mut result = Vec::new();
    for (stmts, params) in scopes {
        let (own_literals, own_imports) = collect_scope_names(&stmts);
        let mut literals = module_literals.clone();
        literals.extend(own_literals);
        let mut imports = module_imports.clone();
        imports.extend(own_imports);

        for call in calls_in_stmts(&stmts) {
            result.push(ScopedCall {
                call,
                params: params.clone(),
                literals: literals.clone(),
                imports: imports.clone(),
            });
        }
    }
    result
}

/// True if `expr` doesn't reference this function's own parameters (the
/// boundary of "external input" in a same-function-scope model) or any
/// name that can't be resolved within the same scope at all -- i.e. it's
/// built entirely from string literals, function/module-local constants,
/// and calls/attribute access on imported names -- mirrors
/// `ast_helpers._is_locally_safe_expr`. Recursion depth is capped
/// defensively; a pathologically deep expression just falls through to
/// the conservative "not safe" default rather than the check ever hanging.
pub fn is_locally_safe_expr(
    expr: &Expr,
    params: &HashSet<String>,
    literals: &HashMap<String, Expr>,
    imports: &HashSet<String>,
    depth: u8,
) -> bool {
    if depth > 8 {
        return false;
    }
    match expr {
        Expr::Constant(_) => true,
        Expr::Name(n) => {
            let id = n.id.as_str();
            if params.contains(id) {
                false
            } else if imports.contains(id) {
                true
            } else if let Some(value) = literals.get(id) {
                is_locally_safe_expr(value, params, literals, imports, depth + 1)
            } else {
                false
            }
        }
        Expr::Attribute(a) => is_locally_safe_expr(&a.value, params, literals, imports, depth + 1),
        Expr::Call(c) => {
            is_locally_safe_expr(&c.func, params, literals, imports, depth + 1)
                && c.args
                    .iter()
                    .all(|a| is_locally_safe_expr(a, params, literals, imports, depth + 1))
                && c.keywords
                    .iter()
                    .all(|kw| is_locally_safe_expr(&kw.value, params, literals, imports, depth + 1))
        }
        Expr::JoinedStr(js) => js.values.iter().all(|v| match v {
            Expr::FormattedValue(fv) => {
                is_locally_safe_expr(&fv.value, params, literals, imports, depth + 1)
            }
            _ => true,
        }),
        Expr::BinOp(b) => {
            is_locally_safe_expr(&b.left, params, literals, imports, depth + 1)
                && is_locally_safe_expr(&b.right, params, literals, imports, depth + 1)
        }
        _ => false,
    }
}
