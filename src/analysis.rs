//! Per-file analysis shared by every check: the module AST plus the
//! derived views built from it. A single `Collector` Visitor walks the
//! whole module once, recording every `Call`/`ExceptHandler`/`FunctionDef`/
//! `Assign`/`AnnAssign`/`Import` node's relevant fields; check functions
//! filter/map over the collected records rather than re-walking the tree.
//! This design (and the four walk-fix overrides it depends on) was
//! validated in the Phase 0 parser spike against real Python output.

use crate::ast_helpers::{
    LineIndex, ScopedCall, call_name, full_attr, has_dynamic_arg, is_re_compile,
    is_sqlalchemy_compile, iter_calls_in_scope, resolve_dotted, walk_arguments_children,
    walk_comprehension_children, walk_keyword_children, walk_withitem_children,
};
use rustpython_ast::text_size::TextSize;
use rustpython_ast::{
    Arguments, Comprehension, Constant, ExceptHandlerExceptHandler, Expr, ExprAttribute, ExprBinOp,
    ExprCall, ExprCompare, ExprConstant, ExprJoinedStr, ExprName, Keyword, ModModule, Operator,
    Ranged, Stmt, StmtAnnAssign, StmtAssign, StmtAsyncFunctionDef, StmtClassDef, StmtFunctionDef,
    StmtImport, StmtImportFrom, Visitor, WithItem,
};
use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};
use std::path::Path;

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

/// Dotted name for a bare `Name`/`Attribute` chain, e.g. `pydantic.BaseModel`
/// -> `"pydantic.BaseModel"` -- mirrors `full_attr`, but for a general
/// expression (a class base) rather than specifically a `Call`'s `.func`.
/// Empty string for anything else (a subscript, a call, ...).
pub fn expr_dotted_name(node: &Expr) -> String {
    let mut parts = Vec::new();
    let mut cur = node;
    loop {
        match cur {
            Expr::Attribute(a) => {
                parts.push(a.attr.as_str());
                cur = &a.value;
            }
            Expr::Name(n) => {
                parts.push(n.id.as_str());
                parts.reverse();
                return parts.join(".");
            }
            _ => return String::new(),
        }
    }
}

fn is_pydantic_base(node: &Expr) -> bool {
    let name = expr_dotted_name(node);
    name == "BaseModel" || name.ends_with(".BaseModel")
}

/// Pydantic's BaseModel is used for internal config/settings objects just
/// as often as for network-facing request bodies -- an unbounded str field
/// on a config class isn't a real attack surface. Narrowing to conventional
/// request/input-DTO name suffixes (matching FastAPI community convention)
/// keeps the signal-to-noise ratio usable rather than flagging every
/// settings class in a codebase. Mirrors
/// `ast_checks.py::_looks_like_request_model`.
const REQUEST_MODEL_SUFFIXES: &[&str] = &["Request", "Input", "Payload", "Body", "Params"];

fn looks_like_request_model(class_name: &str) -> bool {
    REQUEST_MODEL_SUFFIXES
        .iter()
        .any(|s| class_name.ends_with(s))
}

/// `"str"`/`"bytes"` if *annotation* is a bare, `Optional`-wrapped,
/// `| None`-wrapped, or `Annotated`-wrapped `str`/`bytes` type; `None`
/// otherwise -- mirrors `ast_checks.py::_str_or_bytes_base_type`.
fn str_or_bytes_base_type(annotation: &Expr) -> Option<&'static str> {
    match annotation {
        Expr::Name(n) if n.id.as_str() == "str" => Some("str"),
        Expr::Name(n) if n.id.as_str() == "bytes" => Some("bytes"),
        Expr::Subscript(sub) => {
            let Expr::Name(base) = sub.value.as_ref() else {
                return None;
            };
            if base.id.as_str() == "Optional"
                && let Expr::Name(inner) = sub.slice.as_ref()
            {
                return match inner.id.as_str() {
                    "str" => Some("str"),
                    "bytes" => Some("bytes"),
                    _ => None,
                };
            }
            if base.id.as_str() == "Annotated"
                && let Expr::Tuple(tup) = sub.slice.as_ref()
                && let Some(Expr::Name(first)) = tup.elts.first()
            {
                return match first.id.as_str() {
                    "str" => Some("str"),
                    "bytes" => Some("bytes"),
                    _ => None,
                };
            }
            None
        }
        Expr::BinOp(bin) if matches!(bin.op, rustpython_ast::Operator::BitOr) => {
            for side in [bin.left.as_ref(), bin.right.as_ref()] {
                if let Expr::Name(n) = side {
                    match n.id.as_str() {
                        "str" => return Some("str"),
                        "bytes" => return Some("bytes"),
                        _ => {}
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn field_call_has_max_length(node: &Expr) -> bool {
    let Expr::Call(call) = node else { return false };
    let name = full_attr(&call.func);
    (name == "Field" || name == "StringConstraints")
        && call
            .keywords
            .iter()
            .any(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == "max_length"))
}

fn has_length_constraint(annotation: &Expr, default: Option<&Expr>) -> bool {
    if let Some(value) = default
        && field_call_has_max_length(value)
    {
        return true;
    }
    if let Expr::Subscript(sub) = annotation
        && let Expr::Name(base) = sub.value.as_ref()
        && base.id.as_str() == "Annotated"
        && let Expr::Tuple(tup) = sub.slice.as_ref()
    {
        return tup.elts.iter().skip(1).any(field_call_has_max_length);
    }
    false
}

pub struct CallRec {
    pub line: usize,
    pub full_attr: String,
    /// Last path segment (`loads` for `pickle.loads`) -- mirrors `_call_name`.
    pub call_name: String,
    /// Keywords whose value is the literal `False`.
    pub keyword_false_names: Vec<String>,
    /// First positional argument when it is a string literal.
    pub first_arg_str: Option<String>,
    /// Dotted names of every positional/keyword argument that is a bare
    /// name or attribute chain (`yaml.SafeLoader` in `yaml.load(x, Loader=yaml.SafeLoader)`).
    pub arg_dotted_names: Vec<String>,
    /// `"...\r\n".format(x)`: a CRLF literal formatted with data.
    pub is_crlf_format_call: bool,
    pub has_args: bool,
    pub n_positional: usize,
    /// String literals passed directly as positional or keyword arguments.
    pub str_args: Vec<String>,
    /// Every identifier (bare name or attribute) anywhere inside the arguments.
    pub arg_names: Vec<String>,
    pub func_is_bare_name: bool,
    pub args_dynamic: bool,
    pub keyword_names: Vec<String>,
    pub keyword_true_names: Vec<String>,
    pub first_arg_call_full_attr: Option<String>,
    /// Only meaningful when `full_attr == "compile"`: true if this is
    /// `re.compile(...)` or a SQLAlchemy-style `.compile()` -- both
    /// excluded from `check_eval_exec`'s bare-`compile()` rule.
    pub is_excluded_compile: bool,
    /// Line of the `allow_pickle=True` keyword's own *value* node, if
    /// present -- mirrors `ast_checks.py::_allow_pickle_kw_line`, which
    /// deliberately reports the value's line rather than the call's own
    /// (opening-paren) line, so a multi-line call flags the line the
    /// dangerous keyword actually sits on.
    pub allow_pickle_kw_line: Option<usize>,
}

pub struct ExceptRec {
    pub line: usize,
    pub is_bare: bool,
    pub is_exception_name: bool,
    pub single_pass: bool,
    pub single_continue: bool,
    pub has_diagnostic: bool,
}

pub struct FuncDefRec {
    pub line: usize,
    pub name: String,
    pub is_plain_function_def: bool,
    /// `(param name, is-default-True, default's own line)` -- the third
    /// field mirrors `ast_checks.py::_allow_pickle_default_lines`, which
    /// reports the default value's own line rather than the `def`
    /// statement's line, so a multi-line signature flags the line the
    /// dangerous default actually sits on.
    pub params: Vec<(String, Option<bool>, Option<usize>)>,
}

pub struct AssignRec {
    pub line: usize,
    pub is_allow_pickle_true: bool,
}

pub struct PydanticFieldRec {
    pub line: usize,
    pub field_name: String,
    pub base_type: &'static str,
    pub has_constraint: bool,
}

#[derive(Default)]
pub struct Collected {
    pub calls: Vec<CallRec>,
    /// `(line, appears as an operand of a comparison)` for every `CERT_NONE` reference.
    pub cert_none_refs: Vec<(usize, bool)>,
    /// `(line, target's last segment, value)` for every `x = True`/`x = False`
    /// assignment (`app.debug = True`, `ctx.check_hostname = False`).
    pub bool_assigns: Vec<(usize, String, bool)>,
    /// Local name -> fully-qualified dotted name for the file's imports
    /// (see `ast_helpers::resolve_dotted`). Already applied to every
    /// `CallRec::full_attr`.
    pub aliases: HashMap<String, String>,
    /// `(line, top-level module roots)` per `import`/`from ... import` statement.
    pub import_stmts: Vec<(usize, Vec<String>)>,
    /// Lines holding the string literal `"0.0.0.0"`.
    pub bind_all_lines: Vec<usize>,
    /// `(line, name)` for every reference to a deprecated SSL/TLS protocol constant.
    pub weak_tls_refs: Vec<(usize, String)>,
    /// Lines where a CRLF-bearing literal is combined with non-literal data
    /// via `+`, `%`, or an f-string (`.format()` is recorded on the call).
    pub crlf_combo_lines: Vec<usize>,
    pub excepts: Vec<ExceptRec>,
    pub funcdefs: Vec<FuncDefRec>,
    pub assigns: Vec<AssignRec>,
    pub ann_assigns: Vec<AssignRec>,
    pub pydantic_fields: Vec<PydanticFieldRec>,
}

struct Collector<'a> {
    li: &'a LineIndex,
    out: Collected,
    /// Start offsets of every `Compare` operand, so a `CERT_NONE` reference
    /// can be told apart from `== ssl.CERT_NONE` (a check, not a configuration).
    compare_operand_starts: HashSet<TextSize>,
}

pub fn is_false_constant(e: &Expr) -> bool {
    matches!(e, Expr::Constant(c) if matches!(c.value, Constant::Bool(false)))
}

/// Mirrors `ast_checks._has_crlf`: a str/bytes literal containing CR LF or
/// its URL-encoded form.
fn is_crlf_const(e: &Expr) -> bool {
    match e {
        Expr::Constant(c) => match &c.value {
            Constant::Str(s) => s.contains("\r\n") || s.to_ascii_lowercase().contains("%0d%0a"),
            Constant::Bytes(b) => {
                b.windows(2).any(|w| w == b"\r\n")
                    || b.to_ascii_lowercase().windows(6).any(|w| w == b"%0d%0a")
            }
            _ => false,
        },
        _ => false,
    }
}

/// Last segment of each plain `Name`/`Attribute` assignment target.
fn target_tails(targets: &[Expr]) -> Vec<String> {
    targets
        .iter()
        .filter_map(|t| match t {
            Expr::Attribute(a) => Some(a.attr.to_string()),
            Expr::Name(n) => Some(n.id.to_string()),
            _ => None,
        })
        .collect()
}

fn bool_value(e: &Expr) -> Option<bool> {
    match e {
        Expr::Constant(c) => match c.value {
            Constant::Bool(b) => Some(b),
            _ => None,
        },
        _ => None,
    }
}

/// Every identifier (bare name or attribute) inside `e` -- mirrors the
/// `ast.walk`-based `_names_in` for the expression shapes arguments take.
fn names_in_expr(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Name(n) => out.push(n.id.to_string()),
        Expr::Attribute(a) => {
            out.push(a.attr.to_string());
            names_in_expr(&a.value, out);
        }
        Expr::Call(c) => {
            names_in_expr(&c.func, out);
            for a in &c.args {
                names_in_expr(a, out);
            }
            for kw in &c.keywords {
                names_in_expr(&kw.value, out);
            }
        }
        Expr::BinOp(b) => {
            names_in_expr(&b.left, out);
            names_in_expr(&b.right, out);
        }
        Expr::JoinedStr(j) => j.values.iter().for_each(|v| names_in_expr(v, out)),
        Expr::FormattedValue(f) => names_in_expr(&f.value, out),
        Expr::Subscript(s) => {
            names_in_expr(&s.value, out);
            names_in_expr(&s.slice, out);
        }
        Expr::Tuple(t) => t.elts.iter().for_each(|v| names_in_expr(v, out)),
        Expr::List(l) => l.elts.iter().for_each(|v| names_in_expr(v, out)),
        Expr::Starred(s) => names_in_expr(&s.value, out),
        _ => {}
    }
}

const WEAK_TLS_PROTOCOLS: &[&str] = &[
    "PROTOCOL_SSLv2",
    "PROTOCOL_SSLv3",
    "PROTOCOL_TLSv1",
    "PROTOCOL_TLSv1_1",
];

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
        let keyword_false_names: Vec<String> = node
            .keywords
            .iter()
            .filter(|kw| is_false_constant(&kw.value))
            .filter_map(|kw| kw.arg.as_ref().map(|a| a.to_string()))
            .collect();
        let first_arg_str = match node.args.first() {
            Some(Expr::Constant(c)) => match &c.value {
                Constant::Str(s) => Some(s.to_string()),
                _ => None,
            },
            _ => None,
        };
        let arg_dotted_names: Vec<String> = node
            .args
            .iter()
            .chain(node.keywords.iter().map(|kw| &kw.value))
            .map(full_attr)
            .filter(|d| !d.is_empty())
            .collect();
        let has_args = !node.args.is_empty() || !node.keywords.is_empty();
        let str_args: Vec<String> = node
            .args
            .iter()
            .chain(node.keywords.iter().map(|kw| &kw.value))
            .filter_map(|a| match a {
                Expr::Constant(c) => match &c.value {
                    Constant::Str(s) => Some(s.to_string()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        let mut arg_names = Vec::new();
        for a in node
            .args
            .iter()
            .chain(node.keywords.iter().map(|kw| &kw.value))
        {
            names_in_expr(a, &mut arg_names);
        }
        let is_crlf_format_call = matches!(
            node.func.as_ref(),
            Expr::Attribute(a) if a.attr.as_str() == "format" && is_crlf_const(&a.value)
        ) && has_args;
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
            call_name: call_name(&node),
            full_attr: fa,
            keyword_false_names,
            first_arg_str,
            arg_dotted_names,
            is_crlf_format_call,
            has_args,
            n_positional: node.args.len(),
            str_args,
            arg_names,
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
        let has_diagnostic =
            crate::ast_helpers::handler_has_diagnostic(&node.body, node.name.as_deref());
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

    fn visit_stmt_class_def(&mut self, node: StmtClassDef) {
        if looks_like_request_model(node.name.as_str()) && node.bases.iter().any(is_pydantic_base) {
            for stmt in &node.body {
                if let Stmt::AnnAssign(ann) = stmt
                    && let Expr::Name(target) = ann.target.as_ref()
                    && let Some(base_type) = str_or_bytes_base_type(&ann.annotation)
                {
                    let has_constraint =
                        has_length_constraint(&ann.annotation, ann.value.as_deref());
                    self.out.pydantic_fields.push(PydanticFieldRec {
                        line: self.li.line_number(ann.start()),
                        field_name: target.id.to_string(),
                        base_type,
                        has_constraint,
                    });
                }
            }
        }
        self.generic_visit_stmt_class_def(node);
    }

    fn visit_expr_compare(&mut self, node: ExprCompare) {
        self.compare_operand_starts.insert(node.left.start());
        for c in &node.comparators {
            self.compare_operand_starts.insert(c.start());
        }
        self.generic_visit_expr_compare(node);
    }

    fn visit_stmt_import(&mut self, node: StmtImport) {
        let line = self.li.line_number(node.start());
        let mut roots = Vec::new();
        for alias in &node.names {
            roots.push(alias.name.split('.').next().unwrap_or("").to_string());
            if let Some(asname) = &alias.asname
                && asname != &alias.name
            {
                self.out
                    .aliases
                    .insert(asname.to_string(), alias.name.to_string());
            }
        }
        self.out.import_stmts.push((line, roots));
        self.generic_visit_stmt_import(node);
    }

    fn visit_stmt_import_from(&mut self, node: StmtImportFrom) {
        let line = self.li.line_number(node.start());
        let absolute = node.level.as_ref().is_none_or(|l| l.to_u32() == 0);
        let mut roots = Vec::new();
        if let Some(module) = &node.module
            && absolute
        {
            roots.push(module.split('.').next().unwrap_or("").to_string());
            for alias in &node.names {
                if alias.name.as_str() != "*" {
                    let local = alias.asname.as_ref().unwrap_or(&alias.name).to_string();
                    self.out
                        .aliases
                        .insert(local, format!("{module}.{}", alias.name));
                }
            }
        }
        self.out.import_stmts.push((line, roots));
        self.generic_visit_stmt_import_from(node);
    }

    fn visit_expr_constant(&mut self, node: ExprConstant) {
        if matches!(&node.value, Constant::Str(s) if s == "0.0.0.0") {
            self.out
                .bind_all_lines
                .push(self.li.line_number(node.start()));
        }
        self.generic_visit_expr_constant(node);
    }

    fn visit_expr_attribute(&mut self, node: ExprAttribute) {
        if WEAK_TLS_PROTOCOLS.contains(&node.attr.as_str()) {
            self.out
                .weak_tls_refs
                .push((self.li.line_number(node.start()), node.attr.to_string()));
        }
        if node.attr.as_str() == "CERT_NONE" {
            let in_compare = self.compare_operand_starts.contains(&node.start());
            self.out
                .cert_none_refs
                .push((self.li.line_number(node.start()), in_compare));
        }
        self.generic_visit_expr_attribute(node);
    }

    fn visit_expr_name(&mut self, node: ExprName) {
        if WEAK_TLS_PROTOCOLS.contains(&node.id.as_str()) {
            self.out
                .weak_tls_refs
                .push((self.li.line_number(node.start()), node.id.to_string()));
        }
        if node.id.as_str() == "CERT_NONE" {
            let in_compare = self.compare_operand_starts.contains(&node.start());
            self.out
                .cert_none_refs
                .push((self.li.line_number(node.start()), in_compare));
        }
        self.generic_visit_expr_name(node);
    }

    fn visit_expr_bin_op(&mut self, node: ExprBinOp) {
        if matches!(node.op, Operator::Add | Operator::Mod) {
            let sides = [node.left.as_ref(), node.right.as_ref()];
            if sides.iter().any(|s| is_crlf_const(s))
                && sides.iter().any(|s| !matches!(s, Expr::Constant(_)))
            {
                self.out
                    .crlf_combo_lines
                    .push(self.li.line_number(node.start()));
            }
        }
        self.generic_visit_expr_bin_op(node);
    }

    fn visit_expr_joined_str(&mut self, node: ExprJoinedStr) {
        if node.values.iter().any(is_crlf_const)
            && node
                .values
                .iter()
                .any(|v| matches!(v, Expr::FormattedValue(_)))
        {
            self.out
                .crlf_combo_lines
                .push(self.li.line_number(node.start()));
        }
        self.generic_visit_expr_joined_str(node);
    }

    fn visit_stmt_assign(&mut self, node: StmtAssign) {
        let line = self.li.line_number(node.start());
        if let Some(v) = bool_value(&node.value) {
            for tail in target_tails(&node.targets) {
                self.out.bool_assigns.push((line, tail, v));
            }
        }
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
        if let Some(v) = node.value.as_deref().and_then(bool_value) {
            for tail in target_tails(std::slice::from_ref(&node.target)) {
                self.out.bool_assigns.push((line, tail, v));
            }
        }
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

fn collect(tree: &ModModule, li: &LineIndex) -> Collected {
    let mut collector = Collector {
        li,
        out: Collected::default(),
        compare_operand_starts: HashSet::new(),
    };
    for stmt in tree.body.clone() {
        collector.visit_stmt(stmt);
    }
    let mut out = collector.out;
    for call in &mut out.calls {
        call.full_attr = resolve_dotted(&call.full_attr, &out.aliases);
    }
    out
}

/// One parsed Python file, shared by every check that runs on it. The
/// derived views are built on first use and cached: before this, each of
/// the AST checks cloned and re-walked the module itself -- 22 walks per
/// file, growing with every regex check converted.
pub struct ParsedFile {
    pub module: ModModule,
    li: LineIndex,
    collected: OnceCell<Collected>,
    scoped: OnceCell<Vec<ScopedCall>>,
}

impl ParsedFile {
    pub fn new(module: ModModule, source: &str) -> Self {
        Self {
            module,
            li: LineIndex::new(source),
            collected: OnceCell::new(),
            scoped: OnceCell::new(),
        }
    }

    /// `scanner::parse_source` + `new`; `None` when the file doesn't parse.
    pub fn parse(source: &str, path: &Path) -> Option<Self> {
        crate::scanner::parse_source(source, path).map(|m| Self::new(m, source))
    }

    pub fn line_index(&self) -> &LineIndex {
        &self.li
    }

    /// The `Collector`'s record tables (calls, handlers, defs, ...).
    pub fn collected(&self) -> &Collected {
        self.collected
            .get_or_init(|| collect(&self.module, &self.li))
    }

    /// Every call with its enclosing scope's parameters, literal bindings
    /// and imports -- see `ast_helpers::iter_calls_in_scope`.
    pub fn scoped_calls(&self) -> &[ScopedCall] {
        self.scoped
            .get_or_init(|| iter_calls_in_scope(&self.module))
    }
}
