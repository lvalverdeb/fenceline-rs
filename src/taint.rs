//! Intra-procedural taint classification for injection-shaped sinks --
//! mirrors `fenceline/taint.py`.
//!
//! A check like `check_command_injection` knows the *shape* of a dangerous
//! call but not where its data came from. This module answers that one
//! question within the enclosing function: `Source` when a recognised
//! entry point (a request object, `os.environ`, `sys.argv`, `input()`, a
//! socket read, a route handler's parameter) reaches the sink; `Internal`
//! when only plain parameters, `self` attributes or unresolvable values do;
//! `Clean` when every input is a literal, a module constant, a library
//! reference, or a value that cannot carry a payload.
//!
//! Flow-insensitive and never crossing a function boundary: a name's taint
//! is the worst of every value assigned to it anywhere in the same scope.
//! `confidence_for` maps the result onto the finding's confidence axis.
//!
//! The scope model follows the Python original exactly, including its
//! edges: statements directly in a class body, inside a lambda, in a
//! decorator or in a default argument belong to no scope and classify as
//! `Internal`; a nested function sees module names but not its enclosing
//! function's locals.

use crate::analysis::expr_dotted_name;
use crate::ast_helpers::{
    walk_arguments_children, walk_comprehension_children, walk_keyword_children,
    walk_withitem_children,
};
use crate::models::Confidence;
use rustpython_ast::text_size::TextSize;
use rustpython_ast::{
    Arguments, Comprehension, Expr, ExprBinOp, ExprCall, ExprJoinedStr, ExprLambda, ExprNamedExpr,
    Keyword, ModModule, Ranged, Stmt, StmtAnnAssign, StmtAssign, StmtAsyncFor,
    StmtAsyncFunctionDef, StmtAsyncWith, StmtAugAssign, StmtClassDef, StmtFor, StmtFunctionDef,
    StmtImport, StmtImportFrom, StmtWith, Visitor, WithItem,
};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Taint {
    Clean,
    Internal,
    /// A parameter that a caller elsewhere in the package feeds request
    /// data (`crate::callers`); as reportable as `Source`, with its own note.
    Caller,
    Source,
}

/// Appended to a finding's description when no source reaches the sink.
pub const INTERNAL_NOTE: &str =
    " No request or environment input reaches this call within the enclosing function.";

/// Appended when the source is a caller's argument, not this function's code.
pub const CALLER_NOTE: &str =
    " Request data reaches a parameter of this function from a caller in the package.";

const REQUEST_ROOTS: &[&str] = &["request", "environ"];
const SOURCE_PREFIXES: &[&str] = &["os.environ", "sys.argv", "sys.stdin", "self.request"];
const SOURCE_CALLS: &[&str] = &["input", "os.getenv", "os.environb.get"];
const SOURCE_METHODS: &[&str] = &[
    "recv",
    "recv_into",
    "recvfrom",
    "recvmsg",
    "get_argument",
    "get_arguments",
    "get_query_argument",
    "get_query_arguments",
    "get_body_argument",
    "get_body_arguments",
    "get_cookie",
    "get_secure_cookie",
    "get_json",
    "get_data",
];
const CLEAN_CALLS: &[&str] = &[
    "int",
    "float",
    "bool",
    "len",
    "abs",
    "round",
    "hash",
    "id",
    "isinstance",
    "ord",
    "min",
    "max",
    "sum",
    "shlex.quote",
    "shlex.join",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
    "html.escape",
    "re.escape",
];
const CLEAN_METHODS: &[&str] = &[
    "isdigit",
    "isalnum",
    "isalpha",
    "isidentifier",
    "startswith",
    "endswith",
    "count",
    "index",
    "find",
    "rfind",
    "isdisjoint",
];
const ROUTE_DECORATORS: &[&str] = &[
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "api_route",
    "websocket",
    "websocket_route",
    "view",
    "middleware",
];
const HANDLER_BASES: &[&str] = &[
    "Handler", "View", "ViewSet", "Resource", "Endpoint", "Consumer",
];
const HANDLER_METHODS: &[&str] = &[
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "prepare",
    "dispatch",
    "open",
    "on_message",
    "data_received",
    "receive",
];

/// `dir(builtins)` on CPython 3.13 -- a bare name the scope does not bind
/// resolves here before falling through to `Internal`.
const BUILTIN_NAMES: &[&str] = &[
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "BaseException",
    "BaseExceptionGroup",
    "BlockingIOError",
    "BrokenPipeError",
    "BufferError",
    "BytesWarning",
    "ChildProcessError",
    "ConnectionAbortedError",
    "ConnectionError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "DeprecationWarning",
    "EOFError",
    "Ellipsis",
    "EncodingWarning",
    "EnvironmentError",
    "Exception",
    "ExceptionGroup",
    "False",
    "FileExistsError",
    "FileNotFoundError",
    "FloatingPointError",
    "FutureWarning",
    "GeneratorExit",
    "IOError",
    "ImportError",
    "ImportWarning",
    "IndentationError",
    "IndexError",
    "InterruptedError",
    "IsADirectoryError",
    "KeyError",
    "KeyboardInterrupt",
    "LookupError",
    "MemoryError",
    "ModuleNotFoundError",
    "NameError",
    "None",
    "NotADirectoryError",
    "NotImplemented",
    "NotImplementedError",
    "OSError",
    "OverflowError",
    "PendingDeprecationWarning",
    "PermissionError",
    "ProcessLookupError",
    "PythonFinalizationError",
    "RecursionError",
    "ReferenceError",
    "ResourceWarning",
    "RuntimeError",
    "RuntimeWarning",
    "StopAsyncIteration",
    "StopIteration",
    "SyntaxError",
    "SyntaxWarning",
    "SystemError",
    "SystemExit",
    "TabError",
    "TimeoutError",
    "True",
    "TypeError",
    "UnboundLocalError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "UnicodeError",
    "UnicodeTranslateError",
    "UnicodeWarning",
    "UserWarning",
    "ValueError",
    "Warning",
    "ZeroDivisionError",
    "_IncompleteInputError",
    "__build_class__",
    "__debug__",
    "__doc__",
    "__import__",
    "__loader__",
    "__name__",
    "__package__",
    "__spec__",
    "abs",
    "aiter",
    "all",
    "anext",
    "any",
    "ascii",
    "bin",
    "bool",
    "breakpoint",
    "bytearray",
    "bytes",
    "callable",
    "chr",
    "classmethod",
    "compile",
    "complex",
    "copyright",
    "credits",
    "delattr",
    "dict",
    "dir",
    "divmod",
    "enumerate",
    "eval",
    "exec",
    "exit",
    "filter",
    "float",
    "format",
    "frozenset",
    "getattr",
    "globals",
    "hasattr",
    "hash",
    "help",
    "hex",
    "id",
    "input",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "license",
    "list",
    "locals",
    "map",
    "max",
    "memoryview",
    "min",
    "next",
    "object",
    "oct",
    "open",
    "ord",
    "pow",
    "print",
    "property",
    "quit",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "setattr",
    "slice",
    "sorted",
    "staticmethod",
    "str",
    "sum",
    "super",
    "tuple",
    "type",
    "vars",
    "zip",
];
const MAX_DEPTH: u32 = 10;

/// One function's (or the module's) view of its names.
pub struct ScopeInfo {
    params: HashSet<String>,
    handler: bool,
    assigns: HashMap<String, Vec<Expr>>,
    imports: HashSet<String>,
    /// Name of the class whose body directly holds this function, if any.
    cls: Option<String>,
    /// Parameters some caller in the package feeds request data (set by
    /// `crate::callers` after every file of the package is parsed).
    caller_params: RefCell<HashSet<String>>,
}

/// Every `Name` inside an assignment target, like `ast.walk(target)` in the
/// Python original: `a, (b, *c) = v`, and also the base and index of
/// `d[k] = v` or `self.x = v`.
fn bind_names(target: &Expr, out: &mut Vec<String>) {
    match target {
        Expr::Name(n) => out.push(n.id.to_string()),
        Expr::Attribute(a) => bind_names(&a.value, out),
        Expr::Subscript(s) => {
            bind_names(&s.value, out);
            bind_names(&s.slice, out);
        }
        Expr::Starred(s) => bind_names(&s.value, out),
        Expr::Tuple(t) => t.elts.iter().for_each(|e| bind_names(e, out)),
        Expr::List(l) => l.elts.iter().for_each(|e| bind_names(e, out)),
        _ => {}
    }
}

/// Collects one scope's own bindings without descending into nested
/// function, lambda or class bodies -- mirrors `taint._collect`.
struct ScopeCollector {
    assigns: HashMap<String, Vec<Expr>>,
    imports: HashSet<String>,
}

impl ScopeCollector {
    fn bind(&mut self, target: &Expr, value: &Expr) {
        let mut names = Vec::new();
        bind_names(target, &mut names);
        for name in names {
            self.assigns.entry(name).or_default().push(value.clone());
        }
    }
}

impl Visitor for ScopeCollector {
    fn visit_stmt_function_def(&mut self, node: StmtFunctionDef) {
        self.imports.insert(node.name.to_string());
    }
    fn visit_stmt_async_function_def(&mut self, node: StmtAsyncFunctionDef) {
        self.imports.insert(node.name.to_string());
    }
    fn visit_stmt_class_def(&mut self, node: StmtClassDef) {
        self.imports.insert(node.name.to_string());
    }
    fn visit_expr_lambda(&mut self, _node: ExprLambda) {}

    fn visit_stmt_assign(&mut self, node: StmtAssign) {
        for target in &node.targets {
            self.bind(target, &node.value);
        }
        self.generic_visit_stmt_assign(node);
    }
    fn visit_stmt_ann_assign(&mut self, node: StmtAnnAssign) {
        if let Some(value) = &node.value {
            self.bind(&node.target, value);
        }
        self.generic_visit_stmt_ann_assign(node);
    }
    fn visit_stmt_aug_assign(&mut self, node: StmtAugAssign) {
        self.bind(&node.target, &node.value);
        self.generic_visit_stmt_aug_assign(node);
    }
    fn visit_expr_named_expr(&mut self, node: ExprNamedExpr) {
        self.bind(&node.target, &node.value);
        self.generic_visit_expr_named_expr(node);
    }
    fn visit_stmt_for(&mut self, node: StmtFor) {
        self.bind(&node.target, &node.iter);
        self.generic_visit_stmt_for(node);
    }
    fn visit_stmt_async_for(&mut self, node: StmtAsyncFor) {
        self.bind(&node.target, &node.iter);
        self.generic_visit_stmt_async_for(node);
    }
    fn visit_stmt_with(&mut self, node: StmtWith) {
        for item in &node.items {
            if let Some(vars) = &item.optional_vars {
                self.bind(vars, &item.context_expr);
            }
        }
        self.generic_visit_stmt_with(node);
    }
    fn visit_stmt_async_with(&mut self, node: StmtAsyncWith) {
        for item in &node.items {
            if let Some(vars) = &item.optional_vars {
                self.bind(vars, &item.context_expr);
            }
        }
        self.generic_visit_stmt_async_with(node);
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

    fn visit_arguments(&mut self, node: Arguments) {
        walk_arguments_children(self, node);
    }
    fn visit_comprehension(&mut self, node: Comprehension) {
        self.bind(&node.target, &node.iter);
        walk_comprehension_children(self, node);
    }
    fn visit_keyword(&mut self, node: Keyword) {
        walk_keyword_children(self, node);
    }
    fn visit_withitem(&mut self, node: WithItem) {
        walk_withitem_children(self, node);
    }
}

fn collect_own(stmts: &[Stmt]) -> ScopeCollector {
    let mut collector = ScopeCollector {
        assigns: HashMap::new(),
        imports: HashSet::new(),
    };
    for stmt in stmts {
        collector.visit_stmt(stmt.clone());
    }
    collector
}

fn is_handler(name: &str, decorators: &[Expr], enclosing_class_bases: Option<&[String]>) -> bool {
    for deco in decorators {
        let target = match deco {
            Expr::Call(c) => c.func.as_ref(),
            other => other,
        };
        let dotted = expr_dotted_name(target);
        let tail = dotted.rsplit('.').next().unwrap_or("");
        if dotted.contains('.') && ROUTE_DECORATORS.contains(&tail) {
            return true;
        }
    }
    if let Some(bases) = enclosing_class_bases
        && HANDLER_METHODS.contains(&name)
    {
        return bases
            .iter()
            .any(|b| HANDLER_BASES.iter().any(|h| b.ends_with(h)));
    }
    false
}

fn param_names(args: &Arguments) -> HashSet<String> {
    let mut out: HashSet<String> = args
        .posonlyargs
        .iter()
        .chain(args.args.iter())
        .chain(args.kwonlyargs.iter())
        .map(|a| a.def.arg.to_string())
        .filter(|a| a != "self" && a != "cls")
        .collect();
    for extra in [&args.vararg, &args.kwarg].into_iter().flatten() {
        out.insert(extra.arg.to_string());
    }
    out
}

enum Frame {
    /// A function and its qualified name (`Class.method`, `outer.inner`).
    Function(Rc<ScopeInfo>, String),
    /// A class: its name and its bases' dotted names.
    Class(String, Vec<String>),
    /// A lambda, decorator, default argument or class base: no scope.
    Opaque,
}

/// Walks the whole module once, building each function's `ScopeInfo` and
/// recording which scope every sink-shaped node (call, binary op, f-string)
/// sits in -- mirrors `taint._scope_map`.
struct ScopeIndexer {
    module: Rc<ScopeInfo>,
    frames: Vec<Frame>,
    at: HashMap<TextSize, Option<Rc<ScopeInfo>>>,
    functions: HashMap<String, Rc<ScopeInfo>>,
}

impl ScopeIndexer {
    fn current(&self) -> Option<Rc<ScopeInfo>> {
        match self.frames.last() {
            None => Some(Rc::clone(&self.module)),
            Some(Frame::Function(s, _)) => Some(Rc::clone(s)),
            Some(Frame::Class(..)) | Some(Frame::Opaque) => None,
        }
    }

    fn enclosing_class(&self) -> Option<(&str, &[String])> {
        match self.frames.last() {
            Some(Frame::Class(name, bases)) => Some((name, bases)),
            _ => None,
        }
    }

    /// `Class.` / `outer.` / "" -- what precedes a function's own name.
    fn qualname_prefix(&self) -> String {
        match self.frames.last() {
            Some(Frame::Class(name, _)) => format!("{name}."),
            Some(Frame::Function(_, qualname)) => format!("{qualname}."),
            _ => String::new(),
        }
    }

    fn function_scope(
        &self,
        name: &str,
        args: &Arguments,
        decorators: &[Expr],
        body: &[Stmt],
    ) -> Rc<ScopeInfo> {
        let cls = self.enclosing_class();
        let handler = is_handler(name, decorators, cls.map(|(_, bases)| bases));
        let own = collect_own(body);
        let mut assigns: HashMap<String, Vec<Expr>> = self
            .module
            .assigns
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (name, values) in own.assigns {
            assigns.entry(name).or_default().extend(values);
        }
        let mut imports = self.module.imports.clone();
        imports.extend(own.imports);
        Rc::new(ScopeInfo {
            params: param_names(args),
            handler,
            assigns,
            imports,
            cls: cls.map(|(name, _)| name.to_string()),
            caller_params: RefCell::new(HashSet::new()),
        })
    }

    fn visit_function(
        &mut self,
        name: &str,
        args: Arguments,
        decorators: Vec<Expr>,
        body: Vec<Stmt>,
        returns: Option<Box<Expr>>,
    ) {
        let scope = self.function_scope(name, &args, &decorators, &body);
        let qualname = format!("{}{name}", self.qualname_prefix());
        self.functions.insert(qualname.clone(), Rc::clone(&scope));
        // Decorators, defaults and annotations belong to no scope.
        self.frames.push(Frame::Opaque);
        for deco in decorators {
            self.visit_expr(deco);
        }
        self.visit_arguments(args);
        if let Some(returns) = returns {
            self.visit_expr(*returns);
        }
        self.frames.pop();
        self.frames.push(Frame::Function(scope, qualname));
        for stmt in body {
            self.visit_stmt(stmt);
        }
        self.frames.pop();
    }
}

impl Visitor for ScopeIndexer {
    fn visit_stmt_function_def(&mut self, node: StmtFunctionDef) {
        let StmtFunctionDef {
            name,
            args,
            body,
            decorator_list,
            returns,
            ..
        } = node;
        self.visit_function(name.as_str(), *args, decorator_list, body, returns);
    }
    fn visit_stmt_async_function_def(&mut self, node: StmtAsyncFunctionDef) {
        let StmtAsyncFunctionDef {
            name,
            args,
            body,
            decorator_list,
            returns,
            ..
        } = node;
        self.visit_function(name.as_str(), *args, decorator_list, body, returns);
    }
    fn visit_stmt_class_def(&mut self, node: StmtClassDef) {
        let bases: Vec<String> = node.bases.iter().map(expr_dotted_name).collect();
        self.frames.push(Frame::Class(node.name.to_string(), bases));
        self.generic_visit_stmt_class_def(node);
        self.frames.pop();
    }
    fn visit_expr_lambda(&mut self, node: ExprLambda) {
        self.frames.push(Frame::Opaque);
        self.generic_visit_expr_lambda(node);
        self.frames.pop();
    }

    fn visit_expr_call(&mut self, node: ExprCall) {
        self.at.insert(node.start(), self.current());
        self.generic_visit_expr_call(node);
    }
    fn visit_expr_bin_op(&mut self, node: ExprBinOp) {
        self.at.insert(node.start(), self.current());
        self.generic_visit_expr_bin_op(node);
    }
    fn visit_expr_joined_str(&mut self, node: ExprJoinedStr) {
        self.at.insert(node.start(), self.current());
        self.generic_visit_expr_joined_str(node);
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

/// Per-file scope index: which `ScopeInfo` a sink node resolves names in.
pub struct TaintIndex {
    at: HashMap<TextSize, Option<Rc<ScopeInfo>>>,
    functions: HashMap<String, Rc<ScopeInfo>>,
}

impl TaintIndex {
    pub fn build(tree: &ModModule) -> Self {
        let own = collect_own(&tree.body);
        let module = Rc::new(ScopeInfo {
            params: HashSet::new(),
            handler: false,
            assigns: own.assigns,
            imports: own.imports,
            cls: None,
            caller_params: RefCell::new(HashSet::new()),
        });
        let mut indexer = ScopeIndexer {
            module,
            frames: Vec::new(),
            at: HashMap::new(),
            functions: HashMap::new(),
        };
        for stmt in tree.body.clone() {
            indexer.visit_stmt(stmt);
        }
        TaintIndex {
            at: indexer.at,
            functions: indexer.functions,
        }
    }

    /// Name of the class whose method directly contains the node at
    /// `anchor`, if any -- mirrors `taint.enclosing_class`.
    pub fn enclosing_class(&self, anchor: TextSize) -> Option<&str> {
        match self.at.get(&anchor) {
            Some(Some(scope)) => scope.cls.as_deref(),
            _ => None,
        }
    }

    /// Record that some caller feeds request data to `param` of the
    /// function `qualname`; `true` when this is new information -- mirrors
    /// `taint.mark_caller_param`.
    pub fn mark_caller_param(&self, qualname: &str, param: &str) -> bool {
        let Some(scope) = self.functions.get(qualname) else {
            return false;
        };
        if !scope.params.contains(param) {
            return false;
        }
        scope.caller_params.borrow_mut().insert(param.to_string())
    }

    /// Worst taint over `exprs`, resolved in the scope of the sink node
    /// starting at `anchor`. A node the index does not know (or one in a
    /// class body, lambda, decorator or default) is `Internal`. An empty
    /// `exprs` is `Clean`: a sink fed nothing has nothing to inject.
    pub fn classify<'e>(
        &self,
        anchor: TextSize,
        exprs: impl IntoIterator<Item = &'e Expr>,
    ) -> Taint {
        match self.at.get(&anchor) {
            Some(Some(scope)) => Classifier::new(scope).many(exprs, 0),
            _ => Taint::Internal,
        }
    }

    /// Every expression assigned to `name` in the scope of the sink node
    /// starting at `anchor`; empty when the scope is unknown or the name is
    /// never assigned there -- mirrors `taint.bound_values`.
    pub fn bound_values(&self, anchor: TextSize, name: &str) -> &[Expr] {
        match self.at.get(&anchor) {
            Some(Some(scope)) => scope.assigns.get(name).map(Vec::as_slice).unwrap_or(&[]),
            _ => &[],
        }
    }
}

fn source_chain(dotted: &str) -> bool {
    let root = dotted.split('.').next().unwrap_or("");
    REQUEST_ROOTS.contains(&root) || SOURCE_PREFIXES.iter().any(|p| dotted.starts_with(p))
}

struct Classifier<'s> {
    scope: &'s ScopeInfo,
    active: HashSet<String>,
}

impl<'s> Classifier<'s> {
    fn new(scope: &'s ScopeInfo) -> Self {
        Classifier {
            scope,
            active: HashSet::new(),
        }
    }

    fn name(&mut self, name: &str, depth: u32) -> Taint {
        if REQUEST_ROOTS.contains(&name) {
            return Taint::Source;
        }
        if self.scope.params.contains(name) {
            if self.scope.handler {
                return Taint::Source;
            }
            return if self.scope.caller_params.borrow().contains(name) {
                Taint::Caller
            } else {
                Taint::Internal
            };
        }
        if let Some(values) = self.scope.assigns.get(name) {
            if self.active.contains(name) {
                return Taint::Clean; // cycle: the other branch decides
            }
            self.active.insert(name.to_string());
            let worst = self.many(values.iter(), depth + 1);
            self.active.remove(name);
            return worst;
        }
        if self.scope.imports.contains(name) || BUILTIN_NAMES.contains(&name) {
            return Taint::Clean;
        }
        Taint::Internal
    }

    fn many<'e>(&mut self, exprs: impl IntoIterator<Item = &'e Expr>, depth: u32) -> Taint {
        let mut worst = Taint::Clean;
        for e in exprs {
            worst = worst.max(self.expr(e, depth));
            if worst == Taint::Source {
                break;
            }
        }
        worst
    }

    fn expr(&mut self, node: &Expr, depth: u32) -> Taint {
        if depth > MAX_DEPTH {
            return Taint::Internal;
        }
        match node {
            Expr::Constant(_) => Taint::Clean,
            Expr::Name(n) => self.name(n.id.as_str(), depth),
            Expr::Attribute(a) => {
                let dotted = expr_dotted_name(node);
                if !dotted.is_empty() && source_chain(&dotted) {
                    return Taint::Source;
                }
                if matches!(a.value.as_ref(), Expr::Name(n) if n.id.as_str() == "self") {
                    return Taint::Internal;
                }
                self.expr(&a.value, depth + 1)
            }
            Expr::Subscript(s) => {
                let dotted = expr_dotted_name(&s.value);
                if !dotted.is_empty() && source_chain(&dotted) {
                    return Taint::Source;
                }
                self.expr(&s.value, depth + 1)
                    .max(self.expr(&s.slice, depth + 1))
            }
            Expr::Call(c) => {
                let dotted = expr_dotted_name(&c.func);
                let method = match c.func.as_ref() {
                    Expr::Attribute(a) => a.attr.as_str(),
                    _ => "",
                };
                if SOURCE_CALLS.contains(&dotted.as_str())
                    || source_chain(&dotted)
                    || SOURCE_METHODS.contains(&method)
                {
                    return Taint::Source;
                }
                if CLEAN_CALLS.contains(&dotted.as_str()) || CLEAN_METHODS.contains(&method) {
                    return Taint::Clean;
                }
                self.expr(&c.func, depth + 1)
                    .max(self.many(c.args.iter(), depth + 1))
                    .max(self.many(c.keywords.iter().map(|kw| &kw.value), depth + 1))
            }
            Expr::JoinedStr(j) => self.many(
                j.values
                    .iter()
                    .filter(|v| matches!(v, Expr::FormattedValue(_))),
                depth + 1,
            ),
            Expr::FormattedValue(f) => self.expr(&f.value, depth + 1),
            Expr::BinOp(b) => self
                .expr(&b.left, depth + 1)
                .max(self.expr(&b.right, depth + 1)),
            Expr::BoolOp(b) => self.many(b.values.iter(), depth + 1),
            Expr::Tuple(t) => self.many(t.elts.iter(), depth + 1),
            Expr::List(l) => self.many(l.elts.iter(), depth + 1),
            Expr::Set(s) => self.many(s.elts.iter(), depth + 1),
            Expr::Dict(d) => self.many(d.keys.iter().flatten().chain(d.values.iter()), depth + 1),
            Expr::IfExp(i) => self
                .expr(&i.body, depth + 1)
                .max(self.expr(&i.orelse, depth + 1)),
            Expr::Starred(s) => self.expr(&s.value, depth + 1),
            Expr::Await(a) => self.expr(&a.value, depth + 1),
            Expr::NamedExpr(n) => self.expr(&n.value, depth + 1),
            Expr::UnaryOp(u) => self.expr(&u.operand, depth + 1),
            Expr::ListComp(c) => self
                .expr(&c.elt, depth + 1)
                .max(self.many(c.generators.iter().map(|g| &g.iter), depth + 1)),
            Expr::SetComp(c) => self
                .expr(&c.elt, depth + 1)
                .max(self.many(c.generators.iter().map(|g| &g.iter), depth + 1)),
            Expr::GeneratorExp(c) => self
                .expr(&c.elt, depth + 1)
                .max(self.many(c.generators.iter().map(|g| &g.iter), depth + 1)),
            Expr::DictComp(c) => self
                .expr(&c.key, depth + 1)
                .max(self.expr(&c.value, depth + 1))
                .max(self.many(c.generators.iter().map(|g| &g.iter), depth + 1)),
            Expr::Compare(_) | Expr::Lambda(_) => Taint::Clean,
            _ => Taint::Internal,
        }
    }
}

/// Finding confidence and description suffix for a sink's taint, or `None`
/// to drop the finding -- mirrors `taint.confidence_for` plus the checks'
/// shared `_tainted` helper.
pub fn confidence_for(taint: Taint) -> Option<(Confidence, &'static str)> {
    match taint {
        Taint::Source => Some((Confidence::High, "")),
        Taint::Caller => Some((Confidence::High, CALLER_NOTE)),
        Taint::Internal => Some((Confidence::Medium, INTERNAL_NOTE)),
        Taint::Clean => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::ParsedFile;
    use std::path::Path;

    /// Taint of the arguments of the first call to `sink(...)` in `source`.
    fn sink_taint(source: &str) -> Taint {
        let file = ParsedFile::parse(source, Path::new("t.py")).expect("parses");
        let rec = file
            .collected()
            .calls
            .iter()
            .find(|c| c.full_attr == "sink")
            .expect("a sink call");
        rec.data_taint
    }

    fn in_function(body: &str) -> String {
        format!(
            "import os, shlex, sys\nfrom flask import request\nCONST = 'fixed'\n\ndef f(self, blob):\n    {}\n",
            body.replace('\n', "\n    ")
        )
    }

    #[test]
    fn classification_table() {
        let cases: &[(&str, Taint)] = &[
            ("sink(\"literal\")", Taint::Clean),
            ("sink(CONST)", Taint::Clean),
            ("sink([sys.executable, '-m', 'x'])", Taint::Clean),
            ("sink(len(blob))", Taint::Clean),
            ("sink(shlex.quote(blob))", Taint::Clean),
            ("sink(blob)", Taint::Internal),
            ("sink(blob.strip().lower())", Taint::Internal),
            ("sink(self.cmd)", Taint::Internal),
            ("sink(unknown_global)", Taint::Internal),
            ("sink(f'{CONST}-{blob}')", Taint::Internal),
            ("sink(request.args['x'])", Taint::Source),
            ("sink(os.environ.get('X'))", Taint::Source),
            ("sink(sys.argv[1])", Taint::Source),
            ("sink(input('> '))", Taint::Source),
            ("sink(sock.recv(1024))", Taint::Source),
            ("sink(self.request.headers['Host'])", Taint::Source),
            (
                "x = request.form['q']\ny = x.upper()\nsink('cmd ' + y)",
                Taint::Source,
            ),
            (
                "parts = [CONST]\nparts.append(blob)\nsink(' '.join(parts))",
                Taint::Clean,
            ),
        ];
        for (body, expected) in cases {
            assert_eq!(sink_taint(&in_function(body)), *expected, "{body}");
        }
    }

    #[test]
    fn handler_parameters_are_sources() {
        assert_eq!(
            sink_taint("@app.route('/x')\ndef view(q):\n    sink(q)\n"),
            Taint::Source
        );
        assert_eq!(
            sink_taint("class H(RequestHandler):\n    def get(self, q):\n        sink(q)\n"),
            Taint::Source
        );
        assert_eq!(sink_taint("def helper(q):\n    sink(q)\n"), Taint::Internal);
    }

    #[test]
    fn flow_insensitive_over_reassignment() {
        let src =
            "import os\n\ndef f():\n    cmd = 'ls'\n    cmd = os.environ['CMD']\n    sink(cmd)\n";
        assert_eq!(sink_taint(src), Taint::Source);
    }

    #[test]
    fn nested_function_boundary_and_opaque_positions() {
        let src = "def outer(blob):\n    def inner():\n        sink('fixed')\n    sink(blob)\n";
        let file = ParsedFile::parse(src, Path::new("t.py")).unwrap();
        let taints: Vec<Taint> = file
            .collected()
            .calls
            .iter()
            .filter(|c| c.full_attr == "sink")
            .map(|c| c.data_taint)
            .collect();
        assert_eq!(taints, vec![Taint::Clean, Taint::Internal]);
        // A call in a class body, a lambda or a decorator has no scope.
        assert_eq!(sink_taint("class C:\n    x = sink('a')\n"), Taint::Internal);
        assert_eq!(sink_taint("f = lambda: sink('a')\n"), Taint::Internal);
    }
}
