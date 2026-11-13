//! Cross-file parameter taint -- mirrors `fenceline.callers`.
//!
//! `crate::taint` classifies a sink by the names that feed it inside one
//! function; a parameter of a non-handler function is `Internal` because
//! the function alone does not say where its argument came from. This
//! module looks at the callers: after every file of a package is parsed, it
//! binds each call's arguments to the callee's parameters and marks a
//! parameter `Caller` (`TaintIndex::mark_caller_param`) when some caller in
//! the package passes request data to it. Repeated to a fixpoint, so a
//! value that crosses two or three helpers still arrives.
//!
//! Callees are resolved by name: a function or class defined in the same
//! file, `from mod import f` / `import mod` (absolute, relative, or a
//! sibling file of the importer), `Class.method` for a class in scope, and
//! `self.method` inside a class. Anything else is left alone; the pass only
//! ever promotes a parameter, never creates or removes a finding.

use crate::analysis::{ParsedFile, expr_dotted_name};
use crate::ast_helpers::{
    walk_arguments_children, walk_comprehension_children, walk_keyword_children,
    walk_withitem_children,
};
use crate::taint::Taint;
use rustpython_ast::{
    Arguments, Comprehension, Expr, ExprCall, Keyword, Ranged, Stmt, StmtImport, StmtImportFrom,
    Visitor, WithItem,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const MAX_ROUNDS: usize = 8;

struct Def {
    /// posonly + regular, in order, including self/cls.
    positional: Vec<String>,
    kwonly: HashSet<String>,
    vararg: Option<String>,
    /// A method: self/cls is bound implicitly.
    skip_first: bool,
}

fn def_of(args: &Arguments, decorators: &[Expr], method: bool) -> Def {
    let is_static = decorators
        .iter()
        .any(|d| expr_dotted_name(d) == "staticmethod");
    Def {
        positional: args
            .posonlyargs
            .iter()
            .chain(args.args.iter())
            .map(|a| a.def.arg.to_string())
            .collect(),
        kwonly: args
            .kwonlyargs
            .iter()
            .map(|a| a.def.arg.to_string())
            .collect(),
        vararg: args.vararg.as_ref().map(|a| a.arg.to_string()),
        skip_first: method && !is_static,
    }
}

/// Imports and calls anywhere in a file, including inside functions.
#[derive(Default)]
struct Uses {
    /// Local name (or dotted prefix, for `import a.b`) -> module spec.
    aliases: HashMap<String, String>,
    /// Local name -> (module spec, attribute) for `from mod import attr`.
    from_names: HashMap<String, (String, String)>,
    calls: Vec<ExprCall>,
}

impl Visitor for Uses {
    fn visit_stmt_import(&mut self, node: StmtImport) {
        for alias in &node.names {
            let bound = alias.asname.as_deref().unwrap_or(&alias.name);
            self.aliases
                .insert(bound.to_string(), alias.name.to_string());
        }
    }
    fn visit_stmt_import_from(&mut self, node: StmtImportFrom) {
        let level = node.level.as_ref().map_or(0, |l| l.to_u32()) as usize;
        let spec = format!(
            "{}{}",
            ".".repeat(level),
            node.module.as_deref().unwrap_or("")
        );
        for alias in &node.names {
            if alias.name.as_str() != "*" {
                let bound = alias.asname.as_deref().unwrap_or(&alias.name);
                self.from_names
                    .insert(bound.to_string(), (spec.clone(), alias.name.to_string()));
            }
        }
    }
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

struct Module<'a> {
    path: &'a Path,
    file: &'a ParsedFile,
    defs: HashMap<String, Def>,
    classes: HashSet<String>,
    uses: Uses,
}

fn index<'a>(path: &'a Path, file: &'a ParsedFile) -> Module<'a> {
    let mut defs = HashMap::new();
    let mut classes = HashSet::new();
    for stmt in &file.module.body {
        match stmt {
            Stmt::FunctionDef(f) => {
                defs.insert(
                    f.name.to_string(),
                    def_of(&f.args, &f.decorator_list, false),
                );
            }
            Stmt::AsyncFunctionDef(f) => {
                defs.insert(
                    f.name.to_string(),
                    def_of(&f.args, &f.decorator_list, false),
                );
            }
            Stmt::ClassDef(c) => {
                classes.insert(c.name.to_string());
                for inner in &c.body {
                    let (name, args, decorators) = match inner {
                        Stmt::FunctionDef(f) => (&f.name, &f.args, &f.decorator_list),
                        Stmt::AsyncFunctionDef(f) => (&f.name, &f.args, &f.decorator_list),
                        _ => continue,
                    };
                    defs.insert(format!("{}.{name}", c.name), def_of(args, decorators, true));
                }
            }
            _ => {}
        }
    }
    let mut uses = Uses::default();
    for stmt in file.module.body.clone() {
        uses.visit_stmt(stmt);
    }
    Module {
        path,
        file,
        defs,
        classes,
        uses,
    }
}

struct Package<'a> {
    root: &'a Path,
    modules: Vec<Module<'a>>,
    by_path: HashMap<PathBuf, usize>,
    by_stem: HashMap<String, Vec<usize>>,
}

impl<'a> Package<'a> {
    fn new(files: &[(&'a Path, &'a ParsedFile)], root: &'a Path) -> Self {
        let mut sorted: Vec<_> = files.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let modules: Vec<Module<'a>> = sorted.iter().map(|(p, f)| index(p, f)).collect();
        let mut by_path = HashMap::new();
        let mut by_stem: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, m) in modules.iter().enumerate() {
            by_path.insert(m.path.to_path_buf(), i);
            if let Some(stem) = m.path.file_stem().and_then(|s| s.to_str()) {
                by_stem.entry(stem.to_string()).or_default().push(i);
            }
        }
        Package {
            root,
            modules,
            by_path,
            by_stem,
        }
    }

    fn at(&self, base: &Path, dotted: &str) -> Option<usize> {
        let mut p = base.to_path_buf();
        if !dotted.is_empty() {
            for part in dotted.split('.') {
                p.push(part);
            }
        }
        self.by_path
            .get(&p.with_extension("py"))
            .or_else(|| self.by_path.get(&p.join("__init__.py")))
            .copied()
    }

    /// The package file an import spec names, or `None` for anything
    /// outside the package. A sibling of the importer wins over a path from
    /// the package root, which wins over a unique file of that stem.
    fn module(&self, spec: &str, importer: &Module<'a>) -> Option<usize> {
        let importer_dir = importer.path.parent().unwrap_or(self.root);
        if spec.starts_with('.') {
            let level = spec.len() - spec.trim_start_matches('.').len();
            let mut base = importer_dir;
            for _ in 1..level {
                base = base.parent().unwrap_or(base);
            }
            return self.at(base, spec.trim_start_matches('.'));
        }
        self.at(importer_dir, spec)
            .or_else(|| self.at(self.root, spec))
            .or_else(|| {
                let stem = spec.rsplit('.').next().unwrap_or(spec);
                match self.by_stem.get(stem) {
                    Some(v) if v.len() == 1 => Some(v[0]),
                    _ => None,
                }
            })
    }

    /// `name` as a def of module `target`: a function, a `Class.method`, or
    /// a class (its `__init__`).
    fn callable(&self, target: Option<usize>, name: &str) -> Option<(usize, String)> {
        let t = target?;
        let defs = &self.modules[t].defs;
        if defs.contains_key(name) {
            return Some((t, name.to_string()));
        }
        let init = format!("{name}.__init__");
        defs.contains_key(&init).then_some((t, init))
    }

    fn callee(&self, m: usize, call: &ExprCall) -> Option<(usize, String)> {
        let module = &self.modules[m];
        if let Expr::Name(n) = call.func.as_ref() {
            if let Some((spec, attr)) = module.uses.from_names.get(n.id.as_str()) {
                return self.callable(self.module(spec, module), attr);
            }
            return self.callable(Some(m), n.id.as_str());
        }
        let dotted = expr_dotted_name(&call.func);
        let parts: Vec<&str> = dotted.split('.').collect();
        if dotted.is_empty() || parts.len() < 2 {
            return None;
        }
        let head = parts[0];
        if (head == "self" || head == "cls") && parts.len() == 2 {
            let cls = module.file.taint().enclosing_class(call.start())?;
            return self.callable(Some(m), &format!("{cls}.{}", parts[1]));
        }
        for i in (1..parts.len()).rev() {
            let prefix = parts[..i].join(".");
            if let Some(spec) = module.uses.aliases.get(&prefix) {
                let target = self.module(spec, module);
                return self.callable(target, &parts[i..].join("."));
            }
        }
        if parts.len() == 2 {
            if let Some((spec, attr)) = module.uses.from_names.get(head) {
                // `from pkg import mod` binds a submodule, not an attribute.
                let sub = format!("{spec}{}{attr}", if spec.ends_with('.') { "" } else { "." });
                if let Some(submodule) = self.module(&sub, module) {
                    return self.callable(Some(submodule), parts[1]);
                }
                return self.callable(self.module(spec, module), &format!("{attr}.{}", parts[1]));
            }
            if module.classes.contains(head) {
                return self.callable(Some(m), &dotted);
            }
        }
        None
    }

    /// Mark the callee's parameters that this call feeds request data;
    /// `true` when a new parameter was marked.
    fn bind(&self, m: usize, call: &ExprCall) -> bool {
        let Some((t, qualname)) = self.callee(m, call) else {
            return false;
        };
        let def = &self.modules[t].defs[&qualname];
        let positional: &[String] = if def.skip_first {
            def.positional.get(1..).unwrap_or(&[])
        } else {
            &def.positional
        };
        let mut bound: Vec<(&str, &Expr)> = Vec::new();
        for (i, arg) in call.args.iter().enumerate() {
            if matches!(arg, Expr::Starred(_)) {
                break;
            }
            if let Some(name) = positional.get(i) {
                bound.push((name, arg));
            } else if let Some(vararg) = &def.vararg {
                bound.push((vararg, arg));
            } else {
                break;
            }
        }
        for kw in &call.keywords {
            if let Some(name) = &kw.arg
                && (positional.iter().any(|p| p == name.as_str())
                    || def.kwonly.contains(name.as_str()))
            {
                bound.push((name.as_str(), &kw.value));
            }
        }
        let caller = &self.modules[m];
        let mut changed = false;
        for (param, arg) in bound {
            if caller.file.taint().classify(call.start(), [arg]) >= Taint::Caller {
                changed |= self.modules[t]
                    .file
                    .taint()
                    .mark_caller_param(&qualname, param);
            }
        }
        changed
    }
}

/// Mark, in every parsed file of the package rooted at `root`, the
/// parameters that receive request data from some call in the package.
pub fn propagate(files: &[(&Path, &ParsedFile)], root: &Path) {
    if files.is_empty() {
        return;
    }
    let package = Package::new(files, root);
    for _ in 0..MAX_ROUNDS {
        let mut changed = false;
        for (m, module) in package.modules.iter().enumerate() {
            for call in &module.uses.calls {
                changed |= package.bind(m, call);
            }
        }
        if !changed {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::ast_checks::check_sql_injection;
    use crate::models::Confidence;

    fn confidences(files: &[(&str, &str)]) -> Vec<(String, usize, Confidence)> {
        let root = Path::new("/pkg");
        let paths: Vec<PathBuf> = files.iter().map(|(p, _)| root.join(p)).collect();
        let parsed: Vec<ParsedFile> = files
            .iter()
            .zip(&paths)
            .map(|((_, src), p)| ParsedFile::parse(src, p).expect("parses"))
            .collect();
        let pairs: Vec<(&Path, &ParsedFile)> =
            paths.iter().map(Path::new).zip(parsed.iter()).collect();
        propagate(&pairs, root);
        let mut out = Vec::new();
        for ((name, src), pf) in files.iter().zip(&parsed) {
            let lines: Vec<String> = src.lines().map(str::to_string).collect();
            for f in check_sql_injection(Path::new(name), name, &lines, Some(pf)) {
                out.push((name.to_string(), f.line, f.confidence));
            }
        }
        out
    }

    #[test]
    fn caller_in_another_file_promotes_the_callee_parameter() {
        let got = confidences(&[
            (
                "app.py",
                "from flask import Flask, request\nimport libuser\nfrom dao import Student\n\
                 app = Flask(__name__)\n@app.route('/login', methods=['POST'])\ndef login():\n\
                 \x20   return libuser.login(request.form['username'], 'fixed')\n\
                 @app.route('/add')\ndef add():\n    Student.create(None, request.args['name'])\n",
            ),
            (
                "libuser.py",
                "def login(username, password):\n\
                 \x20   c.execute(f\"SELECT * FROM users WHERE username = '{username}'\")\n\
                 \x20   c.execute(f\"SELECT * FROM users WHERE password = '{password}'\")\n\
                 def unused(table):\n    c.execute(f'SELECT * FROM {table}')\n",
            ),
            (
                "dao.py",
                "class Student:\n    @staticmethod\n    def create(conn, name):\n\
                 \x20       q = \"INSERT INTO students (name) VALUES ('%s')\" % name\n\
                 \x20       conn.execute(q)\n",
            ),
        ]);
        assert_eq!(
            got,
            vec![
                ("libuser.py".into(), 2, Confidence::High),
                ("libuser.py".into(), 3, Confidence::Medium),
                ("libuser.py".into(), 5, Confidence::Medium),
                ("dao.py".into(), 5, Confidence::High),
            ]
        );
    }

    #[test]
    fn caller_taint_crosses_two_helpers_and_relative_imports() {
        let got = confidences(&[
            ("svc/__init__.py", ""),
            (
                "svc/views.py",
                "from flask import request\nfrom .logic import handle\n@app.route('/x')\n\
                 def view():\n    handle(request.args['q'])\n",
            ),
            (
                "svc/logic.py",
                "from . import db\ndef handle(value):\n    db.run(table=value)\n",
            ),
            (
                "svc/db.py",
                "def run(conn=None, table=''):\n    conn.execute('SELECT * FROM ' + table)\n",
            ),
        ]);
        assert_eq!(got, vec![("svc/db.py".into(), 2, Confidence::High)]);
    }
}
