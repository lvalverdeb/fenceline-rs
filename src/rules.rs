//! Declarative rules -- mirrors `fenceline/rules.py`. `[[rule]]` tables in
//! a TOML file, loaded from `--rules PATH` (repeatable) and from the
//! `--config` file, run on every scanned file after the built-in checks.
//! The format is specified once, in the Python repository's
//! `docs/rules.md`; both ports run the same `fixtures/rules/` cases.
//!
//! Four kinds: `sink` (the callee matches and the selected arguments feed
//! the taint engine, which sets confidence as for the built-ins), `call`
//! (the callee matches; fixed confidence), `keyword` (the callee matches and
//! a named keyword has a literal value, lacks one, or is missing) and
//! `pattern` (a regex over the comment- and docstring-masked lines, with
//! the text checks' full-line-comment skip).
//!
//! A rule file is checked strictly: an unknown key, a misspelled kind or a
//! severity outside the five levels is an error, not a silently inert line
//! in a security policy.

use crate::analysis::ParsedFile;
use crate::ast_helpers::{
    dotted_matches, full_attr, resolve_dotted, skip, walk_arguments_children,
    walk_comprehension_children, walk_keyword_children, walk_withitem_children,
};
use crate::models::{Confidence, Finding, Severity};
use crate::taint::confidence_for;
use regex::Regex;
use rustpython_ast::{
    Arguments, Comprehension, Constant, Expr, ExprCall, Keyword, Ranged, Visitor, WithItem,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

const KINDS: [&str; 4] = ["sink", "call", "keyword", "pattern"];
const COMMON: [&str; 6] = ["id", "cwe", "name", "severity", "description", "kind"];
const DATA_MSG: &str =
    "'data' must be \"all\", \"first\" or an array of argument positions and keyword names";
/// Lookaround and backreferences: Python's `re` has them, this crate's
/// `regex` does not, so a rule using them is refused in both ports with the
/// same message rather than loading in one and failing in the other.
static UNPORTABLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\(\?<?[=!]|\\[1-9]|\(\?P=").unwrap());

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Bool(bool),
    Int(i64),
    Str(String),
}

#[derive(Debug, Clone)]
pub enum KeywordTest {
    /// The keyword is present with exactly this literal.
    Value(Literal),
    /// The keyword is missing or anything but this literal.
    Unless(Literal),
    /// The keyword is missing.
    Required,
}

#[derive(Debug, Clone)]
pub enum Selector {
    Arg(usize),
    Kw(String),
}

#[derive(Debug, Clone)]
pub enum Data {
    All,
    First,
    Select(Vec<Selector>),
}

#[derive(Debug, Clone)]
pub enum Kind {
    Sink { data: Data },
    Call,
    Keyword { keyword: String, test: KeywordTest },
    Pattern { regex: Regex },
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub cwe: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub description: String,
    /// Fixed confidence for `call`/`keyword`/`pattern`; `sink` rules take
    /// theirs from the taint engine.
    pub confidence: Confidence,
    pub callee: Vec<String>,
    pub kind: Kind,
}

/// `Finding` carries `&'static str` for the CWE id and name (every built-in
/// has literals there). A rule set is loaded once per process and is small,
/// so its strings are leaked into the static lifetime rather than widening
/// `Finding` for the one dynamic producer.
fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn allowed_keys(kind: &str) -> Vec<&'static str> {
    let mut keys = COMMON.to_vec();
    keys.extend(match kind {
        "sink" => vec!["callee", "data"],
        "call" => vec!["callee", "confidence"],
        "keyword" => vec![
            "callee",
            "confidence",
            "keyword",
            "value",
            "unless",
            "required",
        ],
        _ => vec!["confidence", "regex"],
    });
    keys
}

/// Every rule from the `--config` file's `[[rule]]` tables (if any) and
/// from each `--rules` file, in that order; ids must be unique over the set.
pub fn load_rule_set(config: Option<&Path>, paths: &[PathBuf]) -> Result<Vec<Rule>, String> {
    let mut rules = Vec::new();
    if let Some(config) = config {
        rules.extend(rules_from_table(
            &read_toml(config, "--config")?,
            &config.display().to_string(),
        )?);
    }
    for path in paths {
        let loaded = rules_from_table(&read_toml(path, "--rules")?, &path.display().to_string())?;
        if loaded.is_empty() {
            return Err(format!("{}: no [[rule]] tables", path.display()));
        }
        rules.extend(loaded);
    }
    let mut seen = HashSet::new();
    for rule in &rules {
        if !seen.insert(rule.id.as_str()) {
            return Err(format!("rule {:?} is defined twice", rule.id));
        }
    }
    Ok(rules)
}

fn read_toml(path: &Path, flag: &str) -> Result<toml::Table, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {flag} {}: {e}", path.display()))?;
    text.parse::<toml::Table>()
        .map_err(|e| format!("could not parse {flag} {}: {e}", path.display()))
}

pub fn rules_from_table(raw: &toml::Table, source: &str) -> Result<Vec<Rule>, String> {
    let Some(entries) = raw.get("rule") else {
        return Ok(Vec::new());
    };
    let entries = entries
        .as_array()
        .filter(|a| a.iter().all(toml::Value::is_table))
        .ok_or_else(|| format!("{source}: 'rule' must be an array of tables ([[rule]])"))?;
    entries
        .iter()
        .enumerate()
        .map(|(i, e)| parse_rule(e.as_table().expect("checked above"), i + 1, source))
        .collect()
}

fn literal(value: &toml::Value) -> Option<Literal> {
    match value {
        toml::Value::Boolean(b) => Some(Literal::Bool(*b)),
        toml::Value::Integer(i) => Some(Literal::Int(*i)),
        toml::Value::String(s) => Some(Literal::Str(s.clone())),
        _ => None,
    }
}

fn parse_rule(entry: &toml::Table, index: usize, source: &str) -> Result<Rule, String> {
    let location = match entry.get("id").and_then(toml::Value::as_str) {
        Some(id) => format!("{source}: rule {id:?}"),
        None => format!("{source}: rule {index}"),
    };
    let fail = |msg: String| format!("{location}: {msg}");
    let text = |key: &str| -> Result<String, String> {
        entry
            .get(key)
            .and_then(toml::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| fail(format!("'{key}' must be a non-empty string")))
    };

    let kind_name = text("kind")?;
    if !KINDS.contains(&kind_name.as_str()) {
        return Err(fail(format!(
            "kind {kind_name:?} is not one of {}",
            KINDS.join(", ")
        )));
    }
    let allowed = allowed_keys(&kind_name);
    let mut unknown: Vec<&str> = entry
        .keys()
        .map(String::as_str)
        .filter(|k| !allowed.contains(k))
        .collect();
    unknown.sort_unstable();
    if !unknown.is_empty() {
        return Err(fail(format!(
            "unknown key(s) for a {kind_name} rule: {}",
            unknown.join(", ")
        )));
    }
    let id = text("id")?;
    let cwe = text("cwe")?;
    let name = text("name")?;
    let description = text("description")?;
    if !(cwe.len() > 4 && cwe.starts_with("CWE-") && cwe[4..].bytes().all(|b| b.is_ascii_digit())) {
        return Err(fail(format!("cwe {cwe:?} must look like CWE-123")));
    }
    let severity = Severity::parse(&text("severity")?).ok_or_else(|| {
        fail("severity must be one of critical, high, medium, low, info".to_string())
    })?;
    let mut confidence = if kind_name == "pattern" {
        Confidence::Medium
    } else {
        Confidence::High
    };
    if entry.contains_key("confidence") {
        confidence = Confidence::parse(&text("confidence")?)
            .ok_or_else(|| fail("confidence must be one of high, medium, low".to_string()))?;
    }

    let mut callee = Vec::new();
    if kind_name != "pattern" {
        callee = entry
            .get("callee")
            .and_then(toml::Value::as_array)
            .filter(|a| !a.is_empty())
            .and_then(|a| {
                a.iter()
                    .map(|c| c.as_str().filter(|s| !s.is_empty()).map(str::to_string))
                    .collect::<Option<Vec<String>>>()
            })
            .ok_or_else(|| {
                fail("'callee' must be a non-empty array of dotted names".to_string())
            })?;
    }

    let kind = match kind_name.as_str() {
        "sink" => {
            let data = match entry.get("data") {
                None => Data::All,
                Some(v) if v.as_str() == Some("all") => Data::All,
                Some(v) if v.as_str() == Some("first") => Data::First,
                Some(toml::Value::Array(items)) if !items.is_empty() => {
                    let selectors = items
                        .iter()
                        .map(|s| match s {
                            toml::Value::Integer(i) if *i >= 0 => Some(Selector::Arg(*i as usize)),
                            toml::Value::String(k) if !k.is_empty() => {
                                Some(Selector::Kw(k.clone()))
                            }
                            _ => None,
                        })
                        .collect::<Option<Vec<Selector>>>()
                        .ok_or_else(|| fail(DATA_MSG.to_string()))?;
                    Data::Select(selectors)
                }
                _ => return Err(fail(DATA_MSG.to_string())),
            };
            Kind::Sink { data }
        }
        "call" => Kind::Call,
        "keyword" => {
            let keyword = text("keyword")?;
            let tests: Vec<&str> = ["value", "unless", "required"]
                .into_iter()
                .filter(|k| entry.contains_key(*k))
                .collect();
            if tests.len() != 1 {
                return Err(fail(
                    "exactly one of 'value', 'unless' or 'required = true' is needed".to_string(),
                ));
            }
            let test = match tests[0] {
                "required" => {
                    if entry.get("required") != Some(&toml::Value::Boolean(true)) {
                        return Err(fail("'required' can only be true".to_string()));
                    }
                    KeywordTest::Required
                }
                which => {
                    let lit = literal(&entry[which]).ok_or_else(|| {
                        fail(format!(
                            "'{which}' must be a boolean, an integer or a string"
                        ))
                    })?;
                    if which == "value" {
                        KeywordTest::Value(lit)
                    } else {
                        KeywordTest::Unless(lit)
                    }
                }
            };
            Kind::Keyword { keyword, test }
        }
        _ => {
            let source_re = text("regex")?;
            if UNPORTABLE.is_match(&source_re) {
                return Err(fail(
                    "regex uses lookaround or a backreference, which the Rust port cannot run"
                        .to_string(),
                ));
            }
            let regex =
                Regex::new(&source_re).map_err(|e| fail(format!("regex does not compile: {e}")))?;
            Kind::Pattern { regex }
        }
    };

    Ok(Rule {
        id,
        cwe: leak(cwe),
        name: leak(name),
        severity,
        description,
        confidence,
        callee,
        kind,
    })
}

/// Every `Call` in the module, in visit order -- the same universe as the
/// Python port's `_calls()` (an `ast.walk`), class bodies, decorators,
/// defaults and lambdas included. Clones the body once per file, and only
/// when a call-kind rule is loaded.
struct CallCollector {
    calls: Vec<ExprCall>,
}

impl Visitor for CallCollector {
    fn visit_expr_call(&mut self, node: ExprCall) {
        self.calls.push(node.clone());
        self.generic_visit_expr_call(node);
    }

    // rustpython-ast 0.4.0's generated `generic_visit_*` for these four
    // node kinds are no-op stubs (see `ast_helpers`): without these, a call
    // in a keyword value, a `with` item, a default or a comprehension would
    // never be reached.
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

fn code_at(lines: &[String], line: usize) -> String {
    if line >= 1 && line <= lines.len() {
        lines[line - 1].trim().to_string()
    } else {
        String::new()
    }
}

/// Findings of `rules` on one file. `lines` is the raw view (snippets for
/// the call kinds), `code_lines` the masked view the pattern kind scans,
/// as the text checks do.
pub fn run_rules(
    rules: &[Rule],
    pk: &str,
    lines: &[String],
    code_lines: &[String],
    tree: Option<&ParsedFile>,
) -> Vec<Finding> {
    let mut results = Vec::new();
    if rules.is_empty() {
        return results;
    }
    let call_rules: Vec<&Rule> = rules
        .iter()
        .filter(|r| !matches!(r.kind, Kind::Pattern { .. }))
        .collect();
    if let Some(tree) = tree
        && !call_rules.is_empty()
    {
        let mut collector = CallCollector { calls: Vec::new() };
        for stmt in tree.module.body.clone() {
            collector.visit_stmt(stmt);
        }
        let aliases = &tree.collected().aliases;
        for call in &collector.calls {
            let func = resolve_dotted(&full_attr(&call.func), aliases);
            for rule in &call_rules {
                if !rule.callee.iter().any(|c| dotted_matches(&func, c)) {
                    continue;
                }
                let Some((confidence, note)) = match_call(rule, tree, call) else {
                    continue;
                };
                let line = tree.line_index().line_number(call.start());
                results.push(Finding {
                    cwe_id: rule.cwe,
                    cwe_name: rule.name,
                    severity: rule.severity,
                    package: String::new(),
                    file: pk.to_string(),
                    line,
                    code_snippet: code_at(lines, line),
                    description: format!("{}{note}", rule.description),
                    zero_day_relevance: "",
                    confidence,
                });
            }
        }
    }
    for rule in rules {
        let Kind::Pattern { regex } = &rule.kind else {
            continue;
        };
        for (i, line) in code_lines.iter().enumerate() {
            if skip(line) || !regex.is_match(line) {
                continue;
            }
            results.push(Finding {
                cwe_id: rule.cwe,
                cwe_name: rule.name,
                severity: rule.severity,
                package: String::new(),
                file: pk.to_string(),
                line: i + 1,
                code_snippet: line.trim().to_string(),
                description: rule.description.clone(),
                zero_day_relevance: "",
                confidence: rule.confidence,
            });
        }
    }
    results
}

/// `(confidence, description suffix)` when `rule` reports `call`.
fn match_call(
    rule: &Rule,
    tree: &ParsedFile,
    call: &ExprCall,
) -> Option<(Confidence, &'static str)> {
    match &rule.kind {
        Kind::Sink { data } => {
            let exprs = selected_data(data, call);
            confidence_for(tree.taint().classify(call.start(), exprs))
        }
        Kind::Call => Some((rule.confidence, "")),
        Kind::Keyword { keyword, test } => {
            let found = call
                .keywords
                .iter()
                .find(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == keyword));
            let hit = match test {
                KeywordTest::Required => found.is_none(),
                KeywordTest::Value(lit) => found.is_some_and(|kw| literal_equals(&kw.value, lit)),
                KeywordTest::Unless(lit) => !found.is_some_and(|kw| literal_equals(&kw.value, lit)),
            };
            hit.then_some((rule.confidence, ""))
        }
        Kind::Pattern { .. } => None,
    }
}

fn selected_data<'c>(data: &Data, call: &'c ExprCall) -> Vec<&'c Expr> {
    match data {
        Data::All => call
            .args
            .iter()
            .chain(call.keywords.iter().map(|kw| &kw.value))
            .collect(),
        Data::First => call.args.iter().take(1).collect(),
        Data::Select(selectors) => {
            let mut exprs = Vec::new();
            for selector in selectors {
                match selector {
                    Selector::Arg(i) => {
                        if let Some(e) = call.args.get(*i) {
                            exprs.push(e);
                        }
                    }
                    Selector::Kw(name) => exprs.extend(
                        call.keywords
                            .iter()
                            .filter(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == name))
                            .map(|kw| &kw.value),
                    ),
                }
            }
            exprs
        }
    }
}

/// `expr` is the constant `literal`, with `True`/`1` kept apart as Python
/// does for `is`: a rule saying `value = true` means the keyword `True`.
fn literal_equals(expr: &Expr, literal: &Literal) -> bool {
    let Expr::Constant(c) = expr else {
        return false;
    };
    match (&c.value, literal) {
        (Constant::Bool(a), Literal::Bool(b)) => a == b,
        (Constant::Int(a), Literal::Int(b)) => a.to_string() == b.to_string(),
        (Constant::Str(a), Literal::Str(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[[rule]]
id = "t/mktemp"
cwe = "CWE-377"
name = "Insecure Temporary File"
severity = "high"
description = "mktemp() names a file without creating it."
kind = "call"
callee = ["tempfile.mktemp"]
"#;

    fn load(text: &str) -> Result<Vec<Rule>, String> {
        let table: toml::Table = text.parse().unwrap();
        rules_from_table(&table, "rules.toml")
    }

    #[test]
    fn good_rule_loads_with_defaults() {
        let rules = load(GOOD).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].severity, Severity::High);
        assert_eq!(rules[0].confidence, Confidence::High);
        assert_eq!(rules[0].callee, vec!["tempfile.mktemp".to_string()]);
    }

    #[test]
    fn pattern_rule_defaults_to_medium_confidence() {
        let text = GOOD.replace(
            "kind = \"call\"\ncallee = [\"tempfile.mktemp\"]",
            "kind = \"pattern\"\nregex = \"mktemp\"",
        );
        let rules = load(&text).unwrap();
        assert_eq!(rules[0].confidence, Confidence::Medium);
        assert!(matches!(rules[0].kind, Kind::Pattern { .. }));
    }

    #[test]
    fn malformed_rules_are_errors_naming_the_rule() {
        let cases: [(&str, &str, &str); 12] = [
            (
                "kind = \"call\"",
                "kind = \"cal\"",
                "kind \"cal\" is not one of",
            ),
            (
                "kind = \"call\"",
                "kind = \"call\"\nregex = \"x\"",
                "unknown key(s) for a call rule: regex",
            ),
            (
                "severity = \"high\"",
                "severity = \"urgent\"",
                "severity must be one of",
            ),
            (
                "cwe = \"CWE-377\"",
                "cwe = \"377\"",
                "must look like CWE-123",
            ),
            (
                "callee = [\"tempfile.mktemp\"]",
                "callee = []",
                "'callee' must be a non-empty array",
            ),
            (
                "kind = \"call\"",
                "kind = \"sink\"\nconfidence = \"low\"",
                "unknown key(s) for a sink rule: confidence",
            ),
            (
                "kind = \"call\"",
                "kind = \"sink\"\ndata = \"second\"",
                "'data' must be",
            ),
            (
                "kind = \"call\"",
                "kind = \"keyword\"\nkeyword = \"verify\"",
                "exactly one of 'value', 'unless' or 'required = true'",
            ),
            (
                "kind = \"call\"",
                "kind = \"keyword\"\nkeyword = \"verify\"\nvalue = 1.5",
                "'value' must be a boolean, an integer or a string",
            ),
            (
                "kind = \"call\"",
                "kind = \"keyword\"\nkeyword = \"verify\"\nrequired = false",
                "'required' can only be true",
            ),
            (
                "kind = \"call\"\ncallee = [\"tempfile.mktemp\"]",
                "kind = \"pattern\"\nregex = \"(?=x)mktemp\"",
                "lookaround or a backreference",
            ),
            (
                "kind = \"call\"\ncallee = [\"tempfile.mktemp\"]",
                "kind = \"pattern\"\nregex = \"mktemp(\"",
                "regex does not compile",
            ),
        ];
        for (old, new, message) in cases {
            let err = load(&GOOD.replace(old, new)).unwrap_err();
            assert!(err.contains(message), "{err}");
            assert!(err.contains("rule \"t/mktemp\""), "{err}");
        }
    }

    #[test]
    fn duplicate_ids_and_empty_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.toml");
        let b = dir.path().join("b.toml");
        std::fs::write(&a, GOOD).unwrap();
        std::fs::write(&b, GOOD).unwrap();
        let err = load_rule_set(None, &[a.clone(), b]).unwrap_err();
        assert!(err.contains("defined twice"), "{err}");
        let empty = dir.path().join("empty.toml");
        std::fs::write(&empty, "title = \"nothing\"\n").unwrap();
        let err = load_rule_set(None, &[empty]).unwrap_err();
        assert!(err.contains("no [[rule]] tables"), "{err}");
        let config = dir.path().join("fenceline.toml");
        std::fs::write(&config, "[packages]\napp = \"app\"\n").unwrap();
        assert!(load_rule_set(Some(&config), &[]).unwrap().is_empty());
        std::fs::write(&config, format!("[packages]\napp = \"app\"\n{GOOD}")).unwrap();
        assert_eq!(
            load_rule_set(Some(&config), &[a]).unwrap_err(),
            "rule \"t/mktemp\" is defined twice"
        );
    }
}
