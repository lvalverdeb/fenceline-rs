# fenceline

Zero-day security scanner **for Python codebases**, implemented in Rust.

This is a from-scratch reimplementation of [`fenceline`](https://github.com/lvalverdeb/fenceline) (the Python original, formerly `tripwire`) — not a wrapper or FFI binding. It parses and scans Python source directly, with no Python runtime dependency, producing a single native binary you can drop into any CI image or pre-commit hook with nothing else installed. Maps every finding to a CWE from the 2025 CWE Top 25, OWASP Top 10:2025, and known Python zero-day exploit patterns; tracks two independent ratings per finding (severity and confidence, the same distinction Bandit makes).

The [Python original](https://github.com/lvalverdeb/fenceline) remains the actively maintained **spec of record**: when the two disagree, the Python behaviour is correct by definition and this is a bug here, not there. See [`RUST_PORT_PROPOSAL.md`](https://github.com/lvalverdeb/fenceline/blob/main/RUST_PORT_PROPOSAL.md) in the Python repo for the full design rationale, phased build history, and every behavioural quirk uncovered and matched along the way (some quite subtle — e.g. `check_assert_security`'s `\b(is|==|!=|in)\b` provably never matching `==`/`!=` written the normal way with spaces or quotes around them).

**Status**: all 58 checks ported (44 AST-based, 12 text-based, 2 manifest-based), plus `# nosec` inline suppression, baselining, and full CLI flag parity with the Python original — 66 tests passing, including a fixture-corpus conformance runner that diffs every check's output against the Python original's expected results field-by-field.

## Why It Exists

See the Python original's own README and `RUST_PORT_PROPOSAL.md` for the full rationale — in short: a native binary removes the Python-interpreter dependency for running the scanner anywhere (CI images, pre-commit hooks, external codebases), and fenceline's checks are simple enough (single-file, single-pass — no cross-file analysis) that a port carries much less risk than a typical static-analysis tool would.

## Install

```bash
cargo install fenceline
```

This installs a binary named `fenceline` (matching the Python CLI's command name and the crate name).

## Usage

```bash
fenceline
fenceline --json > report.json
fenceline -q
fenceline --fail-on critical
fenceline --exclude tests/ examples/
fenceline --config fenceline.toml
fenceline --package my-lib=my-lib/src/my_lib
fenceline --packages my-lib other-lib
```

Exit codes: `0` (no findings at or above `--fail-on`), `1` (one or more).

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `--json` | off | Machine-readable output |
| `--sarif` | off | SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers |
| `--quiet` / `-q` | off | Suppress the banner |
| `--config` | none | TOML file with a `packages` table of `name = "path"` entries; replaces cwd auto-discovery |
| `--package` | none | Add or override one package as `NAME=PATH` (repeatable); applied on top of `--config` |
| `--packages` | all resolved packages | Names to scan from the resolved registry |
| `--exclude` | none | Path substrings to exclude from scanning |
| `--fail-on` | `high` | Severity threshold (`critical`\|`high`\|`medium`\|`low`\|`info`) for the exit code |
| `--confidence-min` | `low` | Drop findings below this confidence (`high`\|`medium`\|`low`) |
| `--baseline PATH` | — | Only report/fail on findings not already present in this baseline |
| `--write-baseline PATH` | — | Snapshot current findings to PATH and exit 0 |
| `--include-tests` | off | Include CWE-798/617/918/770/295 findings inside test code |
| `--test-paths DIRNAME [DIRNAME ...]` | — | Extra directory names to treat as non-production, alongside the built-in `tests`/`test`/`conftest.py` conventions |
| `--version` | — | Print the installed fenceline version and exit |

`--config` uses TOML rather than the Python original's YAML: this crate's dependency list is intentionally minimal, and the PyYAML shadow vulnerability is itself one of the CVE patterns fenceline scans for — adding a YAML dependency here would be ironic. The `toml` crate is already a dependency (used for workspace-root discovery), so this adds nothing new.

```toml
# fenceline.toml
[packages]
my-lib = "my-lib/src/my_lib"
other = "../other/src/other"
```

## Severity vs. confidence

Every finding carries two independent ratings: **severity** is how bad it would be if the finding is real; **confidence** is how sure the check is that it *is* real. A text-based check that can't fully rule out a docstring or string-literal mention is `MEDIUM`/`LOW`; for most AST checks, matching a real call node is all there is to know, and the finding is `HIGH`.

For the injection-shaped checks (command, code, SQL, template and CRLF injection, SSRF, open redirect, path traversal, arbitrary file write, pandas `eval`/`query`), the call's shape is not enough: `subprocess.run(cmd)` is a finding or not depending on where `cmd` came from. These checks trace the sink's arguments back through the enclosing function (`src/taint.rs`, mirroring the Python original's `fenceline.taint`) and set confidence from what they find:

| The sink is fed by | Confidence |
| --- | --- |
| A recognised entry point: a `request` object, `os.environ`, `sys.argv`, `input()`, a socket read, or a parameter of a route-decorated function or handler method | `HIGH` |
| A parameter that some caller elsewhere in the package feeds request data | `HIGH`, with a note on the finding |
| Plain function parameters, `self` fields no method of the class assigns from a source, or values the function cannot resolve | `MEDIUM`, with a note on the finding |
| Only literals, module constants, library references, or values that cannot carry a payload (a length, an `int()`, a `shlex.quote()`) | not reported |

Within a function the analysis follows assignments without regard to order, so it is deliberately pessimistic. The one order-sensitive rule is the guard: after `if x not in ALLOWED: abort(400)` (or `raise`/`return`), inside `if x in ALLOWED:`, after `assert x in ALLOWED`, or after an anchored `re.fullmatch` / `isdigit()`-style check that exits on failure, `x` is clean at the sinks that follow, provided `ALLOWED` is not derived from input and `x` is not reassigned in between. Across functions it follows calls (`src/callers.rs`): once every file of a package is parsed, each call's arguments are bound to the callee's parameters, and a parameter that receives request data from any caller is treated as request data inside the callee, to a fixpoint. Callees are resolved by name (same file, `import mod`, `from .mod import f`, `Class.method`, `self.method`); a method on an object of unknown type still lands in the `MEDIUM` row. A `self` field takes the worst taint of every value any method of the class assigns to it, each resolved in that method; a field nothing in the class assigns stays `MEDIUM`. Use `--confidence-min medium` to cut noise from the fuzzier regex checks, and `--confidence-min high` to see only findings where attacker-controlled input provably reaches the sink.

## Severity policy

A `[tool.fenceline.severity]` table in the nearest `pyproject.toml` (searched upward from the directory fenceline runs in) caps a check's severity by check function name, same as the Python original:

```toml
[tool.fenceline.severity]
check_crlf = "medium"      # we build HTTP framing by hand; CRLF here is by design
check_ssrf = "low"         # outbound URLs come from our own config, never a request
```

A cap never raises: an INFO finding from a capped check stays INFO. This keeps `--fail-on high` meaningful without `# nosec`-ing every occurrence or dropping the check, and the policy is a reviewable file in the repository. A misspelled check name or level is an error (exit 2), not a silently inert line.

## Files that could not be parsed

A Python file that fails to parse still gets the line-regex checks, but none of the AST checks. The report says so rather than passing the file off as clean: the text report prints a `could not be parsed` line, and the JSON payload carries a `skipped_files` list.

## Dependency CVEs and lockfiles

`check_dependency_cve` compares the version a project will actually install against the same `vuln_deps.json` table the Python original ships (a curated zero-day watchlist, not an advisory-database mirror; run `pip-audit` for full CVE coverage). When a lockfile (`uv.lock`, `poetry.lock`, `Pipfile.lock`) sits next to the manifest, the lockfile's exact versions are checked and the manifest's ranges are ignored, with the finding reported on the lockfile line. Without a lockfile, an `==` pin below the fixed version is HIGH confidence and a lower bound (`>=`, `~=`) below it is MEDIUM. Version comparison follows PEP 440.

## Inline suppression

Same convention as the Python original (Bandit-compatible) — `# nosec` on the offending line suppresses everything found there, or scope it to specific CWEs:

```python
pickle.loads(data)  # nosec CWE-502 -- trusted internal cache, not user input
```

## Baselining an existing codebase

```bash
fenceline --write-baseline fenceline-baseline.json   # snapshot today's findings
fenceline --baseline fenceline-baseline.json          # only new findings fail CI
```

### How it compares

The Python repository's `benchmark/` directory holds a labelled comparison
against Bandit and Semgrep on three intentionally vulnerable apps; this port
produces the identical 139 findings there, so its numbers are the same. Run
it against the binary with
`FENCELINE_CMD=target/release/fenceline ../fenceline/benchmark/run.sh`.

### CI integration

`--sarif` writes the scan as a SARIF 2.1.0 log (one rule per CWE with a MITRE
`helpUri` and a GitHub `security-severity`, one result per finding, unparseable
files as tool notifications), ready for GitHub's `upload-sarif` action or any
SARIF viewer. The repository also ships a `.pre-commit-hooks.yaml`, so

```yaml
repos:
  - repo: https://github.com/lvalverdeb/fenceline-rs
    rev: v1.7.0
    hooks:
      - id: fenceline
```

builds the binary with cargo and scans the working tree whenever a Python
file is staged.

## Design

- `taint` — per-function source tracking for the injection-shaped checks (mirrors `fenceline/taint.py`).
- `callers` — the package-wide pass that marks parameters fed request data by their callers (mirrors `fenceline/callers.py`).
- `models` — the `Finding` struct, plus `Severity`/`Confidence` enums whose declared variant order matches the Python `SEVERITY_ORDER`/`CONFIDENCE_ORDER` dicts exactly (so a derived `Ord` sorts the same way).
- `config` — workspace-root discovery (walks upward for a `pyproject.toml` declaring `[tool.uv.workspace]`), the default package registry, and `is_secure_path` (a from-scratch reimplementation of the Python original's `boti.core.is_secure_path` sandbox check — see the module docs for one disclosed divergence: `std::fs::canonicalize` requires the target to exist, unlike Python's `Path.resolve()`).
- `ast_helpers` — shared AST/text-matching helpers used across checks.
- `scanner` — file discovery (`.py` files under a package root, sorted, with fenceline's own pattern-table files excluded from self-scan), file reading, and AST parsing — all tolerant of unreadable/malformed files, matching the Python original's "never crash the whole scan over one bad file" design.
- `checks` — the built-in check registry: `checks::ast_checks` (walk the parsed AST — won't false-positive on a call mentioned in a docstring or string literal), `checks::text_checks` (line-regex checks for surface-syntax patterns, run over `scanner::mask_non_code`'s view of the file -- comments and docstrings blanked out, columns preserved -- so they too can't false-positive on prose; Trojan Source alone scans raw lines), `checks::manifest_checks` (dependency-manifest CVE/unbounded-pin checks, over `pyproject.toml`/`requirements.txt` etc., not Python source).
- `suppression` — `# nosec` inline-suppression parsing.
- `baseline` — baseline snapshot/diff for adopting fenceline on an existing codebase.
- `reporting` — text and JSON report rendering. JSON field order is guaranteed by struct-field declaration order (not a `serde_json::Value::Object`, whose map-ordering would need an explicit feature flag to avoid alphabetical sorting).
- `cli` — argument parsing and the scan loop.

**Not ported, and not planned**: the Python original's third-party plugin architecture (`fenceline.checks` entry-point discovery for external check functions). A Rust equivalent would need dynamic loading of compiled code (`dlopen`-style), which trades away the single-static-binary property that's the whole point of this port — see `RUST_PORT_PROPOSAL.md` §7.8 in the Python repo for the full reasoning.

## Development

```bash
cargo build --release
cargo test
cargo clippy --all-targets
cargo fmt --check
```

## License

MIT
