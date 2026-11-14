# fenceline

Zero-day security scanner for Python codebases, implemented in Rust. One
native binary — `cargo install fenceline && fenceline` scans whatever's under
the current directory, no Python runtime and no project-specific setup
required.

The aim is to be the one scanner a Python project runs instead of Bandit and
Semgrep's Python rules: Bandit's breadth of checks, with the taint analysis
that lets a tool say *this* `execute()` matters and that one does not, in a
single install with nothing to host and no rule language to learn. It is not
there on every axis yet; [How it compares](#how-it-compares) says where it
stands and what is still missing.

This is a from-scratch reimplementation of [`fenceline`](https://github.com/lvalverdeb/fenceline)
(the Python original) — not a wrapper or FFI binding. It parses and scans
Python source directly, producing a single native binary you can drop into
any CI image or pre-commit hook with nothing else installed. The Python
original remains the actively maintained **spec of record**: when the two
disagree, the Python behaviour is correct by definition and this is a bug
here, not there. See [`RUST_PORT_PROPOSAL.md`](https://github.com/lvalverdeb/fenceline/blob/main/RUST_PORT_PROPOSAL.md)
in the Python repo for the design rationale, phased build history, and every
behavioural quirk uncovered and matched along the way.

Maps every finding to a CWE from the 2025 CWE Top 25, OWASP Top 10:2025, and known
Python zero-day exploit patterns (pickle bypass CVE-2026-56315, PyYAML shadow
vulnerability CVE-2026-24009, LangChain SSTI CVE-2025-68664, dependency confusion
CVE-2025-61774, and more — see the CWE reference printed at the end of every
text-mode report). 58 checks total: 44 walk the parsed AST; the rest are line-regex
checks for surface-syntax patterns that don't need full parsing. Neither kind
false-positives on a dangerous call quoted in a docstring or comment: the regex
checks scan a copy of each file with comments and string-only statements blanked
out (columns preserved), so only real code is matched.

**Status**: all 58 checks ported, plus `# nosec` inline suppression,
baselining, severity policy, SARIF and full CLI flag parity with the Python
original — 67 tests passing, including a fixture-corpus conformance runner
that diffs every check's output against the Python original's expected
results field-by-field. On the benchmark apps and on a reference corpus of
real libraries the two ports produce identical findings, description for
description.

## Installation

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
| `--sarif` | off | SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers (see "CI integration" below) |
| `--quiet` / `-q` | off | Suppress the banner |
| `--config` | none | TOML file with a `packages` table of `name = "path"` entries (see below); replaces cwd auto-discovery |
| `--package` | none | Add or override one package as `NAME=PATH` (repeatable); applied on top of `--config` |
| `--packages` | all resolved packages | Names to scan from the resolved registry |
| `--exclude` | none | Path substrings to exclude from scanning |
| `--fail-on` | `high` | Severity threshold (`critical`\|`high`\|`medium`\|`low`\|`info`) for the exit code |
| `--confidence-min` | `low` | Drop findings below this confidence (`high`\|`medium`\|`low`) |
| `--baseline PATH` | — | Only report/fail on findings not already present in this baseline |
| `--write-baseline PATH` | — | Snapshot current findings to PATH and exit 0 |
| `--include-tests` | off | Include CWE-798/617/918/770/295 findings inside test code (see "Test code" below) |
| `--test-paths DIRNAME [DIRNAME ...]` | — | Extra directory names to treat as non-production, alongside the built-in `tests`/`test`/`conftest.py` conventions (see "Test code" below) |
| `--version` | — | Print the installed fenceline version and exit |

### Test code

By default, findings for CWE-798 (hardcoded credentials), CWE-617 (reachable
assert), CWE-918 (SSRF), CWE-770 (unbounded resource allocation), and CWE-295
(disabled TLS verification) are suppressed when they occur in a
`tests/`/`test/` directory, a `test_*.py`/`*_test.py` file, or `conftest.py`
— an ephemeral `testcontainers` password, a `pytest` assertion, a hardcoded
localhost test URL, a small committed fixture read, or `CERT_NONE` against a
self-signed local test server isn't the same risk as the identical pattern in
a production request handler, and scoring them identically drowns out real
findings in the same category. Pass `--include-tests` to see them
anyway. Production code paths are unaffected either way. This is a
naming-convention heuristic only — a codebase-specific directory like an
`evaluation/` benchmark harness isn't recognized by name alone, since that
name means different things in different codebases. Declare your own such
directories explicitly with `--test-paths`, e.g. `--test-paths evaluation
benchmarks` — they're unioned with the built-in conventions above.

### What gets scanned by default

A bare `fenceline` invocation (no `--config`/`--package`) auto-discovers packages from
the current directory: every immediate subdirectory containing at least one
`.py` file anywhere in its subtree becomes its own named package, skipping
noise directories (`.venv`, `.git`, `__pycache__`, `node_modules`, `build`,
`dist`, `*.egg-info`, and similar caches — also excluded *within* a scanned
subtree, not just at the top level). Loose `.py` files sitting directly in
the current directory (outside any subdirectory) are scanned too, grouped
into a package named after the directory itself.

To point it at other packages — in this workspace, another workspace, or
any directory on disk — use `--config` and/or `--package`:

1. No `--config`/`--package` → cwd auto-discovery, as above.
2. `--config` given → its `packages` table is used as the full set,
   explicitly rather than auto-discovered.
3. `--package NAME=PATH` entries are then overlaid on top of whichever set
   (1) or (2) produced — adding new names or overriding ones already
   defined, so a config file plus a quick ad-hoc addition both work
   together.

Use `--packages NAME [NAME ...]` afterwards to narrow down to a subset of
whichever registry was resolved. Use `--exclude SUBSTR [SUBSTR ...]` to skip
additional path substrings on top of the built-in noise-directory list.

#### `--config`: TOML file

```toml
# fenceline.toml
[packages]
my-lib = "my-lib/src/my_lib"
other = "../other/src/other"
```

```bash
fenceline --config fenceline.toml
```

TOML rather than YAML deliberately, in both ports: the PyYAML shadow
vulnerability (CVE-2026-24009, mentioned above) is itself one of the patterns
fenceline scans for, and adding a YAML dependency to a tool that flags
YAML-library CVEs would be ironic. The `toml` crate is already a dependency
here (used for workspace-root discovery), so this adds nothing new. Paths
resolve relative to the config file, and every resolved path passes the same
path-security sandbox check `--package` entries get.

### CI integration

`--sarif` writes the scan as a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
log: one rule per CWE (with a `helpUri` into the MITRE CWE database and a
`security-severity` so GitHub labels alerts critical/high/medium/low), one
result per finding, and any file that could not be parsed as a tool
notification. Upload it with GitHub's `upload-sarif` action and findings
appear as code scanning alerts, with GitHub tracking which are new on a pull
request:

```yaml
- run: cargo install fenceline && fenceline --sarif -q > fenceline.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: fenceline.sarif
```

The `|| true` keeps the upload step reachable; `--fail-on` still decides the
exit code if you want the scan step itself to gate.

As a [pre-commit](https://pre-commit.com) hook, fenceline builds the binary
with cargo and scans the working tree whenever a Python file is staged:

```yaml
repos:
  - repo: https://github.com/lvalverdeb/fenceline-rs
    rev: v1.8.0
    hooks:
      - id: fenceline
        # args: [--fail-on, critical, --baseline, fenceline-baseline.json]
```

### How it compares

The Python repository's `benchmark/` directory holds a labelled, reproducible
comparison against Bandit and Semgrep on three intentionally vulnerable apps
(pygoat, vulpy, dvpwa), with every finding of all three tools adjudicated by
hand. At 1.6.0 fenceline sat between the two (76% precision, 53% recall
against Bandit's 90% / 82%); the gap was three checks, and closing them put
the current main at 92% precision and 94% recall, against Bandit's 90% / 77%
and Semgrep's 99% / 32% on the same ground truth, and 97% precision at
`--confidence-min high`. This port produces the identical 219 findings there,
so its numbers are the same; run it against the binary with
`FENCELINE_CMD=target/release/fenceline ../fenceline/benchmark/run.sh`. The
numbers, the labelling rules and `run.sh` are in the Python repository's
[`benchmark/README.md`](https://github.com/lvalverdeb/fenceline/blob/main/benchmark/README.md).

So on those apps fenceline finds more than Bandit with fewer false
positives, and at `--confidence-min high` it finds twice what Semgrep's
community rules do at nearly the same precision. What still separates it
from a full replacement, in the order we intend to close it:

- The false-positive rate on ordinary, non-vulnerable code is not measured
  yet. The benchmark apps are built to be vulnerable, so they test recall
  far better than noise. A library corpus (aiohttp, botocore, tornado,
  PyYAML) is scanned for regressions and audited by hand, but it has no
  ground truth.
- Three apps is a small benchmark, and the cross-file analysis has had only
  a handful of findings to prove itself on. A Django or FastAPI project with
  a service layer is the next addition.
- Calls are resolved by name (`import`, `from .mod import f`,
  `Class.method`, `self.method`). A method on an object whose type fenceline
  cannot see ends the trace at MEDIUM. There is no type inference.
- The 58 checks are fixed. The Python original has a plugin API for your
  own checks; this port has none (see Design), and neither has a declarative
  rule format like Semgrep's.
- `check_dependency_cve` is a curated watchlist, not an advisory database;
  keep `pip-audit` for that.

### Severity vs. confidence

Every finding carries two independent ratings, the same distinction Bandit
makes: **severity** is how bad it would be if the finding is real; **confidence**
is how sure the check is that it *is* real. A line-regex check that can't fully
rule out a docstring or string-literal mention is `MEDIUM`; a handful of
inherently heuristic checks (timing-attack keyword proximity, ReDoS
backtracking-risk judgment, `debug=True` pattern matching) are `LOW`. For most
AST checks, matching a real `Call` node is all there is to know, and the
finding is `HIGH`.

For the injection-shaped checks (command, code, SQL, template and CRLF
injection, SSRF, open redirect, path traversal, arbitrary file write, pandas
`eval`/`query`), knowing the shape of the call is not enough: `subprocess.run(cmd)` is a
finding or not depending on where `cmd` came from. These checks trace the
sink's arguments back through the enclosing function (`src/taint.rs`,
mirroring the Python original's `fenceline.taint`) and set confidence from
what they find:

| The sink is fed by | Confidence |
| --- | --- |
| A recognised entry point: the `request` of a handler or of a module that imports a web framework, `os.environ`, `sys.argv`, `input()`, a socket read, or a parameter of a route-decorated function or handler method | `HIGH` |
| A parameter that some caller elsewhere in the package feeds request data | `HIGH`, with a note on the finding |
| Plain function parameters, `self` fields no method of the class assigns from a source, or values the function cannot resolve | `MEDIUM`, with a note on the finding |
| Only literals, module constants, library references, or values that cannot carry a payload (a length, an `int()`, a `shlex.quote()`) | not reported |

Within a function the analysis follows assignments without regard to order,
so it is deliberately pessimistic: a name assigned a constant and later a
request value counts as a request value. The one order-sensitive rule is the
guard: after `if x not in ALLOWED: abort(400)` (or `raise`, `return`),
inside `if x in ALLOWED:`, after `assert x in ALLOWED`, or after an anchored
`re.fullmatch` / `isdigit()`-style check that exits on failure, `x` is clean
at the sinks that follow, provided `ALLOWED` is something the function did
not derive from input and `x` is not reassigned in between. Across
functions it follows calls (`src/callers.rs`):
once every file of a package is parsed, each call's arguments are bound to
the callee's parameters, and a parameter that receives request data from
any caller is treated as request data inside the callee, repeated until a
value that crosses several helpers has arrived. Callees are resolved by
name (same file, `import mod`, `from .mod import f`, `Class.method`,
`self.method`); a method called on an object of unknown type still lands in
the `MEDIUM` row. A `self` field takes the worst taint of every value any
method of the class assigns to it, each resolved in that method, so a URL
stored by `__init__` or a handler and used elsewhere carries its origin; a
field nothing in the class assigns stays `MEDIUM`. The name `request` counts
as web input only inside a handler or in a module that imports a web
framework (Flask, Django, aiohttp, Starlette, FastAPI and the like) anywhere,
even lazily; in a client library that builds outbound requests, or after
`from urllib import request`, it resolves like any other name. Use
`--confidence-min medium` to cut noise from the fuzzier regex checks, and
`--confidence-min high` to see only findings where attacker-controlled input
provably reaches the sink.

### Severity policy

Severity is fenceline's judgement of how bad a finding is if real; a team may
know better for its own codebase. A `[tool.fenceline.severity]` table in the
nearest `pyproject.toml` (searched upward from the directory fenceline runs
in) caps a check's severity, by check function name:

```toml
[tool.fenceline.severity]
check_crlf = "medium"      # we build HTTP framing by hand; CRLF here is by design
check_ssrf = "low"         # outbound URLs come from our own config, never a request
```

A cap never raises: an INFO finding from a capped check stays INFO. This keeps
`--fail-on high` meaningful without `# nosec`-ing every occurrence or dropping
the check altogether, and the policy is a reviewable file in the repository. A
misspelled check name or level is an error (exit 2), not a silently inert line.

### Files that could not be parsed

A Python file that fails to parse still gets the line-regex checks, but none
of the AST checks. The report says so rather than passing the file off as
clean: the text report prints a `could not be parsed` line, and the JSON
payload carries a `skipped_files` list.

### Dependency CVEs and lockfiles

`check_dependency_cve` compares the version a project will actually install
against the same `vuln_deps.json` table the Python original ships (a curated
zero-day watchlist, not an advisory-database mirror; run `pip-audit` for full
CVE coverage). When a lockfile (`uv.lock`, `poetry.lock`, `Pipfile.lock`)
sits next to the manifest, the lockfile's exact versions are checked and the
manifest's ranges are ignored, with the finding reported on the lockfile
line. Without a lockfile, an `==` pin below the fixed version is HIGH
confidence and a lower bound (`>=`, `~=`) below it is MEDIUM. Version
comparison follows PEP 440 (`1.0rc1 < 1.0 < 1.0.post1`, `2024.1.0`).

### Baselining an existing codebase

Adopting fenceline on a codebase with existing findings doesn't mean fixing
all of them before CI can pass:

```bash
fenceline --write-baseline fenceline-baseline.json   # snapshot today's findings
fenceline --baseline fenceline-baseline.json          # only new findings fail CI
```

A finding is matched against the baseline by `(cwe_id, file, code_snippet)`,
not line number, so it keeps matching across unrelated edits that shift line
numbers elsewhere in the file. Re-run `--write-baseline` periodically (or
whenever a baselined finding is deliberately fixed) to keep it current.

### Suppressing a specific finding

`# nosec` (bare) suppresses every finding on that line; `# nosec CWE-502`
suppresses only that CWE, leaving any other finding on the same line intact
— the same convention Bandit uses, with CWE IDs instead of Bandit's own
B-numbers:

```python
pickle.loads(data)  # nosec CWE-502 -- trusted internal cache, not user input
```

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
- `reporting` — text, JSON and SARIF report rendering. JSON field order is guaranteed by struct-field declaration order (not a `serde_json::Value::Object`, whose map-ordering would need an explicit feature flag to avoid alphabetical sorting).
- `cli` — argument parsing and the scan loop: every file of a package is parsed first, the callers pass runs, then the checks.

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
