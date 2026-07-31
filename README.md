# fenceline

Zero-day security scanner **for Python codebases**, implemented in Rust.

This is a from-scratch reimplementation of [`fenceline`](https://github.com/lvalverdeb/fenceline) (the Python original, formerly `tripwire`) — not a wrapper or FFI binding. It parses and scans Python source directly, with no Python runtime dependency, producing a single native binary you can drop into any CI image or pre-commit hook with nothing else installed. Maps every finding to a CWE from the 2025 CWE Top 25, OWASP Top 10:2025, and known Python zero-day exploit patterns; tracks two independent ratings per finding (severity and confidence, the same distinction Bandit makes).

The [Python original](https://github.com/lvalverdeb/fenceline) remains the actively maintained **spec of record**: when the two disagree, the Python behaviour is correct by definition and this is a bug here, not there. See [`RUST_PORT_PROPOSAL.md`](https://github.com/lvalverdeb/fenceline/blob/main/RUST_PORT_PROPOSAL.md) in the Python repo for the full design rationale, phased build history, and every behavioural quirk uncovered and matched along the way (some quite subtle — e.g. `check_assert_security`'s `\b(is|==|!=|in)\b` provably never matching `==`/`!=` written the normal way with spaces or quotes around them).

**Status**: all 57 checks ported (14 AST-based, 41 text-based, 2 manifest-based), plus `# nosec` inline suppression, baselining, and full CLI flag parity with the Python original — 47 tests passing, including a fixture-corpus conformance runner that diffs every check's output against the Python original's expected results field-by-field.

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
| `--quiet` / `-q` | off | Suppress the banner |
| `--config` | none | TOML file with a `packages` table of `name = "path"` entries; replaces cwd auto-discovery |
| `--package` | none | Add or override one package as `NAME=PATH` (repeatable); applied on top of `--config` |
| `--packages` | all resolved packages | Names to scan from the resolved registry |
| `--exclude` | none | Path substrings to exclude from scanning |
| `--fail-on` | `high` | Severity threshold (`critical`\|`high`\|`medium`\|`low`\|`info`) for the exit code |
| `--confidence-min` | `low` | Drop findings below this confidence (`high`\|`medium`\|`low`) |
| `--baseline PATH` | — | Only report/fail on findings not already present in this baseline |
| `--write-baseline PATH` | — | Snapshot current findings to PATH and exit 0 |
| `--include-tests` | off | Include CWE-798/617/918/770 findings inside test code |
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

Every finding carries two independent ratings: **severity** is how bad it would be if the finding is real; **confidence** is how sure the check is that it *is* real. An AST-based check that matched a real call node is `HIGH` confidence; a text-based check that can't fully rule out a docstring or string-literal mention is `MEDIUM`/`LOW`. Use `--confidence-min medium` to cut noise from the fuzzier checks without raising your severity bar.

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

## Design

- `models` — the `Finding` struct, plus `Severity`/`Confidence` enums whose declared variant order matches the Python `SEVERITY_ORDER`/`CONFIDENCE_ORDER` dicts exactly (so a derived `Ord` sorts the same way).
- `config` — workspace-root discovery (walks upward for a `pyproject.toml` declaring `[tool.uv.workspace]`), the default package registry, and `is_secure_path` (a from-scratch reimplementation of the Python original's `boti.core.is_secure_path` sandbox check — see the module docs for one disclosed divergence: `std::fs::canonicalize` requires the target to exist, unlike Python's `Path.resolve()`).
- `ast_helpers` — shared AST/text-matching helpers used across checks.
- `scanner` — file discovery (`.py` files under a package root, sorted, with fenceline's own pattern-table files excluded from self-scan), file reading, and AST parsing — all tolerant of unreadable/malformed files, matching the Python original's "never crash the whole scan over one bad file" design.
- `checks` — the built-in check registry: `checks::ast_checks` (walk the parsed AST — won't false-positive on a call mentioned in a docstring or string literal), `checks::text_checks` (line-regex checks for surface-syntax patterns), `checks::manifest_checks` (dependency-manifest CVE/unbounded-pin checks, over `pyproject.toml`/`requirements.txt` etc., not Python source).
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
