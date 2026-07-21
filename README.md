# fenceline

Zero-day security scanner **for Python codebases**, implemented in Rust.

This is a from-scratch reimplementation of [`fenceline`](https://github.com/lvalverdeb/fenceline) (the Python original, formerly `tripwire`) — not a wrapper or FFI binding. It parses and scans Python source directly, with no Python runtime dependency, aiming for a single native binary you can drop into any CI image or pre-commit hook with nothing else installed. Maps every finding to a CWE, tracks two independent ratings per finding (severity and confidence), and is designed to be extensible via third-party checks.

The [Python original](https://github.com/lvalverdeb/fenceline) remains the actively maintained **spec of record**: when the two disagree, the Python behaviour is correct by definition and this is a bug here, not there. See [`RUST_PORT_PROPOSAL.md`](https://github.com/lvalverdeb/fenceline/blob/main/RUST_PORT_PROPOSAL.md) in the Python repo for the full design rationale, phased build history, and every behavioural quirk uncovered and matched along the way (some quite subtle — e.g. `check_assert_security`'s `\b(is|==|!=|in)\b` provably never matching `==`/`!=` written the normal way with spaces or quotes around them).

**Status**: Phase 2 in progress. Plumbing only — workspace-root discovery, the default package registry, file iteration and AST parsing, and text/JSON report rendering all work and are unit-tested (22 tests), but **no checks exist yet** (that's Phase 3), so a real scan always reports zero findings. Not usable as a scanner yet.

## Why It Exists

See the Python original's own README and `RUST_PORT_PROPOSAL.md` for the full rationale — in short: a native binary removes the Python-interpreter dependency for running the scanner anywhere (CI images, pre-commit hooks, external codebases), and fenceline's checks are simple enough (single-file, single-pass — no cross-file analysis) that a port carries much less risk than a typical static-analysis tool would.

## Build

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Design

- `models` — the `Finding` struct, plus `Severity`/`Confidence` enums whose declared variant order matches the Python `SEVERITY_ORDER`/`CONFIDENCE_ORDER` dicts exactly (so a derived `Ord` sorts the same way).
- `config` — workspace-root discovery (walks upward for a `pyproject.toml` declaring `[tool.uv.workspace]`), the default package registry, and `is_secure_path` (a from-scratch reimplementation of the Python original's `boti.core.is_secure_path` sandbox check — see the module docs for one disclosed divergence: `std::fs::canonicalize` requires the target to exist, unlike Python's `Path.resolve()`).
- `scanner` — file discovery (`.py` files under a package root, sorted, with fenceline's own pattern-table files excluded from self-scan), file reading, and AST parsing — all tolerant of unreadable/malformed files, matching the Python original's "never crash the whole scan over one bad file" design.
- `reporting` — text and JSON report rendering. JSON field order is guaranteed by struct-field declaration order (not a `serde_json::Value::Object`, whose map-ordering would need an explicit feature flag to avoid alphabetical sorting).

Not yet ported: any actual check (Phase 3), the CLI (Phase 4 — `clap`, `--package`/`--fail-on`/`--confidence-min`/`--baseline`/`--write-baseline`), and the newer Python-side features (`# nosec` suppression, the third-party plugin architecture — see `RUST_PORT_PROPOSAL.md` §7.8 for why the plugin story specifically has no obvious Rust equivalent).
