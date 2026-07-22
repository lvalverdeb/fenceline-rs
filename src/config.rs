//! Workspace-root discovery, the path-security sandbox check, and
//! dependency-manifest filenames -- mirrors `fenceline/config.py`.

use std::path::{Path, PathBuf};

/// Dependency-manifest filenames probed alongside each package's source tree
/// for the eventual `check_dependency_cve`/`check_unbounded_pins` (Phase 3).
pub const DEP_MANIFEST_FILES: &[&str] =
    &["pyproject.toml", "requirements.txt", "setup.py", "Pipfile"];

/// Walk upward from `start` for the `pyproject.toml` declaring the uv
/// workspace -- mirrors `config.py::_find_workspace_root`. Deliberately
/// requires the `[tool.uv.workspace]` table specifically, not just the
/// nearest `pyproject.toml`: fenceline ships its own `pyproject.toml` one
/// level below the true workspace root, so a nearest-marker search would
/// resolve to the wrong directory.
///
/// Returns `None` rather than erroring when no such ancestor exists --
/// fenceline works standalone too (e.g. its own CI checkout, with no
/// sibling `boti`/etc. directories and no ambient workspace at all), and
/// this must not panic in that case.
pub fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    let mut candidate = Some(start.to_path_buf());
    while let Some(dir) = candidate {
        let pyproject = dir.join("pyproject.toml");
        if pyproject.is_file()
            && let Ok(text) = std::fs::read_to_string(&pyproject)
            && let Ok(value) = text.parse::<toml::Table>()
        {
            let has_workspace = value
                .get("tool")
                .and_then(|t| t.get("uv"))
                .and_then(|uv| uv.get("workspace"))
                .is_some();
            if has_workspace {
                return Some(dir);
            }
        }
        candidate = dir.parent().map(PathBuf::from);
    }
    None
}

/// Mirrors `boti.core.is_secure_path`: verifies *target* resolves inside one
/// of *allowed_dirs* -- a defensive sandbox check for a *security* tool's
/// own file access (fenceline reads and reports the contents of whatever
/// it's pointed at). Reimplemented directly (§4.3 of RUST_PORT_PROPOSAL.md)
/// rather than depending on `boti` at build time, since it's ~10 lines with
/// no Python-specific behaviour.
///
/// **Known divergence from Python**: Python's `Path.resolve()` normalises a
/// path lexically and follows symlinks *without requiring the path to
/// exist* -- `std::fs::canonicalize` (used here) errors on a nonexistent
/// path instead. In practice this only matters for a path that doesn't
/// exist yet, where this function now fails closed (treats it as insecure)
/// rather than resolving it anyway the way Python does; it matters for
/// `--package NAME=PATH` pointed at a not-yet-created path.
pub fn is_secure_path(target: &Path, allowed_dirs: &[&Path]) -> bool {
    let Ok(target) = target.canonicalize() else {
        return false;
    };
    allowed_dirs.iter().any(|allowed| {
        allowed
            .canonicalize()
            .is_ok_and(|allowed| target.starts_with(allowed))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_workspace_root_returns_none_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(find_workspace_root(tmp.path()), None);
    }

    #[test]
    fn find_workspace_root_finds_ancestor_workspace_marker() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("pyproject.toml"),
            "[tool.uv.workspace]\nmembers = []\n",
        )
        .unwrap();
        let nested = tmp.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            find_workspace_root(&nested)
                .unwrap()
                .canonicalize()
                .unwrap(),
            tmp.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn find_workspace_root_ignores_pyproject_without_workspace_table() {
        // A package's own pyproject.toml (no [tool.uv.workspace]) must not
        // be mistaken for the workspace root -- mirrors why this can't just
        // be "nearest pyproject.toml wins".
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("pyproject.toml"),
            "[project]\nname = \"pkg\"\n",
        )
        .unwrap();
        assert_eq!(find_workspace_root(tmp.path()), None);
    }

    #[test]
    fn is_secure_path_accepts_nested_path() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a");
        std::fs::create_dir(&nested).unwrap();
        assert!(is_secure_path(&nested, &[tmp.path()]));
    }

    #[test]
    fn is_secure_path_rejects_path_outside_allowed_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        assert!(!is_secure_path(other.path(), &[tmp.path()]));
    }
}
