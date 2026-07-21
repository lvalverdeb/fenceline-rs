//! Workspace-root discovery, the default scan-target package registry, and
//! dependency-manifest filenames -- mirrors `fenceline/config.py`.

use std::collections::BTreeMap;
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
/// rather than resolving it anyway the way Python does. `default_packages`
/// below only ever calls this on real, existing package directories, so
/// this divergence doesn't bite there; it would matter for a future
/// `--package NAME=PATH` (Phase 4) pointed at a not-yet-created path.
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

/// Every default scan target must resolve inside `workspace_root` -- mirrors
/// `config.py::DEFAULT_PACKAGES`'s `is_secure_path` filter. Empty when
/// `workspace_root` is `None`: there's nothing to default to, the caller
/// must pass an explicit target instead (Phase 4's `--package`).
pub fn default_packages(workspace_root: Option<&Path>) -> BTreeMap<String, PathBuf> {
    let Some(root) = workspace_root else {
        return BTreeMap::new();
    };
    [
        ("boti", "boti/src/boti"),
        ("boti-data", "boti-data/src/boti_data"),
        ("boti-dask", "boti-dask/src/boti_dask"),
        ("fenceline", "fenceline/src/fenceline"),
    ]
    .into_iter()
    .map(|(name, rel)| (name.to_string(), root.join(rel)))
    .filter(|(_, path)| is_secure_path(path, &[root]))
    .collect()
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

    #[test]
    fn default_packages_resolve_inside_workspace_root() {
        let tmp = tempfile::tempdir().unwrap();
        for pkg in ["boti", "boti-data", "boti-dask", "fenceline"] {
            let src_name = pkg.replace('-', "_");
            std::fs::create_dir_all(tmp.path().join(pkg).join("src").join(&src_name)).unwrap();
        }
        let packages = default_packages(Some(tmp.path()));
        assert_eq!(packages.len(), 4);
        for path in packages.values() {
            assert!(path.starts_with(tmp.path()));
        }
    }

    #[test]
    fn default_packages_empty_when_no_workspace_root() {
        assert!(default_packages(None).is_empty());
    }
}
