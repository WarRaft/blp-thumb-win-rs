#!/usr/bin/env sh
set -euo pipefail

# Load settings early (may get re-sourced after bump)
. "$(dirname "$0")/build-setting.sh"

usage() {
  cat <<EOF
Usage:
  $(basename "$0") --bump {patch|minor|major|X.Y.Z} [--notes "text"] [--dry-run]

Options:
  --bump     Bump level or explicit semver (required)
  --notes    Release notes text (optional). If omitted, uses a small default.
  --dry-run  Do everything except git push and gh release
EOF
}

BUMP=""
NOTES=""
DRY_RUN="0"

while [ $# -gt 0 ]; do
  case "$1" in
    --bump) shift; BUMP="${1:-}";;
    --notes) shift; NOTES="${1:-}";;
    --dry-run) DRY_RUN="1";;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 2;;
  esac
  shift || true
done

[ -n "${BUMP}" ] || { echo "ERR: --bump is required"; usage; exit 2; }

# Ensure tools
command -v gh >/dev/null 2>&1 || { echo "ERR: GitHub CLI 'gh' not found"; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "ERR: cargo not found"; exit 1; }

# Install cargo-edit if needed (for `cargo set-version`)
if ! cargo set-version --help >/dev/null 2>&1; then
  echo "==> Installing cargo-edit (provides 'cargo set-version')"
  cargo install cargo-edit
fi

# Clean working tree check
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "ERR: Working tree not clean. Commit/stash changes before publishing."
  exit 1
fi

# Determine bump command
case "${BUMP}" in
  patch|minor|major)
    echo "==> Bumping version: ${BUMP}"
    cargo set-version --bump "${BUMP}"
    ;;
  *)
    # allow explicit semver X.Y.Z
    if printf '%s' "${BUMP}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
      echo "==> Setting version: ${BUMP}"
      cargo set-version "${BUMP}"
    else
      echo "ERR: --bump must be 'patch', 'minor', 'major' or 'X.Y.Z'"
      exit 2
    fi
    ;;
esac

# Re-read settings to get NEW version/paths
. "$(dirname "$0")/build-setting.sh"

echo "==> Committing version bump to ${TAG}"
git add Cargo.toml Cargo.lock || true
git commit -m "chore: release ${TAG}"

echo "==> Tagging ${TAG}"
git tag -a "${TAG}" -m "${TAG}"

# Build artifacts
"$(dirname "$0")/build-only.sh"

# Prepare release notes
if [ -z "${NOTES}" ]; then
  NOTES="Automated release ${TAG}

Artifacts:
- ${BUNDLE_NAME}.zip (Windows x64)
Includes: ${LIB_NAME}.dll, ${BIN_NAME}.exe, (optional) PDBs, README, LICENSE.
"
fi

# Push & release
if [ "${DRY_RUN}" = "1" ]; then
  echo "==> DRY RUN: skipping git push and gh release"
  echo "Would push tag ${TAG} and create release with ${ZIP_PATH}"
  exit 0
fi

echo "==> Pushing commit and tags"
git push origin HEAD
git push origin "${TAG}"

echo "==> Creating GitHub release ${TAG}"
# Attach zip (primary), and also raw DLL/EXE for convenience
ASSETS="${ZIP_PATH}"
[ -f "${DLL_PATH}" ] && ASSETS="${ASSETS} ${DLL_PATH}"
[ -f "${EXE_PATH}" ] && ASSETS="${ASSETS} ${EXE_PATH}"

# shellcheck disable=SC2086
gh release create "${TAG}" ${ASSETS} \
  --repo "${REPO_SLUG}" \
  --title "${CRATE_NAME} ${TAG}" \
  --notes "${NOTES}"

echo "==> Done: https://github.com/${REPO_SLUG}/releases/tag/${TAG}"
