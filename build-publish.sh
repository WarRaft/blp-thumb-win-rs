#!/usr/bin/env bash
set -euo pipefail

# === settings ===
source "$(dirname "$0")/build-settings.sh"

# --- helpers ---
require() { command -v "$1" >/dev/null 2>&1 || { echo "❌ '$1' not found"; exit 1; }; }
die() { echo "❌ $*"; exit 1; }

require git
require gh
require jq
require cargo
require sed

# repo slug (owner/repo)
REPO_SLUG="${REPO_SLUG:-}"
if [[ -z "${REPO_SLUG}" ]]; then
  # попробуем вытащить из origin
  ORIGIN_URL="$(git remote get-url origin 2>/dev/null || true)"
  case "$ORIGIN_URL" in
    git@github.com:*.git) REPO_SLUG="${ORIGIN_URL#git@github.com:}"; REPO_SLUG="${REPO_SLUG%.git}";;
    https://github.com/*) REPO_SLUG="${ORIGIN_URL#https://github.com/}"; REPO_SLUG="${REPO_SLUG%.git}";;
  esac
fi
[[ -n "${REPO_SLUG}" ]] || die "REPO_SLUG is not set (e.g. WarRaft/blp-thumb-win-rs)"

# bump kind: patch|minor|major
BUMP_KIND="${BUMP_KIND:-patch}"

# --- sanity checks ---
git diff --quiet || die "Uncommitted changes in repo"
gh auth status &>/dev/null || die "gh is not authenticated. Run: gh auth login"

# --- project meta ---
PROJECT_NAME="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].name')"
CURR_VERSION="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')"

IFS=. read -r MAJ MIN PAT <<<"$CURR_VERSION"
case "$BUMP_KIND" in
  major) NEW_VERSION="$((MAJ+1)).0.0" ;;
  minor) NEW_VERSION="$MAJ.$((MIN+1)).0" ;;
  patch) NEW_VERSION="$MAJ.$MIN.$((PAT+1))" ;;
  *) die "Unknown BUMP_KIND='$BUMP_KIND'" ;;
esac
TAG="v$NEW_VERSION"
echo "🔢 Version: $CURR_VERSION → $NEW_VERSION  (tag: $TAG)"

# --- bump Cargo.toml (BSD/macOS sed поддержан) ---
if sed --version &>/dev/null; then
  sed -E -i "s/^version *= *\"[0-9]+\.[0-9]+\.[0-9]+([^\"]*)?\"/version = \"$NEW_VERSION\"/" Cargo.toml
else
  sed -E -i '' "s/^version *= *\"[0-9]+\.[0-9]+\.[0-9]+([^\"]*)?\"/version = \"$NEW_VERSION\"/" Cargo.toml
fi
[[ -f Cargo.lock ]] && cargo generate-lockfile >/dev/null || true

# --- commit + tag + push ---
git add Cargo.toml Cargo.lock 2>/dev/null || true
git commit -m "chore(release): $TAG"
git tag -a "$TAG" -m "$PROJECT_NAME $NEW_VERSION"
git push origin HEAD --tags

# --- build (двухпроходный build-only.sh кладёт DLL+EXE в ./bin) ---
./build-only.sh

# --- asset: только инсталлер из ./bin ---
EXE_BIN_PATH="${BIN_DIR}/${BIN_NAME}.exe"
[[ -f "$EXE_BIN_PATH" ]] || die "installer not found: $EXE_BIN_PATH"

# --- publish release (только EXE) ---
if gh release view "$TAG" -R "$REPO_SLUG" >/dev/null 2>&1; then
  echo "ℹ️  Release $TAG exists — uploading installer (clobber)"
  gh release upload "$TAG" "$EXE_BIN_PATH" --clobber -R "$REPO_SLUG"
else
  echo "🚀 Creating release $TAG with installer"
  gh release create "$TAG" \
    -R "$REPO_SLUG" \
    -t "$PROJECT_NAME $NEW_VERSION" \
    -n "Windows installer attached." \
    "$EXE_BIN_PATH"
fi

echo "✅ Published $TAG → $REPO_SLUG"
echo "   attached: $(basename "$EXE_BIN_PATH")"
