#!/usr/bin/env sh
set -euo pipefail

# Load settings
. "$(dirname "$0")/build-setting.sh"

echo "==> Ensuring target '${TARGET_TRIPLE}' is installed"
rustup target add "${TARGET_TRIPLE}" >/dev/null

echo "==> Building (target=${TARGET_TRIPLE}, profile=${PROFILE})"
cargo build --target "${TARGET_TRIPLE}" --${PROFILE}

# Check artifacts
[ -f "${DLL_PATH}" ] || { echo "ERR: DLL not found: ${DLL_PATH}"; exit 1; }
[ -f "${EXE_PATH}" ] || { echo "ERR: EXE not found: ${EXE_PATH}"; exit 1; }

echo "==> Preparing bundle at ${BUNDLE_DIR}"
rm -rf "${BUNDLE_DIR}" "${ZIP_PATH}"
mkdir -p "${BUNDLE_DIR}"

# Copy artifacts
cp "${DLL_PATH}" "${BUNDLE_DIR}/"
cp "${EXE_PATH}" "${BUNDLE_DIR}/"

# Optional PDBs (if present)
[ -f "${PDB_DLL}" ] && cp "${PDB_DLL}" "${BUNDLE_DIR}/" || true
[ -f "${PDB_EXE}" ] && cp "${PDB_EXE}" "${BUNDLE_DIR}/" || true

# Add docs if present
[ -f "README.md" ] && cp "README.md" "${BUNDLE_DIR}/" || true
[ -f "LICENSE" ] && cp "LICENSE"   "${BUNDLE_DIR}/" || true

# Version stamp
printf '%s\n' "${VERSION}" > "${BUNDLE_DIR}/VERSION.txt"

# Zip bundle
echo "==> Creating ${ZIP_PATH}"
mkdir -p "${DIST_DIR}"
(
  cd "${DIST_DIR}"
  if command -v zip >/dev/null 2>&1; then
    zip -r -9 "$(basename "${ZIP_PATH}")" "$(basename "${BUNDLE_DIR}")" >/dev/null
  elif command -v 7z >/dev/null 2>&1; then
    7z a -tzip "$(basename "${ZIP_PATH}")" "$(basename "${BUNDLE_DIR}")" >/dev/null
  else
    echo "ERR: neither 'zip' nor '7z' found. Install one of them."
    exit 1
  fi
)

# Checksums
echo "==> Writing checksums"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${ZIP_PATH}" > "${ZIP_PATH}.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "${ZIP_PATH}" > "${ZIP_PATH}.sha256"
fi

echo "==> Done"
echo "Artifacts:"
echo "  ${DLL_PATH}"
echo "  ${EXE_PATH}"
echo "  ${ZIP_PATH}"
[ -f "${ZIP_PATH}.sha256" ] && echo "  ${ZIP_PATH}.sha256"
