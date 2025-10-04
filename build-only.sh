#!/usr/bin/env bash
set -euo pipefail

# Load settings
. "$(dirname "$0")/build-settings.sh"

# Reset the human-readable build log for this top-level run
mkdir -p assets
: > assets/build-report.txt   # truncate (or create)

echo "==> Ensuring target '${TARGET_TRIPLE}' is installed"
rustup target add "${TARGET_TRIPLE}" >/dev/null

# Clean previous bin artifacts to avoid stale bundles
if [ -d "${BIN_DIR}" ]; then
  echo "==> Removing existing ${BIN_DIR}/"
  rm -rf "${BIN_DIR}"
fi

# 1) Build LIB (DLL) first — no icon embedding here
echo "==> Building LIB (DLL) only: target=${TARGET_TRIPLE}, profile=${PROFILE}"
cargo build --target "${TARGET_TRIPLE}" --${PROFILE} --lib

# Check DLL
[ -f "${DLL_PATH}" ] || { echo "ERR: DLL not found after lib build: ${DLL_PATH}"; exit 1; }

# Prepare bin/
echo "==> Ensuring ./${BIN_DIR} exists"
mkdir -p "${BIN_DIR}"

# Copy DLL into ./bin so installer can include_bytes! it at compile-time
cp -f "${DLL_PATH}" "${BIN_DIR}/"
echo "==> Copied DLL to ${BIN_DIR}/$(basename "${DLL_PATH}")"

# Optional PDB for DLL
[ -f "${PDB_DLL}" ] && { cp -f "${PDB_DLL}" "${BIN_DIR}/"; echo "==> Copied PDB: $(basename "${PDB_DLL}")"; } || true

# 2) Build installer (icon embedding happens only now)
echo "==> Building installer only (embeds ./bin/$(basename "${DLL_PATH}") via include_bytes!)"

# Force build.rs to re-run for the installer phase (single-file trigger)
printf "phase=installer ts=%s\n" "$(date +%s%N)" >> assets/build-report.txt

# Set env only for the installer build so build.rs knows to embed resources
BLP_INSTALLER=1 cargo build --target "${TARGET_TRIPLE}" --${PROFILE} --bin "${BIN_NAME}"

# Check EXE
[ -f "${EXE_PATH}" ] || { echo "ERR: EXE not found after installer build: ${EXE_PATH}"; exit 1; }

# Copy EXE into ./bin
cp -f "${EXE_PATH}" "${BIN_DIR}/"
echo "==> Copied EXE to ${BIN_DIR}/$(basename "${EXE_PATH}")"

# Optional PDB for EXE
[ -f "${PDB_EXE}" ] && { cp -f "${PDB_EXE}" "${BIN_DIR}/"; echo "==> Copied PDB: $(basename "${PDB_EXE}")"; } || true

echo "==> Done. Artifacts in ${BIN_DIR}/:"
ls -l "${BIN_DIR}"
