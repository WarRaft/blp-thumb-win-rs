#!/usr/bin/env bash
set -euo pipefail

# Load settings
. "$(dirname "$0")/build-settings.sh"

echo "==> Ensuring target '${TARGET_TRIPLE}' is installed"
rustup target add "${TARGET_TRIPLE}" >/dev/null

# 1) Build LIB (DLL) first
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

# 2) Build installer (it expects DLL in ./bin at compile-time)
echo "==> Building installer only (embeds ./bin/$(basename "${DLL_PATH}") via include_bytes!)"
cargo build --target "${TARGET_TRIPLE}" --${PROFILE} --bin "${BIN_NAME}"

# Check EXE
[ -f "${EXE_PATH}" ] || { echo "ERR: EXE not found after installer build: ${EXE_PATH}"; exit 1; }

# Copy EXE into ./bin
cp -f "${EXE_PATH}" "${BIN_DIR}/"
echo "==> Copied EXE to ${BIN_DIR}/$(basename "${EXE_PATH}")"

# Optional PDB for EXE
[ -f "${PDB_EXE}" ] && { cp -f "${PDB_EXE}" "${BIN_DIR}/"; echo "==> Copied PDB: $(basename "${PDB_EXE}")"; } || true

echo "==> Done. Artifacts in ${BIN_DIR}/:"
ls -l "${BIN_DIR}"
