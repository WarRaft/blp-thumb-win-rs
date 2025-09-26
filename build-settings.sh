#!/usr/bin/env bash
# Shared settings for build scripts

set -euo pipefail

need() { command -v "$1" &>/dev/null || { echo "❌ Требуется '$1'"; exit 1; }; }

# ---- Project metadata ----
CRATE_NAME="${CRATE_NAME:-blp-thumb-win}"
LIB_NAME="${LIB_NAME:-blp_thumb_win}"            # -> blp_thumb_win.dll
BIN_NAME="${BIN_NAME:-blp-thumb-installer}"      # -> blp-thumb-installer.exe

# ---- Profile ----
PROFILE="${PROFILE:-release}"

# ---- Target triple ----
OS_UNAME="$(uname -s || echo Unknown)"
if [ "${OS_UNAME}" = "Darwin" ]; then
  TARGET_TRIPLE="${TARGET_TRIPLE:-x86_64-pc-windows-gnu}"
else
  TARGET_TRIPLE="${TARGET_TRIPLE:-x86_64-pc-windows-msvc}"
fi
export TARGET_TRIPLE

# ---- Cross toolchain hints (macOS → mingw-w64) ----
if [ "${OS_UNAME}" = "Darwin" ] && [ "${TARGET_TRIPLE}" = "x86_64-pc-windows-gnu" ]; then
  export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="${CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER:-x86_64-w64-mingw32-gcc}"
  export RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static"
  export CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"
  export CC_x86_64_pc_windows_gnu="${CC_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-gcc}"
  export AR_x86_64_pc_windows_gnu="${AR_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-ar}"
  export RANLIB_x86_64_pc_windows_gnu="${RANLIB_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-ranlib}"
fi

# ---- Output paths ----
TARGET_DIR="target/${TARGET_TRIPLE}/${PROFILE}"
DLL_PATH="${TARGET_DIR}/${LIB_NAME}.dll"
EXE_PATH="${TARGET_DIR}/${BIN_NAME}.exe"
PDB_DLL="${TARGET_DIR}/${LIB_NAME}.pdb"
PDB_EXE="${TARGET_DIR}/${BIN_NAME}.pdb"

# ---- Where to drop final artifacts ----
BIN_DIR="${BIN_DIR:-bin}"

export TARGET_DIR DLL_PATH EXE_PATH PDB_DLL PDB_EXE BIN_DIR PROFILE
