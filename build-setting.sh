#!/usr/bin/env sh
# Shared settings for build scripts
# Usage: source ./build-setting.sh
# Goal: sane defaults on macOS (x86_64-pc-windows-gnu via mingw-w64)

set -euo pipefail

# ---- Project metadata ----
CRATE_NAME="${CRATE_NAME:-blp-thumb-win}"
LIB_NAME="${LIB_NAME:-blp_thumb}"                 # -> blp_thumb.dll
BIN_NAME="${BIN_NAME:-blp-thumb-installer}"       # -> blp-thumb-installer.exe
REPO_SLUG="${REPO_SLUG:-WarRaft/blp-thumb-win-rs}"  # owner/repo for gh

# ---- Profile ----
PROFILE="${PROFILE:-release}"

# ---- Target triple (Rust) ----
# By default use MSVC on non-mac; switch to GNU on macOS (no Visual Studio).
OS_UNAME="$(uname -s || echo Unknown)"
if [ "${OS_UNAME}" = "Darwin" ]; then
  TARGET_TRIPLE="${TARGET_TRIPLE:-x86_64-pc-windows-gnu}"
else
  TARGET_TRIPLE="${TARGET_TRIPLE:-x86_64-pc-windows-msvc}"
fi
export TARGET_TRIPLE

# ---- Cross toolchain hints (only needed for GNU cross from macOS) ----
if [ "${OS_UNAME}" = "Darwin" ] && [ "${TARGET_TRIPLE}" = "x86_64-pc-windows-gnu" ]; then
  # Tell cargo which linker to use for this target
  export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="${CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER:-x86_64-w64-mingw32-gcc}"
  # Static CRT to avoid shipping libgcc/libstdc++ DLLs
  export RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static"
  # Make cmake crates stop looking for Visual Studio
  export CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"
  # Extra tool names (help some build scripts)
  export CC_x86_64_pc_windows_gnu="${CC_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-gcc}"
  export AR_x86_64_pc_windows_gnu="${AR_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-ar}"
  export RANLIB_x86_64_pc_windows_gnu="${RANLIB_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-ranlib}"
fi

# ---- Dist/output ----
DIST_DIR="${DIST_DIR:-dist}"

# ---- Version (read from Cargo.toml unless provided) ----
# Takes the first 'version = "..."' it finds.
VERSION="${VERSION:-$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -n1)}"
[ -n "${VERSION}" ] || { echo "ERR: cannot read version from Cargo.toml"; exit 1; }
TAG="v${VERSION}"

# ---- Derived paths ----
TARGET_DIR="target/${TARGET_TRIPLE}/${PROFILE}"
DLL_PATH="${TARGET_DIR}/${LIB_NAME}.dll"
EXE_PATH="${TARGET_DIR}/${BIN_NAME}.exe"
PDB_DLL="${TARGET_DIR}/${LIB_NAME}.pdb"
PDB_EXE="${TARGET_DIR}/${BIN_NAME}.pdb"

BUNDLE_NAME="${CRATE_NAME}-v${VERSION}-windows-x64"
BUNDLE_DIR="${DIST_DIR}/${BUNDLE_NAME}"
ZIP_PATH="${DIST_DIR}/${BUNDLE_NAME}.zip"

# ---- Export for child scripts ----
export CRATE_NAME LIB_NAME BIN_NAME REPO_SLUG PROFILE DIST_DIR \
       VERSION TAG TARGET_DIR DLL_PATH EXE_PATH PDB_DLL PDB_EXE \
       BUNDLE_NAME BUNDLE_DIR ZIP_PATH
