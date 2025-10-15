# blp-thumb-win-rs

Dependencies & documentation: this project implements Windows Explorer handlers
for the BLP texture format and depends on the BLP format specification and the
`blp-rs` Rust decoder for parsing BLP files. See the BLP spec at
https://github.com/WarRaft/BLP and the decoder used by this project at
https://github.com/WarRaft/blp-rs for format details and decoding code used by
the DLL.

blp-thumb-win-rs provides native Windows Explorer integration for BLP image files.
It implements a thumbnail handler as a COM DLL written in Rust and ships a small
installer that registers the shell bindings so Explorer shows rich thumbnails for
`.blp` files. The preview pane is configured to reuse this thumbnail instead of a
dedicated preview handler.

## What it does

- Builds a COM DLL (`blp_thumb_win.dll`) which exposes a thumbnail provider.
- Produces an installer executable that embeds the DLL and writes registry
  entries (HKCU) to register the handler and helper keys for the current user.
- Adds verbose registry-logging while installing so you can inspect exactly which
  keys and values are written.

## Quick build (Linux/macOS dev host cross-build for Windows targets)

This repository includes helper scripts used for cross-building the DLL and
installer. The project uses the Rust toolchain and cross targets (x86_64-pc-windows-gnu / msvc).

1. Ensure Rust toolchain + required targets are installed (see your normal
   Rust setup for cross-compilation).
2. Run the provided build script to produce the DLL and installer:

```sh
bash build-only.sh
```

Artifacts will be placed in `./bin/`:
- `blp_thumb_win.dll` — the COM DLL
- `blp-thumb-win-installer.exe` — the installer that writes registry entries

## Install on Windows (recommended)

Copy the `blp_thumb_win.dll` and `blp-thumb-win-installer.exe` to a Windows machine
and run the installer. Registration is performed in HKCU for the current user, so
no elevation is required.

After running the installer, restart Explorer or use the `Restart Explorer`
action in the provided installer UI so Explorer picks up the new handlers.

## Registry keys written by the installer (ASCII tree)

Below is the registry layout that the installer creates or updates for HKCU.

```
HKCU
└─ Software
   └─ Classes
      ├─ .blp
      │  (Default) = WarRaft.BLP                ; file extension -> ProgID
      │  Content Type = image/x-blp
      │  PerceivedType = image
      ├─ WarRaft.BLP                            ; ProgID
      │  (Default) = BLP Thumbnail Provider
      │  ShellEx
      │  └─ {8895B1C6-B41F-4C1C-A562-0D564250836F} = {CLSID_BLP_THUMB}
      │  ThumbnailCutoff, TypeOverlay, etc. (optional)
      └─ CLSID
         ├─ {CLSID_BLP_THUMB}
         │  (Default) = BLP Thumbnail Provider
         │  DisableProcessIsolation = 1
         │  InprocServer32
         │  └─ (Default) = %LOCALAPPDATA%\blp-thumb-win\blp_thumb_win.dll
         │     ThreadingModel = Apartment
         │     ProgID = WarRaft.BLP
         │  Implemented Categories
         │  └─ {E357FCCD-A995-4576-B01F-234630154E96}
         └─ (legacy preview handler entries removed)
```

Explorer lists touched by the installer (HKCU):

HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers
   (.blp) = {CLSID_BLP_THUMB}

HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved
   {CLSID_BLP_THUMB} = "BLP Thumbnail Provider"

## Notes & troubleshooting

- If Explorer does not pick up handlers immediately, restart Explorer or
  log out/in. The installer attempts to clear shell caches and notifies the
  shell, but a restart is sometimes needed.
- The installer writes readable logs describing every registry write; check
  those logs if registration appears to fail.

## Contributing

Contributions are welcome. The main areas of work are:
- Improving BLP parsing and rendering quality in the DLL
- Making installation/registration more robust across Windows versions
- Adding automated tests or CI that validates registration on Windows VMs

## Safety — use at your own risk

This project performs direct modifications to the Windows registry to
register shell extensions and COM classes. Registry modifications can affect
system behavior. Use this software at your own risk. Before running the
installer on any system (especially production machines), make a backup of
important data and consider exporting affected registry branches so you can
restore them if needed. The author and maintainers accept no responsibility
for data loss or system damage resulting from running this installer.
