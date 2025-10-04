# blp-thumb-win-rs

Dependencies & documentation: this project implements Windows Explorer handlers
for the BLP texture format and depends on the BLP format specification and the
`blp-rs` Rust decoder for parsing BLP files. See the BLP spec at
https://github.com/WarRaft/BLP and the decoder used by this project at
https://github.com/WarRaft/blp-rs for format details and decoding code used by
the DLL.

blp-thumb-win-rs provides native Windows Explorer integration for BLP image files.
It implements both a thumbnail handler and a preview handler as a COM DLL written in Rust,
and ships a small installer that registers the COM classes and shell bindings so
Explorer will show thumbnails and preview-pane content for `.blp` files.

## What it does

- Builds a COM DLL (`blp_thumb_win.dll`) which exposes two COM classes:
  - A thumbnail provider (BLP thumbnail handler)
  - A preview handler (BLP preview handler)
- Produces an installer executable that embeds the DLL and writes registry
  entries (HKLM/HKCU) to register the handlers and helper keys.
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
and run the installer. For system-wide (HKLM) registration, run the installer as
Administrator. The installer also writes to HKCU so per-user registration will
work without elevation.

After running the installer, restart Explorer or use the `Restart Explorer`
action in the provided installer UI so Explorer picks up the new handlers.

## Registry keys written by the installer (ASCII tree)

Below is the registry layout that the installer creates or updates. The
installer writes to either HKLM or HKCU depending on whether you choose system
or per-user scope; replace `HKLM/HKCU` with the chosen scope when inspecting
registry paths.

```
HKLM / HKCU
└─ Software
   └─ Classes
      ├─ .blp
      │  (Default) = WarRaft.BLP                ; file extension -> ProgID
      │  Content Type = image/x-blp
      │  PerceivedType = image
      ├─ WarRaft.BLP                            ; ProgID
      │  (Default) = BLP Thumbnail Provider
      │  ShellEx
      │  └─ {8895B1C6-B41F-4C1C-A562-0D564250836F} = {CLSID_BLP_PREVIEW}
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
         └─ {CLSID_BLP_PREVIEW}
            (Default) = BLP Preview Handler
            DisplayName = @blp_thumb_win.dll,-101    ; optional but helpful
            AppID = {534A1E02-D58F-44f0-B58B-36CBED287C7C}
            DisableProcessIsolation = 1
            InprocServer32
            └─ (Default) = %LOCALAPPDATA%\blp-thumb-win\blp_thumb_win.dll
               ThreadingModel = Apartment
               ProgID = WarRaft.BLP
            Implemented Categories
            └─ {8895B1C6-B41F-4C1C-A562-0D564250836F}
```

And Explorer lists used by the system:

HKLM / HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers
   (.blp) = {CLSID_BLP_THUMB}

HKLM / HKCU\Software\Microsoft\Windows\CurrentVersion\PreviewHandlers
   {CLSID_BLP_PREVIEW} = "BLP Preview Handler"

Shell Extensions Approved list (used for shell extensions):

HKLM / HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved
   {CLSID_BLP_THUMB} = "BLP Thumbnail Provider"
   {CLSID_BLP_PREVIEW} = "BLP Preview Handler"

## Notes & troubleshooting

- If Explorer does not pick up handlers immediately, restart Explorer or
  log out/in. The installer attempts to clear shell caches and notifies the
  shell, but a restart is sometimes needed.
- For system-wide registration (HKLM) you must run the installer elevated.
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
system behavior and may require administrative privileges when writing to
HKLM. Use this software at your own risk. Before running the installer on any
system (especially production machines), make a backup of important data and
consider exporting affected registry branches (for example `HKLM\\Software\\Classes`)
so you can restore them if needed. The author and maintainers accept no
responsibility for data loss or system damage resulting from running this
installer.
