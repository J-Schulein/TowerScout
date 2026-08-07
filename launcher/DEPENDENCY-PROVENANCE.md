# Task-087 Launcher Dependency Provenance

This is a prototype review inventory for the production-shaped Windows
launcher build. It is not a release SBOM, a source-offer replacement, or legal
approval. A controlled signed build must regenerate the inventory from its
accepted source ref and resolve the open notice questions below.

## Build toolchain

The isolated August 5, 2026 build used CPython 3.12.5 and the exact packages
pinned in `requirements-build.txt`:

| Component | Version | License metadata observed locally | Role |
| --- | --- | --- | --- |
| PyInstaller | 6.15.0 | GPL-2.0-or-later with the PyInstaller bootloader exception | Builds the windowed one-directory application |
| PyInstaller hooks contrib | 2026.6 | GPL-2.0-or-later for standard hooks; Apache-2.0 for bundled runtime hooks | Build-time hook collection |
| altgraph | 0.17.5 | MIT | PyInstaller dependency analysis |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | Version and requirement handling |
| pefile | 2023.2.7 | MIT | Windows PE processing during the build |
| pywin32-ctypes | 0.2.3 | BSD-3-Clause | Windows build support |
| setuptools | 83.0.0 | MIT | PyInstaller build dependency |

The table records installed distribution metadata and packaged license files;
it does not reinterpret or approve those terms.

## Bundled runtime

Static inventory of the prototype output identified:

- CPython 3.12.5 runtime and standard-library components;
- Tcl/Tk 8.6 components used by Tkinter, including the generated package's
  `_internal/_tk_data/license.terms` file;
- PyInstaller's Windows AMD64 GUI bootloader and Python archive;
- Windows extension modules and runtime DLLs selected by PyInstaller; and
- TowerScout launcher modules `app`, `coordination`, `discovery`, and `models`.

The launcher package contains no TowerScout model/data assets, provider keys,
dormant helper, PowerShell/CMD/BAT files, certificate/key files, or container
image content.

## Open release gates

Before distribution or managed-endpoint execution, the approved owner must:

1. generate a file-level SBOM and cryptographic hashes from the controlled
   build rather than treating this inventory as authoritative;
2. include the applicable CPython, Tcl/Tk, PyInstaller, hook, and bundled DLL
   notices in the release compliance set and confirm redistribution posture;
3. decide whether third-party DLL/PYD files require provenance verification,
   organizational re-signing, or both;
4. integrate the launcher inventory with `THIRD_PARTY_NOTICES.md`, `SBOM.txt`,
   `SOURCE.txt`, the release manifest, and package checksums; and
5. obtain project-owner/legal review for release wording. This document does
   not provide that approval.

No source from the external Windows helpers repository was inspected or
copied. Any later reuse requires a separate license and provenance review.
