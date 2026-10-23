# Release notes and qualification boundary

Use the authoritative release record and the included `release-manifest.v1.json` for the exact version,
source revision, CPU/CUDA flavor, image digest, package hashes and qualification results.
This source document does not declare a new official artifact qualified or published.

## Changes prepared for this release

- Retain Windows Docker/Podman CPU and NVIDIA CUDA 12.8 profiles with separate digest-pinned packages.
- Remove the unsafe file-deletion endpoint and its active frontend caller; constrain Host to localhost/IPv4 loopback and reject foreign-Origin, cross-site and same-site browser requests. These controls are not authentication or an XSS defense.
- Preserve files in the uploads volume when the application starts or its container is replaced; startup no longer clears that durable directory.
- Align KML and dataset selection with the UI's primary/secondary confidence threshold; keep CSV's boundary flag factual.
- Protect spreadsheet text, emit UTF-8 CSV, preserve valid XML text and release temporary download URLs.
- Bound dataset restore to 1,000 members, 64 MiB per member and 512 MiB total expanded size; preserve the current session on failed restore.
- Validate publication inputs and exact source, and require the protected release environment before building or registry login.
- Automatic TLS repair selects only signing CA certificates already present in a Windows Root store; other CAs require explicit Local IT approval and selection.

## Installation restrictions

The package is unsigned. Use the supplied wrappers only where the user and organization permit them;
signature-enforcing or organization-allowlisted endpoints are outside the standard support claim.
Compare authoritative hashes before extracting browser-downloaded bytes.
Podman requires a short extraction path (package root at most 80 characters), rootless operation,
and explicitly selected 64-bit Python 3.12. Quit Docker Desktop before Podman runs; preserve volumes during recovery.
CPU-only hardware and Podman without Docker Desktop installed remain unqualified.

Historical tests exercised RTX PRO 500 Blackwell Laptop GPU (`sm_120`) and T1000 (`sm_75`).
Newly built artifacts still require the two-host qualification recorded for their exact identities.
No GPU model name alone qualifies every driver, Windows, WSL, engine or toolkit version.

CSV retains all detection rows with selection/threshold flags; KML exports selected visible results; training datasets retain selected above-threshold labels across full images, including outside-boundary results.
Text beginning with a spreadsheet formula marker is prefixed with an apostrophe for safe opening in spreadsheet software.
Dataset export/restore preserves review data, not the full configuration or container volumes.

Read the [package guide](../package-guide.md), [maintenance boundaries](../maintenance.md),
and [dependency security disposition](../security/dependency-security-disposition.md).
