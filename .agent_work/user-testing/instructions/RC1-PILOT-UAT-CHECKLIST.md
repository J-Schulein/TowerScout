# RC1 Pilot / UAT Checklist

Use this checklist for controlled V1 RC1 package-path pilot testing.

## Supported Pilot Path

- Windows 11 AMD64.
- Docker Desktop as the primary runtime engine.
- CPU-default launch with `-Gpu off`.
- Azure Maps or Google Maps provider key.
- Package-local assets imported with hash verification.
- Bounded public/non-sensitive detection area, preferably 1-6 tiles.

Do not use this checklist to claim GPU acceleration, Docker-Desktop-free Podman support, source-build support, restricted-network/offline support, or large-AOI performance.

## Before You Start

Confirm you have:

- TowerScout release package ZIP.
- Matching asset bundle and checksum instructions.
- A provider key from the release owner or your organization.
- Docker Desktop installed and running.
- WSL 2 enabled for Docker Desktop's normal Windows Linux-container backend.
- PowerShell access.
- A modern browser.
- Outbound internet access for the container image, map provider, and geocoding provider.

Do not send API keys, full `.env` files, private AOI screenshots, or unredacted logs.

If you do not normally use PowerShell:

1. Open File Explorer.
2. Open the extracted TowerScout package folder.
3. Click the address bar, type `powershell`, and press Enter.
4. Paste one command at a time and press Enter.

Commands beginning with `.\` run scripts from the current folder.

Before launch, Docker Desktop should be open from the Windows Start menu and
show that it is running. If support asks you to check WSL/Docker readiness, run:

```powershell
wsl --status
wsl --list --verbose
docker --version
docker compose version
```

Expected result: WSL is installed, any listed Linux distribution uses version
`2`, and Docker commands print version information.

## Test Steps

1. Extract the TowerScout release package ZIP to a local folder.
2. Extract the asset bundle into the package `assets/` folder.
3. Open PowerShell in the package folder.
4. Start TowerScout:

   ```powershell
   .\start.bat -Engine docker -Gpu off
   ```

   Expected result: PowerShell prints that TowerScout is starting with Docker,
   reports a readiness state, and opens `http://localhost:5000` or allows you
   to open that address manually.

5. Import assets:

   ```powershell
   .\scripts\import-assets.cmd -Engine docker -Source assets -VerifyHashes -RestartWaitSeconds 180
   ```

   Expected result: the import finishes without missing/corrupt asset errors
   and waits for TowerScout to respond after restart.

6. Open TowerScout in the browser if it does not open automatically.
7. Complete Setup Wizard with Azure Maps or Google Maps.
8. Open Settings Resource Links and confirm the package-local docs and source/license page load.
9. Run the owner-provided bounded detection smoke.
10. Confirm results appear on the map and in the right-hand review panel.
11. Confirm addresses/provider metadata appear when geocoding succeeds, or that a clear fallback appears when unavailable.
12. If requested, export CSV or KML.
13. Stop TowerScout through the package stop script or documented shutdown path.

   ```powershell
   .\scripts\stop.cmd -Engine docker
   ```

## Record The Result

Record:

- Date/time and time zone.
- Windows version.
- Runtime engine and version.
- Package version/folder name.
- Image digest shown by package metadata or launch output.
- Asset import result.
- Provider used.
- Detection fixture/AOI name.
- Tile count estimate if shown.
- Final result: `PASS`, `PASS_WITH_NOTES`, `BLOCKED`, or `FAIL`.

## If Something Fails

Use `TESTER-ISSUE-REPORT-CHECKLIST.txt`.

Capture exact error text and the step where it failed. Screenshots are useful only when they do not reveal API keys, private locations, or sensitive data.
