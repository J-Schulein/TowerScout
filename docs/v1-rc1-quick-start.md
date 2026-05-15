# TowerScout V1 RC1 Quick Start

This is the short Windows pilot path for the TowerScout V1 RC1 `agpl-yolo`
release package. It assumes a Windows 11 AMD64 workstation, a supported
container engine, normal outbound internet access, and one approved Google Maps
or Azure Maps provider key.

For details, see `docs/v1-rc1-package-guide.md`.

## 1. Download The Release Files

Download or receive these files for the same release version:

- `towerscout-v0.1.0-rc1.zip`
- `towerscout-v0.1.0-rc1.zip.sha256`
- `towerscout-v0.1.0-rc1-assets-towerscout-v1-assets-2026-05-05.zip`
- `towerscout-v0.1.0-rc1-assets-towerscout-v1-assets-2026-05-05.zip.sha256`

The exact filenames can change by release, but the control ZIP version and
asset ZIP version must match.

## 2. Extract The Control Package

Extract the control ZIP to a normal local folder such as:

```text
C:\Users\<you>\TowerScout-v0.1.0-rc1
```

After extraction, the folder should contain `start.bat`, `compose.yaml`,
`scripts\`, `docs\`, compliance files, `IMAGE.txt`, `SHA256SUMS.txt`, and an
empty `assets\` folder.

## 3. Initialize The Package

From PowerShell in the package folder, run the launcher once:

```powershell
.\start.bat
```

The first launcher run creates `.env` from `.env.example`, starts the selected
engine, polls TowerScout readiness, and opens:

```text
http://localhost:5000
```

At this point readiness may be `setup_required` because provider setup is not
complete, `degraded` because assets are not imported yet, or both through the
recovery hints. That is expected during first setup.

If support tells you to use a specific engine, keep using the same engine for
every helper command because Docker and Podman use separate named volumes:

```powershell
.\start.bat -Engine podman
```

## 4. Stage And Import Assets

Open the asset ZIP. Its root should contain:

```text
model_params\
data\
asset_manifest.v1.json
```

Extract those entries into the package `assets\` folder so the result is:

```text
assets\
  model_params\
  data\
  asset_manifest.v1.json
```

From PowerShell in the package folder, import the assets:

```powershell
.\scripts\import-assets.cmd -Source assets
```

If you started with an explicit engine, use that same engine here:

```powershell
.\scripts\import-assets.cmd -Engine podman -Source assets
```

For release-candidate or support validation, use hash verification:

```powershell
.\scripts\import-assets.cmd -Source assets -VerifyHashes
```

Or, with an explicit engine:

```powershell
.\scripts\import-assets.cmd -Engine podman -Source assets -VerifyHashes
```

The import helper starts the container if needed so the named volumes are
available. It should run after `.env` has been created by the launcher.

## 5. Start Or Reopen TowerScout

From the package folder, run:

```powershell
.\start.bat
```

The launcher starts the selected Docker-compatible or OCI-compatible engine,
polls TowerScout readiness, and opens:

```text
http://localhost:5000
```

Use `localhost`, not `127.0.0.1`, for normal browser use.

## 6. Complete Setup

When the browser opens, use Setup Wizard or Settings to configure one provider:

- Google Maps, or
- Azure Maps.

One valid provider key is enough to start using TowerScout. Provider keys for
the V1 RC1 pilot must be site/user-owned and restricted. Browser map SDK keys
are visible to someone who can access the running browser app, so do not use an
unrestricted shared TowerScout project key.

## 7. Confirm Success

Run:

```powershell
.\scripts\status.cmd
```

If you started with an explicit engine, use the same engine:

```powershell
.\scripts\status.cmd -Engine podman
```

Expected readiness states:

- `setup_required`: TowerScout is running, but provider setup is not complete.
- `degraded`: TowerScout is running, but assets or another recoverable
  capability are missing.
- `ready`: provider setup and required assets are present.
- `fatal`: TowerScout cannot safely serve the app; collect support evidence.

For a small smoke check, open TowerScout, choose a provider, define a small
search area, select `Estimate tiles`, then run `Find towers` only for a small
area that is appropriate for your pilot.

## 8. Stop Or Restart

Stop TowerScout:

```powershell
.\scripts\stop.cmd
```

Start again:

```powershell
.\start.bat
```

Provider setup and imported assets are stored in named volumes and should
survive container restarts and replacement.

## 9. Source, Licenses, And Help

The YOLO-enabled V1 RC1 package/image is not Apache-2.0-only. It is distributed
with AGPL-3.0 obligations because it includes Ultralytics YOLOv5 runtime source
and YOLO-derived detector weights.

Find release notices in the package:

- `LICENSE`
- `NOTICE`
- `THIRD_PARTY_NOTICES.md`
- `MODEL_LICENSES.md`
- `DATA_LICENSES.md`
- `PROVIDER_TERMS.md`
- `SOURCE.txt`
- `SBOM.txt`
- `release-manifest.v1.json`

When TowerScout is running, Settings includes Resource Links for Project
Overview, User Guide, Source/licenses, Video Guides, and the research article.
The source/license notice is also available at:

```text
http://localhost:5000/license
```

## 10. If Something Fails

Run:

```powershell
.\scripts\status.cmd
.\scripts\logs.cmd -Tail 200
```

Use the same `-Engine` value on status/log commands if support asked you to
start with a specific engine.

Do not share `.env`, provider keys, raw screenshots, raw browser network
traces, cached provider responses, uploaded investigation files, exported
datasets, named-volume contents, or unreviewed raw logs unless your site has an
approved support-handling procedure.
