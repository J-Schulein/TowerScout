# TowerScout Project Overview

TowerScout is a local web application for identifying likely cooling towers
from satellite and aerial imagery. Cooling towers can be relevant during
Legionnaires' disease outbreak investigations and registry-building work.

This document is the package-local V1 RC1 project overview used by the running
app Resource Links section.

## What The V1 RC1 Package Provides

The V1 RC1 package provides a Windows-first local pilot path:

- A GitHub Release control ZIP.
- A pinned GHCR container image digest.
- Docker-compatible / OCI-compatible Compose runtime configuration.
- Windows launch, stop, status, log, asset import, and TLS CA helper scripts.
- Package-local docs.
- Source, license, provider, model, data, SBOM, and release-manifest notices.
- A separate asset bundle contract for model weights and ZIP-code data.

The normal pilot path is package-based. Source checkout, Python virtual
environment, and Conda setup guides are legacy/source-install support material,
not the preferred V1 RC1 pilot path.

## Main Workflow

A typical TowerScout user:

1. Starts TowerScout from `start.bat` to initialize the package.
2. Imports required model and ZIP-code assets.
3. Configures Google Maps or Azure Maps in Setup Wizard or Settings.
4. Chooses a provider.
5. Defines a search area.
6. Estimates tile count.
7. Runs detection.
8. Reviews detections and adds manual corrections.
9. Exports CSV, KML, or dataset results.

The User Guide is available in the running app Resource Links section and at:

```text
http://localhost:5000/docs/towerscout-user-guide.md
```

## Release Boundary

The V1 RC1 supported target is:

- Windows 11 AMD64.
- Single-user local use.
- CPU baseline.
- Normal outbound internet access.
- Docker-compatible or OCI-compatible runtime with Compose support.
- One site/user-owned restricted Google Maps or Azure Maps provider key.

Out of scope for V1 RC1: macOS, ARM64, air-gapped/offline installs, VDI,
shared multi-user hosting, managed remote deployment, and native installer
behavior.

## Provider Keys

TowerScout uses Google Maps or Azure Maps browser SDKs. Browser map SDK keys
are visible to someone with access to the running browser app. For V1 RC1,
provider keys are expected to be site/user-owned and restricted. Unrestricted
shared TowerScout project keys are unsupported.

Users and sites should configure provider-side restrictions, API/service
scoping, quotas, billing alerts, monitoring, and key rotation according to
local policy.

## License And Source

The YOLO-enabled V1 RC1 package/image is not Apache-2.0-only. It is distributed
with AGPL-3.0 obligations because it includes Ultralytics YOLOv5 runtime source
and YOLO-derived detector weights.

The release package includes:

- `LICENSE`
- `NOTICE`
- `THIRD_PARTY_NOTICES.md`
- `MODEL_LICENSES.md`
- `DATA_LICENSES.md`
- `PROVIDER_TERMS.md`
- `SOURCE.txt`
- `SBOM.txt`
- `release-manifest.v1.json`

When TowerScout is running, the local source/license notice is available at:

```text
http://localhost:5000/license
```

## Research Article And Videos

Research article:

```text
https://www.sciencedirect.com/science/article/pii/S2589750024000943?via%3Dihub
```

Video guides:

```text
https://www.youtube.com/@thaddeussegura8452/videos
```
