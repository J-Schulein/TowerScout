# TASK-071: End-User Release Package Documentation

**Status**: COMPLETED - focused validation passed; ready for TASK-066
**Priority**: CRITICAL  
**Type**: B/C (Documentation / User Enablement)  
**Estimated Effort**: 1-2 days (8-16 hours)  
**Target Sprint**: Sprint 06 V1 RC1  

## Objective

Produce package-based end-user documentation for the TowerScout V1 RC1 `agpl-yolo` release track so a non-technical Windows pilot user can download the release package, place/import required assets, start TowerScout, complete first-run setup, find source/license notices, validate success, understand the main TowerScout workflow, and report problems without project tribal knowledge.

This task should replace or clearly distinguish older source/Conda tester guidance from the V1 RC1 package path. It should also make end-user docs discoverable from the Settings screen's Resource Links section, including package-local Project Overview and User Guide docs where practical.

## Requirements (EARS Notation)

**R-071-001**: WHEN a pilot user receives the V1 RC1 release package, THE DOCUMENTATION SHALL explain what files to download and where to extract them.

**R-071-002**: WHEN required assets are supplied separately, THE DOCUMENTATION SHALL explain the asset bundle layout, placement, import command, and verification expectations defined by `TASK-072`.

**R-071-003**: WHEN a user starts TowerScout for the first time, THE DOCUMENTATION SHALL explain how to run `start.bat`, what readiness states mean, and when the browser should open.

**R-071-004**: WHEN no provider key is configured, THE DOCUMENTATION SHALL explain how to use Setup Wizard or Settings to configure at least one supported map provider.

**R-071-005**: WHEN launch or setup fails, THE DOCUMENTATION SHALL tell users what status/log/preflight evidence to collect and what information not to share.

**R-071-006**: WHEN a user's environment includes Docker, Podman, Compose provider, TLS inspection, restricted network, or asset issues, THE DOCUMENTATION SHALL route the user to the appropriate supported V1 RC1 guidance or clearly state the limitation.

**R-071-007**: WHEN older source-install tester guides remain in the repo, THE DOCUMENTATION SHALL make clear whether they are legacy/source-install guidance and not the preferred V1 RC1 pilot package path.

**R-071-008**: WHEN the package docs describe the YOLO-enabled release, THE DOCUMENTATION SHALL state that the package/image is distributed with AGPL-3.0 obligations and is not Apache-2.0-only.

**R-071-009**: WHEN users need source or license information, THE DOCUMENTATION SHALL point to the package compliance files and the running app `/license` page.

**R-071-010**: WHEN a user opens Settings, THE APPLICATION SHALL expose source/license notices from the Resource Links section rather than as a separate main-page footer link.

**R-071-011**: WHEN a user opens Settings Resource Links, THE APPLICATION SHALL link Project Overview to a user-safe package-local project overview document for V1 RC1 unless a later clean-repo/public-site transition provides an approved public URL.

**R-071-012**: WHEN a user opens Settings Resource Links, THE APPLICATION SHALL link Video Guides to `https://www.youtube.com/@thaddeussegura8452/videos` and remove placeholder wording.

**R-071-013**: WHEN a user opens Settings Resource Links, THE APPLICATION SHALL link TowerScout Research Article to `https://www.sciencedirect.com/science/article/pii/S2589750024000943?via%3Dihub` and remove placeholder wording.

**R-071-014**: WHEN a user needs workflow help, THE DOCUMENTATION SHALL include a general User Guide that explains the main TowerScout workflow from setup through export/restore, including provider selection, search area definition, tile estimate, detection, review, manual corrections, and saving results.

**R-071-015**: WHEN the User Guide explains drawing workflows, THE DOCUMENTATION SHALL clearly distinguish drawing custom search areas from adding manual tower detections and SHALL document provider-specific polygon completion behavior: Azure Maps uses double-click to complete the polygon and Google Maps uses right-click to complete the polygon.

**R-071-016**: WHEN setup docs explain provider keys, THE DOCUMENTATION SHALL state what API configuration is required for successful use, including that one valid Google Maps or Azure Maps key is enough to start, Google keys must support the app's Maps JavaScript, Places/autocomplete, Static Maps imagery, and Geocoding usage, and Azure Maps subscription keys must support the app's Web SDK, imagery, and search/geocoding usage.

**R-071-017**: WHEN setup docs explain provider key safety, THE DOCUMENTATION SHALL incorporate the `TASK-076` policy: browser map SDK keys are client-visible, V1 RC1 assumes site/user-owned restricted keys, unrestricted shared project keys are unsupported, and users/sites should configure provider-side restrictions, quotas, billing alerts, monitoring, and rotation.

## Acceptance Criteria

- [x] A one-page V1 RC1 quick start exists for Windows 11 AMD64 pilot users.
- [x] A fuller V1 RC1 package guide exists for first-line support and testers.
- [x] The docs explain release package download/extraction, asset placement/import, launch, first-run setup, validation, stop/restart, troubleshooting, and issue reporting.
- [x] The docs include sensitive-data handling guidance for `.env`, provider keys, logs, cached provider responses, uploaded files, and exported datasets.
- [x] The docs reflect the `TASK-072` asset bundle contract.
- [x] The docs reflect the `TASK-069` AGPL-compliant YOLO release posture.
- [x] The docs tell users where to find `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `MODEL_LICENSES.md`, `DATA_LICENSES.md`, `PROVIDER_TERMS.md`, `SOURCE.txt`, `SBOM.txt`, and `release-manifest.v1.json`.
- [x] The docs reflect current Podman/Docker support language from `TASK-065`.
- [x] The docs state the V1 RC1 support boundary, including CPU baseline and supported Windows target.
- [x] Older source/Conda testing guides are marked or linked in a way that avoids confusing pilot package users.
- [x] `TASK-066` can use these docs as the only user-facing instructions for clean-machine validation.
- [x] A package-local Project Overview exists or an explicit approved public clean-repo/site URL is documented as the target.
- [x] A general User Guide exists and covers the end-to-end workflow, including custom search areas, manual tower detections, Azure double-click polygon completion, and Google right-click polygon completion.
- [x] Setup docs include provider API configuration guidance for Google Maps and Azure Maps, including required API capabilities and key safety caveats.
- [x] Setup docs include the `TASK-076` V1 RC1 key-ownership policy and state that unrestricted shared project keys are unsupported.
- [x] Settings Resource Links are updated to include Project Overview, User Guide, Source/licenses, Video Guides, and TowerScout Research Article without placeholder wording.
- [x] Release package and runtime image packaging include any package-local docs needed by Resource Links.

## Dependencies

- `TASK-069`: AGPL-compliant YOLO release posture and compliance payload.
- `TASK-072`: release asset bundle contract.
- `TASK-065`: release support language and runtime support caveats.
- `docs/oci-quick-start.md`: current OCI quick-start baseline.
- `docs/oci-runtime-contract.md`: current runtime contract.
- `docs/release-asset-bundle-contract.md`: `TASK-072` asset bundle contract.
- `webapp/templates/towerscout.html`: current Settings Resource Links and main-page source/license link location.
- `webapp/towerscout.py`: current `/license` route and any package-local documentation route needed for Resource Links.
- `scripts/package-release.ps1` and `Dockerfile`: release package/image inclusion points for package-local docs.
- `TASK-076`: provider API key exposure and restriction policy, for approved V1 RC1 key-safety language.
- `.agent_work/context/guides/TowerScout_User_Testing_Guide.txt`: older source/venv tester guide to reconcile or label.
- `.agent_work/context/guides/TowerScout_User_Testing_Guide_Windows_Miniconda.txt`: older source/Conda tester guide to reconcile or label.

## Implementation Plan

1. Review existing OCI docs and older user-testing guides.
2. Decide where V1 RC1 package docs should live, favoring `docs/` for release-package docs and `.agent_work/context/guides/` for internal tester/support handoff if needed.
3. Draft `docs/v1-rc1-quick-start.md` as the one-page quick start for pilot users.
4. Draft `docs/v1-rc1-package-guide.md` as the full package guide for support/testers.
5. Draft `docs/towerscout-user-guide.md` as the general end-user workflow guide, including:
   - choosing Google Maps or Azure Maps
   - address, ZIP, circle, and custom-shape searches
   - using Estimate tiles before Find towers
   - reviewing detections and deselecting false positives
   - adding manual tower detections after a detection run
   - the difference between custom search polygons and manual tower polygons
   - Azure Maps double-click polygon completion
   - Google Maps right-click polygon completion
   - exporting CSV/KML and dataset archives
   - restoring a previous dataset
6. Draft `docs/project-overview.md` as a user-safe V1 RC1 project overview. Treat this package-local file as the near-term Settings link target; a later clean-repo or public-site transition may replace it with an approved public URL.
7. Integrate the `TASK-069` AGPL release posture and `TASK-072` asset bundle contract.
8. Add setup guidance for provider API keys, including supported provider choices, required Google Maps/Azure Maps capabilities, `DEFAULT_MAP_PROVIDER`, and the `TASK-076` provider-key policy:
   - browser map SDK keys are client-visible to users with access to the running app
   - V1 RC1 assumes site/user-owned provider keys
   - unrestricted shared TowerScout project keys are unsupported unless separately owner-approved and risk-accepted
   - users/sites should configure provider-side application/API restrictions, quotas, billing alerts, usage monitoring, and rotation
   - Google guidance should recommend separate restricted keys where practical and require application/API restrictions for TowerScout-used APIs
   - Azure guidance should describe shared-key rotation/monitoring for the local pilot and note Entra ID or SAS-token authentication as broader-distribution hardening options, not V1 RC1 setup requirements
9. Add troubleshooting and issue-report guidance aligned with `.agent_work/user-testing/`.
10. Update Settings Resource Links:
    - move `Source/licenses` into Resource Links as a `/license` link
    - link Project Overview to the package-local overview doc
    - link User Guide to the package-local workflow guide
    - link Video Guides to `https://www.youtube.com/@thaddeussegura8452/videos`
    - link TowerScout Research Article to `https://www.sciencedirect.com/science/article/pii/S2589750024000943?via%3Dihub`
    - remove placeholder wording and use `rel="noopener"` for external links
11. Add a read-only package-local docs serving route if needed so Settings links work from the running container, and include linked docs in the release package/runtime image packaging.
12. Mark older source/Conda tester guides as legacy/source-install guidance if they remain.
13. Hand off the docs to `TASK-066` for clean-machine validation.

---

## Implementation Log

### 2026-05-11 - Task Created
**Objective**: Create detailed Sprint 06 task documentation for end-user release package documentation.  
**Context**: Sprint 06 planning identified that broad end-user testing should wait until package docs and asset instructions are clear. Existing tester guides target source/Conda flows and do not represent the V1 RC1 release package path.  
**Decision**: Keep this task focused on package-based user documentation, with source-install guidance treated as legacy/support material unless explicitly needed.  
**Execution**: Created `.agent_work/tasks/active/TASK-071-end-user-release-docs.md` and synchronized the task with `current-tasks.md`.  
**Output**: Task file ready for intake.  
**Validation**: Pending `.agent_work` validation after all Sprint 06 task files are created.  
**Next**: Start documentation inventory and draft the V1 RC1 quick start against the `agpl-yolo` compliance payload and completed asset contract.

### 2026-05-14 - Scope Refinement For Resource Links And User Workflow Docs
**Objective**: Incorporate additional Task-071 requirements for Settings Resource Links, Project Overview, Video Guides, the research article link, User Guide coverage, and provider API-key setup guidance.
**Context**: Review of `webapp/templates/towerscout.html` showed the Settings Resource Links section currently contains placeholder links, while the source/license link is a separate main-page footer link. The existing Task-071 scope covered package setup and support docs but did not explicitly require a general user workflow guide or in-app doc discoverability.
**Decision**: Expand Task-071 to include package-local Project Overview and User Guide docs, update Settings Resource Links during implementation, and treat the clean public repo/site as a later opportunity to replace package-local doc links rather than a blocker for V1 RC1.
**Execution**: Added requirements `R-071-010` through `R-071-016`, expanded acceptance criteria, added app/template/packaging dependencies, and updated the implementation plan with Resource Links and User Guide work.
**Output**: Task-071 now covers release package docs, general workflow docs, provider setup guidance, and in-app documentation/resource link discoverability.
**Validation**: Pending `.agent_work` validation after this documentation update.
**Next**: Implement Task-071 docs and Resource Links changes, then validate the package docs path for `TASK-066`.

### 2026-05-14 - Task-076 Provider-Key Policy Plan Alignment
**Objective**: Verify whether the recorded Task-076 provider-key exposure policy requires a Task-071 plan update.
**Context**: `TASK-076` now records the V1 RC1 policy that browser map SDK keys are client-visible, pilot keys must be site/user-owned and restricted, unrestricted shared TowerScout project keys are unsupported, and provider-side quotas, billing alerts, monitoring, and rotation are required mitigations.
**Decision**: Keep `TASK-071` as the documentation integration point and tighten its provider-key setup plan so the approved policy is not left as a generic key-safety caveat.
**Execution**: Updated implementation plan step 8 with the concrete `TASK-076` policy topics that must appear in the quick start, package guide, and user guide.
**Output**: Task-071 now has explicit implementation-plan coverage for the provider-key policy expected by `TASK-076`.
**Validation**: Pending `.agent_work` validation after this plan update.
**Next**: Draft the V1 RC1 docs with the approved provider-key policy language and hand the assumption to `TASK-066` validation.

### 2026-05-15 - V1 RC1 Docs And Resource-Link Integration Started
**Objective**: Implement the Task-071 package documentation set and make it discoverable from the running V1 RC1 app/package.
**Context**: The existing Settings Resource Links still pointed to placeholder project/documentation/video URLs, `/license` was exposed as a separate footer link, and package/image assembly only carried the older OCI docs.
**Decision**: Keep the user-facing docs in package-local `docs/` files for V1 RC1, serve them read-only from `/docs/`, and keep legacy source/Conda tester guides in `.agent_work/context/guides/` with explicit legacy notices.
**Execution**: Drafted the V1 RC1 quick start, package guide, user guide, and project overview; updated Settings Resource Links to Project Overview, User Guide, Source/licenses, Video Guides, and TowerScout Research Article; added the local docs route; added the docs to release package and image assembly; and marked the older source/Conda guides as legacy source-install guidance.
**Output**: Package-local V1 RC1 docs and app/package integration are ready for focused validation.
**Validation**: Pending focused unit tests, doc command checks, agent-work validation, and sensitive-term scan.
**Next**: Run focused validation, address findings, then update acceptance status for handoff to `TASK-066`.

### 2026-05-15 - Focused Validation Passed
**Objective**: Validate the Task-071 docs, in-app Resource Links, package inclusion, and task-tracking updates.
**Context**: The implementation adds package-local docs, a `/docs/` serving route, release package/image inclusion, Settings Resource Links, and focused route/license/package tests.
**Decision**: Treat Task-071 as complete for the documentation and app/package integration scope, with clean-machine execution deferred to `TASK-066`.
**Execution**: Ran focused pytest suites for route/license/package coverage and provider-secret/config safety, agent-work validation, docs command scanning, and sensitive-term scanning.
**Output**: Focused validation passed. The docs are ready to hand to `TASK-066` as the user-facing clean-machine validation instructions.
**Validation**:
- `.venv\Scripts\python.exe -m pytest tests\unit\test_flask_routes.py tests\unit\test_license_notices.py tests\unit\test_release_package_script.py -q -p no:cacheprovider` passed: 27 passed, 1 existing `datetime.utcnow()` deprecation warning.
- `.venv\Scripts\python.exe -m pytest tests\unit\test_config.py tests\unit\test_error_sanitization.py tests\unit\test_flask_routes.py -q -p no:cacheprovider` passed: 34 passed, 13 existing `datetime.utcnow()` deprecation warnings.
- `.venv\Scripts\python.exe .agent_work\scripts\validate_agent_work.py` passed.
- `.venv\Scripts\python.exe .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .` passed.
- `.venv\Scripts\python.exe .agents\skills\towerscout-end-user-docs-check\scripts\check_doc_commands.py . docs README.md` completed with one non-blocking warning for an existing `127.0.0.1` health/readiness reference in `docs/oci-quick-start.md`; user-facing browser instructions use `localhost`.
- `.venv\Scripts\python.exe .agents\skills\towerscout-secret-and-provider-key-safety\scripts\scan_for_sensitive_terms.py` completed. Matches were expected environment-variable/code references plus ignored local env/config files; no new tracked Task-071 docs introduced provider secrets.
**Next**: Use these docs during `TASK-066` clean-machine release-candidate validation and record any user-facing friction as validation findings.

### 2026-05-15 - Documentation Clarity Pass
**Objective**: Re-review the Task-071 docs for first-run ordering, engine consistency, and pilot-user clarity.
**Context**: A second pass compared the docs against `scripts/launch.ps1`, `scripts/import-assets.ps1`, `scripts/lib/TowerScoutCompose.ps1`, `compose.yaml`, `.env.example`, and the asset bundle contract.
**Decision**: Tighten the first-run sequence and helper-command guidance rather than changing release scripts in this docs-focused pass.
**Execution**: Updated quick start, package guide, user guide, project overview, OCI quick start, and runtime contract language to state that users should run `.\start.bat` once before asset import so `.env` is created from the release `.env.example`, and that explicit engine selection must be reused for start, asset import, status, logs, and stop because Docker and Podman use separate named volumes.
**Output**: The docs now make first-run initialization, asset import, and engine-specific volume behavior explicit.
**Validation**:
- `.venv\Scripts\python.exe .agents\skills\towerscout-end-user-docs-check\scripts\check_doc_commands.py . docs README.md` completed with the same non-blocking `127.0.0.1` warning for an internal health/readiness reference in `docs/oci-quick-start.md`.
- `.venv\Scripts\python.exe -m pytest tests\unit\test_flask_routes.py tests\unit\test_license_notices.py tests\unit\test_release_package_script.py -q -p no:cacheprovider` passed: 27 passed, 1 existing `datetime.utcnow()` deprecation warning.
- `.venv\Scripts\python.exe .agent_work\scripts\validate_agent_work.py` passed.
- `.venv\Scripts\python.exe .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .` passed.
- `git diff --check` passed.
**Next**: Use the revised docs during `TASK-066` clean-machine validation and record any real-user friction there.

### 2026-05-15 - Settings Resource Link HTML Pass
**Objective**: Make the package-local Settings Resource Link docs open as polished web pages instead of raw Markdown.
**Context**: Manual review of the Settings Resource Links showed that the local Project Overview and User Guide opened as plain Markdown files, which was accurate but did not match the in-app presentation quality expected for pilot users.
**Decision**: Keep the Markdown files as support/package source docs, add static HTML views plus a package-local stylesheet, and point Settings to the HTML files.
**Execution**: Added `docs/project-overview.html`, `docs/towerscout-user-guide.html`, and `docs/towerscout-docs.css`; updated Settings Resource Links to the HTML files; updated release package inclusion and focused tests; and kept `/license`, video guides, and the research article links unchanged.
**Output**: The two package-local Settings docs now open as styled HTML pages while the Markdown sources remain available.
**Validation**:
- `.venv\Scripts\python.exe -m pytest tests\unit\test_flask_routes.py tests\unit\test_license_notices.py tests\unit\test_release_package_script.py -q -p no:cacheprovider` passed: 27 passed, 1 existing `datetime.utcnow()` deprecation warning.
- `.venv\Scripts\python.exe .agents\skills\towerscout-end-user-docs-check\scripts\check_doc_commands.py . docs README.md` completed with the existing non-blocking `127.0.0.1` warning for an internal health/readiness reference in `docs/oci-quick-start.md`.
- `.venv\Scripts\python.exe .agent_work\scripts\validate_agent_work.py` passed.
- `git diff --check` passed.
**Next**: Use these HTML pages during `TASK-066` clean-machine validation and record any visual or usability friction there.

### 2026-05-15 - Source/License HTML Pass
**Objective**: Make the Settings `Source/licenses` link open as a styled HTML page consistent with the package-local docs.
**Context**: After the Project Overview and User Guide were converted to styled HTML views, the `/license` Resource Link still opened as raw plain text.
**Decision**: Render `/license` as HTML while keeping `/license.txt` as a plain-text combined notice fallback for support and copy/paste workflows.
**Execution**: Updated the Flask `/license` route to load the same compliance notice payload into escaped HTML sections, added `/license.txt`, reused `docs/towerscout-docs.css`, and extended focused route tests.
**Output**: Settings `Source/licenses` now opens a styled source/license page and still exposes raw combined notices at `/license.txt`.
**Validation**:
- `.venv\Scripts\python.exe -m pytest tests\unit\test_flask_routes.py tests\unit\test_license_notices.py tests\unit\test_release_package_script.py -q -p no:cacheprovider` passed: 27 passed, 1 existing `datetime.utcnow()` deprecation warning.
- `.venv\Scripts\python.exe .agents\skills\towerscout-end-user-docs-check\scripts\check_doc_commands.py . docs README.md` completed with the existing non-blocking `127.0.0.1` warning for an internal health/readiness reference in `docs/oci-quick-start.md`.
- `.venv\Scripts\python.exe .agent_work\scripts\validate_agent_work.py` passed.
- `git diff --check` passed.
**Next**: Use the styled source/license page during `TASK-066` clean-machine validation and record any visual or usability friction there.

### 2026-05-15 - Quick Start HTML Pass
**Objective**: Make the Quick Start linked from the HTML User Guide open as a styled HTML page.
**Context**: The HTML User Guide footer still linked to the raw `docs/v1-rc1-quick-start.md` source file.
**Decision**: Keep the Markdown quick-start source, add a styled `docs/v1-rc1-quick-start.html` view, and make `/docs/` open the HTML quick start by default.
**Execution**: Added `docs/v1-rc1-quick-start.html`, updated the User Guide footer link, updated `/docs/`, release package inclusion, package contract docs, and focused tests.
**Output**: Quick Start now has a package-local HTML view matching the Project Overview, User Guide, and Source/licenses pages.
**Validation**:
- `.venv\Scripts\python.exe -m pytest tests\unit\test_flask_routes.py tests\unit\test_license_notices.py tests\unit\test_release_package_script.py -q -p no:cacheprovider` passed: 27 passed, 1 existing `datetime.utcnow()` deprecation warning.
- `.venv\Scripts\python.exe .agents\skills\towerscout-end-user-docs-check\scripts\check_doc_commands.py . docs README.md` completed with the existing non-blocking `127.0.0.1` warning for an internal health/readiness reference in `docs/oci-quick-start.md`.
- `.venv\Scripts\python.exe .agent_work\scripts\validate_agent_work.py` passed.
- `git diff --check` passed.
**Next**: Use the styled quick start during `TASK-066` clean-machine validation and record any visual or usability friction there.

---

## Validation Results

### Test Summary
**Test Date**: 2026-05-15
**Test Environment**: Windows PowerShell, repo `.venv` Python
**Test Status**: PASSED_WITH_WARNINGS

### Acceptance Criteria Validation
- [x] Quick start created - PASSED
- [x] Full package guide created - PASSED
- [x] Asset contract integrated - PASSED
- [x] AGPL release posture and source/license notice location integrated - PASSED
- [x] Troubleshooting guidance included - PASSED
- [x] Older guides reconciled or labeled - PASSED
- [x] Project Overview created or approved public target documented - PASSED
- [x] User Guide created with workflow and drawing guidance - PASSED
- [x] Provider API key setup requirements documented - PASSED
- [x] Task-076 provider-key ownership/restriction policy documented - PASSED
- [x] Settings Resource Links updated and verified - PASSED
- [x] Package-local docs included in release package/runtime image where needed - PASSED

### Issues Identified

- The docs command checker reports one existing `127.0.0.1` reference in `docs/oci-quick-start.md`. This is a low-level health/readiness reference and not the main user browser URL.
- Pytest reports existing `datetime.utcnow()` deprecation warnings in route/config/error timestamp code.
- Sensitive-term scanning reports existing ignored local env/config files with real-looking provider and Flask values. These files are not tracked and were not introduced by Task-071.

### Remediation Actions

- No Task-071 remediation required. `TASK-066` should use the new docs as written and record any clean-machine friction.
- Keep ignored local env/config files out of release evidence and support handoff material.

### Sign-off

Ready for `TASK-066` release-candidate validation.
