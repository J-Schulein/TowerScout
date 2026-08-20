# Task Backlog - October 2026 Roadmap

**Last Updated**: August 20, 2026
**Planning State**: Fix first while the immutable `v0.1.2` pilot remains in
use. Refine immutable unsigned `v0.1.3-preview.N` GitHub prereleases until the
normal-user package is satisfactory, then complete Task-100 production signing
and managed-endpoint qualification in October. Task-099's scoped August gate
and Task-101's PR #72/default-branch gates passed; current `main` is now
integrated into PR #67, and Task-087 remains paused until that branch's new
exact head passes. Required release and handoff work takes priority over
Task-058/059 stretch work.
**Hard End**: October 31, 2026; operational closeout October 30

---

## Required Roadmap Work

| Order | Task | Status | Estimate | Dependencies | Required outcome |
| ---: | --- | --- | --- | --- | --- |
| 1 | `TASK-096` User-Initiated Exit And Container Stop | NOT_STARTED | 2-4 days | Task-087 helper/security pattern; current stop scripts | Confirmed Exit/Stop works on Docker and Podman without deleting named volumes |
| 2 | `TASK-097` Podman CPU/GPU Final Path Qualification | NOT_STARTED | 3-5 days plus environment validation | Tasks 090, 098, 099, 101, 087, and 096 | Podman CPU and GPU/CDI pass final-package qualification without Docker Desktop |
| 3 | `TASK-091` Owner-Runnable Release Qualification | NOT_STARTED | 3-6 days | Stable unsigned package/preview shape; fixture/harness custody | Preview-based harness and custody rehearsal are ready for Task-100; signed acceptance completes under Task-100 |
| 4 | `TASK-092` Documentation Currentness And Information Architecture | NOT_STARTED | Stage A 1-2 days; Stage B as approved | Stable unsigned package behavior and shape | Repo docs, user docs, release notes, external Setup Guide, and demo video agree |
| 5 | `TASK-093` Persistent Data Lifecycle And Recovery Rehearsal | NOT_STARTED | 1-2 days minimum | Runtime profiles and package lifecycle stable | Safe owner-run upgrade, rollback, cleanup, and recovery procedure |
| 6 | `TASK-100` Production Signing And Managed-Endpoint Qualification | NOT_STARTED | 3-5 days plus signer/endpoint scheduling | October; Task-101 security gate clear; satisfactory unsigned preview recorded; stable source/package shape from Tasks 087/096/097; Tasks 091-093 release, docs, and lifecycle prerequisites ready; approved signer and endpoint window | Signed `v0.1.3-rc.N` verifies after packaging and passes representative managed-endpoint acceptance |
| 7 | `TASK-094` Evidence-Gated Support Snapshot | EVIDENCE_GATED | 1-3 days if selected | Pilot/support evidence | Implement only if real feedback shows a support-diagnostics gap |

### Task-096 Boundary

- If the Task-087 launcher proof passes, reuse its fixed-target confirmation,
  runtime validation, sanitized state, and recovery pattern for Stop; otherwise
  retain the current user-run stop path and re-plan the UX.
- Use a secured, equally constrained host mechanism without browser-supplied
  command text or runtime sockets.
- Support Docker and Podman.
- Require confirmation.
- Preserve named volumes.
- Do not expose runtime sockets or arbitrary commands to the browser.

### Task-097 Boundary

- Qualify Podman CPU and Podman GPU as supported final paths.
- Cover the approved Compose-provider installer and manual fallback.
- Cover setup, start, readiness, providers, detection, assets, persistence,
  status, logs, TLS repair, Exit/Stop, and cleanup.
- Investigate Podman-machine image-pull and source-build TLS separately from
  Task-087.
- Fix packaged-runtime blockers. Document a source-build-only limitation only
  through an explicit owner decision.

### Task-091 Boundary

- Build and rehearse the minimum owner-runnable qualification harness against
  the stable unsigned package/preview shape before Task-100.
- Confirm fixture, evidence, and operator custody without calling the unsigned
  package a signed candidate or managed-endpoint-qualified release.
- Reuse the same bounded harness for the signed `v0.1.3-rc.N` acceptance run
  under Task-100; that signed run, not the preview rehearsal, closes final
  candidate acceptance.

### Task-092 Boundary

- Add administrator instructions for the opt-in Model Upload Key before the
  final documentation freeze.
- Cover secure key generation, private storage, enable/disable behavior,
  rotation, the approved SHA-256 allowlist, adding a new approved model, and
  troubleshooting rejected uploads.
- Make clear that normal users do not need the key, the upload feature remains
  disabled by default, and the key must never be committed, logged, placed in
  screenshots, or included in support artifacts.
- Explain that loopback publication blocks other physical devices by default,
  while another locally controlled Docker Desktop container can reach the host
  proxy and is still denied without the key.

### Task-100 Boundary

- Do not select Task-100 before October 1 or before the project lead records
  that the unsigned normal-user package satisfies ADR-019's entry gate.
- Consume the stable qualification harness/custody baseline from Task-091
  without making Task-091's preparation circular; final signed acceptance
  completes under Task-100.
- Confirm the approved signer/operator, service, certificate/key custody,
  timestamping, renewal/revocation, and backup ownership without storing
  secrets or sensitive certificate identifiers in the repository.
- Decide which launcher, installer, executable, and script surfaces in the
  normal user path require signing. Remove, redesign, or explicitly disposition
  endpoint-policy-incompatible execution-policy bypass behavior.
- Build from the accepted clean source, sign and timestamp before final ZIP
  assembly, and regenerate manifests/checksums from the signed bytes.
- Verify signatures before packaging and after clean extraction. Qualify the
  signed package on an approved clean machine and representative managed
  endpoint without Defender/AMSI exclusions, execution-policy bypasses,
  unusual policy changes, or administrator-only normal setup.
- Publish the accepted signed package only as immutable `v0.1.3-rc.N` and keep
  official cdcai publication behind Task-089 authorization and identity
  selection.

---

## Conditional Architecture Work

| Order | Task | Status | Estimate | Start gate |
| ---: | --- | --- | --- | --- |
| 8 | `TASK-058` Background Detection Jobs And Durable Run State | CONDITIONAL | 3-5 days | Tasks 090, 098, 099, 101, 087, 096, and 097 pass; no pilot blocker; September 18 remains credible |
| 9 | `TASK-059` Backend Layer Decomposition And Logging Consolidation | CONDITIONAL | 3-5 days | Task-058 accepted and remaining schedule margin is still safe |

August 28 is the latest responsible Task-058 capacity checkpoint, not an
earliest start date. Task-058 may begin earlier when all gates pass.

---

## Existing Follow-On Backlog

| Priority | Task | Status | Recommended disposition |
| ---: | --- | --- | --- |
| 1 | `TASK-076` Provider API Key Exposure And Restriction Policy | NOT_STARTED | Reassess before final documentation/freeze; include provider-side restriction and ownership guidance |
| 2 | `TASK-068` Windows Test Portability And Script Validation | NOT_STARTED | Pull forward if Tasks 087, 096, or 097 expose repeatable script gaps |
| 3 | `TASK-077` Public Release Manifest And Asset Import Hardening | PARTIAL_FOLLOW_UP | Select only for a demonstrated manifest/import release gap |
| 4 | `TASK-070` Restricted-Network Package Enhancements | NOT_STARTED | Select only if final-package requirements expand beyond managed connected networks |
| 5 | `TASK-027` Enhanced Error Handling | NOT_STARTED | Use for confirmed user-facing error gaps that do not belong to required tasks |
| 6 | `TASK-026` CPU Optimization | NOT_STARTED | Defer unless measured final-candidate CPU performance becomes blocking |
| 7 | `TASK-029` Multi-Provider Fallback | NOT_STARTED | Defer until provider policy and error classification are stable |
| 8 | `TASK-060` Frontend Build Modernization | NOT_STARTED | Maintenance after final release unless current build becomes blocking |
| 9 | `TASK-078` Permissive Apache-Only Runtime Migration | NOT_STARTED | Future release track; not part of October closeout |

Parking lot:

- `TASK-028` Mobile Responsiveness
- `TASK-061` Coordinated NumPy 2 Runtime Migration
- Advanced filtering
- Performance dashboard
- Additional user preferences

---

## Active Elsewhere

| Task | Current state |
| --- | --- |
| `TASK-095` Governance And AI-Ready Handoff Foundation | Active in Sprint 09; Phase A complete, Phase B continues |
| `TASK-090` Runtime, Custom-Image, And Dependency Security Investigation | Completed; Task-098 scope approved |
| `TASK-098` Dependency Security Remediation And Release Gate | Completed July 27; PR #51 merged, main CI passed, and Dependabot reconciled at closeout to eight documented non-blocking torch advisories |
| `TASK-099` August Dependency Advisory Follow-Up | Completed in Sprint 09 on August 11; PRs #68/#69 merged as `f460445`/`0133b50`, main CI and root graph refresh passed, alert `#74` closed without dismissal, and its closeout inventory contained the eight documented torch residuals |
| `TASK-101` extract-zip Advisory Assessment And Release-Gate Disposition | Active exact-head gate; PR #72/default-branch remediation and PR #73 checkpoint passed, and current `main` through `9276084` is integrated into PR #67; the new exact-head matrix remains before completion |
| `TASK-087` Host-Side TLS Repair Control Plane | Paused / reconciliation-gated; PR #67 remains open for reviewer input, while new implementation, merge, and preview/candidate publication wait for green exact-head checks and the explicit resume transition |
| `TASK-089` cdcai Adoption And Ownership Transfer | Owner-gated; preparation only until Task-100 signed qualification, final owner qualification, and approval |

---

## Milestone Controls

| Date | Control |
| --- | --- |
| August 20 | PR #73/default-main checkpoint passed and current `main` was integrated into PR #67; exact-head validation remains before Task-101 completion and Task-087 resumption |
| August 20 | PR #72/default-branch security gates recorded as passed; PR #67 semantic reconciliation became the next Task-101 gate |
| August 19 | Task-087 Proceed-to-unsigned-preview decision recorded; production signing assigned to Task-100 |
| August 19 | Task-101 selected as the active high-severity alert `#76` gate; Task-087 implementation/package work paused while PR #67 remained reviewable |
| August 28 | Required scope and Task-058 capacity checkpoint |
| September 18 | Code complete |
| September 25 | Feature/documentation complete and satisfactory unsigned-package target |
| October 1 | Earliest Task-100 activation, only after the satisfactory-package decision |
| October 9 | Signed `v0.1.3-rc.N` content/candidate freeze |
| October 16 | Task-100 managed-endpoint qualification and acceptance complete |
| October 23 | Owner-operated handoff rehearsal complete |
| October 30 | Operational closeout |
| October 31 | Hard project end |
