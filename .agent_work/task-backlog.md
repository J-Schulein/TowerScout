# Task Backlog - October 2026 Roadmap

**Last Updated**: September 18, 2026
**Planning State**: Fix first while the immutable `v0.1.2` pilot remains in
use. Task-087 is active under its fixed nine-slice
[`Gate A burn-down`](./tasks/active/TASK-087/GATE-A-STATUS.md). Exact-head
validated checkpoint `6cc2a83` is green. Implementation checkpoint `1c59252`
composes the exact captured state through activated `rollback_armed`, stages
verified forward certificate candidates, and durably links exact provider
mini-journal progress into the forward chain. The remaining target/provider
mutation, runtime/terminal transitions, cleanup, legacy transaction replacement,
and live proof remain open.
Exact-head
validated implementation checkpoint `299ae96` promotes only the exact
authenticated pointer temp after source and prior-destination verification and
requires exact completed-move evidence. Exact-head validated checkpoint
`53b618b` removes only the authenticated planned-state zero-byte orphan by its
verified held handle. Exact-head validated checkpoint `d6ce415` adds encrypted,
purpose-separated exact-state environment and fixed-certificate backup
envelopes bound to the journal stream. Exact-head validated checkpoint
`1ecfd5e` adds authenticated singleton `backup_preparing` intent with two
independent unpredictable future blob names and exact prior-state summaries.
Exact-head validated checkpoint `21aba57` reloads that durable authority under
the held protected root and creates and fully verifies only the two planned
DPAPI ciphertext blobs while preserving every ambiguous artifact.
Exact-head validated checkpoint `92acf29` reauthenticates and freshly reverifies
both exact blobs under the same held-root interval before persisting and
reauthenticating `backup_verified` with stable identities, ciphertext hashes,
and sizes. Exact-head validated checkpoint `deee6ab` reconstructs both expected
receipts only from that authenticated chain, freshly reverifies both exact
blobs under one held-root interval, and appends and reauthenticates generation
3 `rollback_armed`. Exact-head validated checkpoint `7b96a6b` reloads exactly
that chain, freshly reverifies both exact blobs under one held-root interval,
and repairs the metadata pointer to the exact armed tip. Already-current
activation is idempotent and failed pointer writes are safely retryable. It
does not authorize recovery, cleanup, `.env` replacement, certificate writes,
repair, or runtime mutation.
Exact-head validated checkpoint `b12280d` adds fresh-process rollback admission
from that armed state. It accepts only the authenticated three- or four-
generation chain, derives both expected backup receipts only from durable
records, reverifies both blobs under one held root, selects generation 3 before
append, and persists and selects generation 4 `rollback_started` at most once.
Retry repairs only the started pointer; no restore, cleanup, `.env`
replacement, certificate write, repair, or runtime mutation is enabled.
Exact-head validated checkpoint `56ba458` reads and authenticates both exact
encrypted backups under one held protected-root interval and durably records
generation 5 `environment_restore_temp_planned`. It binds the exact original
state and either one unpredictable restore-temp name or secure absence; retry
repairs only the exact planned pointer without another append or name. It
creates or restores no file and enables no cleanup, repair, or runtime mutation.
Independently reviewed and exact-head validated checkpoint `a37cf8a` adds strict
generation-6 schema/native zero-byte temp storage and mandatory authenticated
cross-protocol recovery scanning before target-lock acquisition. Provider
pending blocks; repair pending is retained only as read-only evidence. The
remaining PR #67 path must be rebaselined against the fixed acceptance criteria,
with remaining recovery states/action, recovery/transaction integration,
provider `.env` hardening, and environment-dependent Windows revocation and
Docker/Podman proof as the principal uncertainties. Independently reviewed and
exact-head validated checkpoint `57e280e` now persists generation 6 at most
once after exact planned zero-byte creation or secure absence, and reverifies
the recorded identity before pointer repair on retry. Independently reviewed
checkpoints `1eb3363` and `d9f6563` then define and persist generation 7 after
exact authenticated original bytes are written only to that recorded temp and
verified on the same handle and after reopen. Retry performs no second write
and repairs only the exact generation-7 pointer; secure absence performs no
storage call. Exact-head CI/CD run `35238335037`, Task-087 run `35238334999`,
and Trivy pass; the main-only build is neutral as designed. `.env`
replacement/removal and later recovery/runtime mutation remain disabled.
Checkpoint `da09dff` also persists the selected provider and Windows-root
fingerprint in authenticated generation 1 so fresh-process recovery can rebuild
the original target-plan certificate identity without certificate bytes or a
new trust-selection call. Checkpoint `9b12645` then adds read-only absent-target
observation: it retains native authority, proves exact absence plus the pinned
image and all eight volumes twice, and re-derives the persisted rollback-runtime
authority without issuing a runtime command. Checkpoint `351c9a9` revalidates
that exact absence before one fixed volume-preserving prior-profile recreation,
keeps Docker and Podman in their required containment paths, and requires four
exact present captures to recover the original authority. Checkpoint `fd1ef6b`
connects the retained and recreated paths to the manager-facing runtime-
availability port with exact evidence and owner cleanup. Checkpoint `852a72c`
then restores exact authenticated certificate originals or removes exact repair
candidates through a retained, repeatedly revalidated native boundary.
Checkpoint `1a390b9` then re-creates only the exact `towerscout` service without
volume deletion and proves the new container against the original runtime and
all-volume authority. Checkpoint `515c1f5` binds authenticated pre-mutation
readiness/provider state and derives exact environment, certificate, runtime,
container, all-volume, and readiness authority for terminal verification.
Checkpoint `f298a3e` adds the native verifier with fresh exact local/runtime
observations, bounded readiness/provider probes, and fail-closed retained-target
ownership. Checkpoint `9d7f533` adds the separate authenticated forward repair
journal, binds it to the exact armed rollback generation, and retains its exact
provider mini-journal through restart. Checkpoint `8a6dd47` persists exact
certificate candidate names and identities and stages both candidates through
flushed/reopened verification only after rollback is armed and current.
Checkpoint `9bdf51c` applies/reconciles both verified candidates through the
retained exact target and durably records `certificates_applied` only after
destination and stage proof. Checkpoint `244eeb7` idempotently cleans only the
two recorded protected-root identities. Checkpoint `fa9d3eb` supplies the
missing native plan-preparation boundary without enabling mutation. Checkpoints
`1c59252`, `4b9a44d`, `e9a8559`, and `ab5aefa` compose durable rollback arming,
forward staging, certificate/provider mutation, exact old-container removal,
and twice-verified repaired-profile start/rebinding through current
`runtime_started`. Remaining terminal verification/commit/cleanup and
recovery-on-failure integration plus the legacy transaction refactor are still
open.
After Gate A source
acceptance and the PR #67 merge decision, complete Task-096 lifecycle controls
and Task-102 native first-run setup before resuming Task-087 Gate B normal-
package integration. Then qualify the completed front door under Task-097,
refine immutable unsigned `v0.1.3-preview.N` GitHub prereleases until the
normal-user package is satisfactory, and complete Task-100 production signing
and managed-endpoint qualification. PR #67 stays Draft, mutation remains
disabled, and existing `Task-087-validation-*` packages remain nonpublishable.
Required release and handoff work takes priority over Task-058/059 stretch work.
**Hard End**: October 31, 2026; operational closeout October 30

---

## Required Roadmap Work

| Order | Task | Status | Estimate | Dependencies | Required outcome |
| ---: | --- | --- | --- | --- | --- |
| 1 | `TASK-096` Launcher Lifecycle Controls | NOT_STARTED | 2-4 days | Task-087 Gate A source acceptance and PR #67 merge; current lifecycle-script behavior as reference only | State-driven Start/Open/Stop/Restart works natively on Docker and Podman without deleting named volumes |
| 2 | `TASK-102` Native Launcher First-Run Setup | NOT_STARTED | 3-5 days | Task-096 lifecycle foundation; accepted Task-087 native execution/security contracts | Double-click launcher performs package/asset/runtime setup and opens the browser Setup Wizard without invoking command wrappers |
| 3 | `TASK-097` Integrated Front-Door Package Qualification | NOT_STARTED | 3-5 days plus environment validation | Tasks 090, 098, 099, 101, Task-087 Gate B package integration, 096, and 102 | Completed front-door package passes Docker/Podman CPU/GPU qualification; Podman works without Docker Desktop |
| 4 | `TASK-091` Owner-Runnable Release Qualification | NOT_STARTED | 3-6 days | Stable unsigned package/preview shape; fixture/harness custody | Preview-based harness and custody rehearsal are ready for Task-100; signed acceptance completes under Task-100 |
| 5 | `TASK-092` Documentation Currentness And Information Architecture | NOT_STARTED | Stage A 1-2 days; Stage B as approved | Stable unsigned package behavior and shape | Repo docs, user docs, release notes, external Setup Guide, and demo video agree |
| 6 | `TASK-093` Persistent Data Lifecycle And Recovery Rehearsal | NOT_STARTED | 1-2 days minimum | Runtime profiles and package lifecycle stable | Safe owner-run upgrade, rollback, cleanup, and recovery procedure |
| 7 | `TASK-100` Production Signing And Managed-Endpoint Qualification | NOT_STARTED | 3-5 days plus signer/endpoint scheduling | October; Task-101 security gate clear; satisfactory unsigned preview recorded; stable source/package shape from Tasks 087/096/102/097; Tasks 091-093 release, docs, and lifecycle prerequisites ready; approved signer and endpoint window | Signed `v0.1.3-rc.N` verifies after packaging and passes representative managed-endpoint acceptance |
| 8 | `TASK-094` Evidence-Gated Support Snapshot | EVIDENCE_GATED | 1-3 days if selected | Pilot/support evidence | Implement only if real feedback shows a support-diagnostics gap |

### Task-096 Boundary

- Begin only after Task-087 Gate A source acceptance and the PR #67 merge
  decision; do not wait for Gate B package integration.
- Reuse the accepted fixed-target validation, native contained execution,
  sanitized state, locking, and recovery contracts for state-driven
  Start/Open/Stop/Restart controls.
- Invoke exact Docker/Podman/Compose executable identities through fixed
  argument plans. Do not invoke PowerShell, CMD/BAT wrappers, shell text, the
  dormant helper, or browser-supplied commands.
- Require clear confirmation for Stop and Restart. Stop uses
  `compose down --remove-orphans` semantics and never requests `-v`,
  `--volumes`, or named-volume deletion.
- Open only the verified loopback TowerScout URL after readiness. Keep current
  scripts as support/emergency fallbacks rather than the primary user path.
- Support Docker and rootless Podman and preserve every named volume.

### Task-102 Boundary

- Make `TowerScoutLauncher.exe` the normal user's double-click first-run entry
  point after Task-096 establishes lifecycle controls.
- Validate the package, selected engine/profile, required assets, manifest and
  hashes; import assets; start the exact captured profile; wait for readiness;
  and open the existing browser Setup Wizard.
- Keep provider-key entry and validation in the browser Setup Wizard. Do not
  collect or persist provider keys in the native launcher.
- Port required setup behavior into bounded native Python/Win32 operations.
  Do not hide `setup-towerscout.cmd`, `start.bat`, PowerShell, or another shell
  behind a launcher button.
- Preserve CPU-safe default launch, explicit GPU selection/prerequisites,
  Docker/rootless-Podman boundaries, existing asset verification, and all
  persistent-volume contracts.
- Keep scripts as documented support/emergency fallbacks until final
  qualification proves the launcher path.

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
- Add a tool-neutral owner model-upgrade runbook and bounded manifest/checksum
  helper. Cover accepting a trained artifact, adding or replacing compatible
  YOLOv5 weights, selecting the intended model/version, updating the asset
  manifest path/size/SHA-256, rebuilding release metadata and checksums,
  recording license/provenance, validating fixed CPU/GPU fixtures and
  performance, and rolling back safely.
- Clearly separate a compatible weights-only update from a YOLO runtime or
  model-family upgrade. The latter must also pin and review the vendored source
  revision, loader, dependencies, licenses/SBOM, and complete runtime-profile
  requalification before release.

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
| 8 | `TASK-058` Background Detection Jobs And Durable Run State | CONDITIONAL | 3-5 days | Tasks 090, 098, 099, 101, 087 Gate B, 096, 102, and 097 pass; no pilot blocker; required release qualification retains responsible margin |
| 9 | `TASK-059` Backend Layer Decomposition And Logging Consolidation | CONDITIONAL | 3-5 days | Task-058 accepted and remaining schedule margin is still safe |

August 28 is the latest responsible Task-058 capacity checkpoint, not an
earliest start date. Task-058 may begin earlier when all gates pass.

---

## Existing Follow-On Backlog

| Priority | Task | Status | Recommended disposition |
| ---: | --- | --- | --- |
| 1 | `TASK-076` Provider API Key Exposure And Restriction Policy | NOT_STARTED | Reassess before final documentation/freeze; include provider-side restriction and ownership guidance |
| 2 | `TASK-068` Windows Test Portability And Script Validation | NOT_STARTED | Pull forward if Tasks 087, 096, 102, or 097 expose repeatable script gaps |
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
| `TASK-101` extract-zip Advisory Assessment And Release-Gate Disposition | Completed August 20; PR #72/default-branch remediation and PR #73 checkpoint passed, then PR #67 head `946deaf` passed CI/CD run `32383065903` and Task-087 run `32383065959` |
| `TASK-087` Host-Side TLS Repair Control Plane | In progress / IMPLEMENT at implementation head `ab5aefa`; `01d2a96` is the validated exact head. Native rollback/startup admission and the exact retained lock/recovery context are composed. Durable certificate/provider mutation plus exact runtime stop/start now reaches current `runtime_started`; terminal verification/commit/cleanup, recovery-on-failure integration, the `repair.py` refactor, live trust/runtime proof, and final validation remain. PR #67 remains Draft. After Gate A acceptance and the merge decision, complete Tasks 096 and 102 before Task-087 Gate B normal-package integration. |
| `TASK-096` Launcher Lifecycle Controls | Backlog / NOT_STARTED. Begins only after Task-087 Gate A acceptance and the PR #67 merge decision; owns native state-driven Start/Open/Stop/Restart. |
| `TASK-102` Native Launcher First-Run Setup | Backlog / NOT_STARTED. Begins after Task-096; owns package/asset/runtime/readiness setup and opens the browser Setup Wizard for provider keys before Task-087 Gate B. |
| `TASK-089` cdcai Adoption And Ownership Transfer | Owner-gated; preparation only until Task-100 signed qualification, final owner qualification, and approval |

---

## Milestone Controls

| Date | Control |
| --- | --- |
| August 20 | Task-087 lifecycle head `6e0f744` passed CI/CD run `32385304086` and Task-087 run `32385304052`; independent PR #67 technical/security review requested changes, so exact-target/recovery source remediation and re-review are now the active gate |
| August 20 | PR #67 reconciliation head `946deaf` passed CI/CD run `32383065903` and Task-087 run `32383065959`; Task-101 completion and Task-087 resume are recorded, with lifecycle-head checks next |
| August 20 | PR #72/default-branch security gates recorded as passed; PR #67 semantic reconciliation became the next Task-101 gate |
| August 19 | Task-087 Proceed-to-unsigned-preview decision recorded; production signing assigned to Task-100 |
| August 19 | Task-101 selected as the active high-severity alert `#76` gate; Task-087 implementation/package work paused while PR #67 remained reviewable |
| August 28 | Required scope and Task-058 capacity checkpoint |
| September 16 | Launcher front-door sequence rebaselined: Task-087 Gate A and PR #67 decision, Task-096, Task-102, Task-087 Gate B, then Task-097 |
| September 18 | Superseded historical code-complete target; not a current gate |
| September 25 | Superseded historical satisfactory-package target; replacement forecast follows Gate A acceptance |
| October 1 | Earliest Task-100 activation, only after the satisfactory-package decision |
| October 9 | Signed `v0.1.3-rc.N` content/candidate freeze |
| October 16 | Task-100 managed-endpoint qualification and acceptance complete |
| October 23 | Owner-operated handoff rehearsal complete |
| October 30 | Operational closeout |
| October 31 | Hard project end |
