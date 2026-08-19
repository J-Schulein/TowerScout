# TowerScout October 2026 Fix-First Implementation Roadmap

**Status**: CURRENT - canonical forward execution roadmap
**Approved**: July 23, 2026
**Last Reconciled**: August 19, 2026
**Decision Owners**: Project lead and cdcai owner
**Pilot Baseline**: Immutable fork-side `v0.1.2`
**Unsigned Preview Convention**: `v0.1.3-preview.N`
**Signed Candidate Convention**: `v0.1.3-rc.N`
**Operational Closeout**: October 30, 2026
**Hard Project End**: October 31, 2026

## August 19 Preview-To-Signing Sequence Override

ADR-019 controls release and signing sequence wherever older sections below
conflict. The project lead selected Proceed to unsigned preview integration
after the Task-087 functional package gates passed.

- Keep all existing `Task-087-validation-*` artifacts validation-only and
  nonpublishable.
- Complete technical/security review and add the launcher to a new normal-user
  release-package path.
- Publish iterative packages only as immutable unsigned
  `v0.1.3-preview.N` fork-side GitHub prereleases, never `Latest`, with clear
  unmanaged-test-machine and non-production wording.
- Test the actual GitHub download/extract/setup/use path on an approved clean
  unmanaged Windows machine without security exclusions or bypass guidance.
- Record package satisfaction only when the stable executable/entry-point
  shape, exact source, fresh pinned image, manifests/checksums/notices/docs,
  required functional flows, and supported runtime boundaries are accepted.
- Start `TASK-100` in October after that decision. It owns production signing,
  post-sign packaging/checksums, representative managed-endpoint validation,
  and the signed `v0.1.3-rc.N` candidate.
- Keep `cdcai/TowerScout` unchanged until the signed candidate is qualified and
  the owner explicitly approves adoption.

Target the satisfactory unsigned package by September 25, Task-100 activation
no earlier than October 1, signed-candidate freeze by October 9, and Task-100
acceptance by October 16. Existing historical evidence and decisions remain
valid for the exact artifacts they describe, but do not reinstate the former
parallel-signing or signing-before-merge sequence.

## August 11 Task-087 Current Override

Draft PR #67 is reconciled locally with current `main` at `3932abf`, preserving
the Sprint 09/Task-099 closeout and the final Task-087 implementation tree. The
native Python/Tkinter transaction and typed-confirmation UI are implemented.
One separately authorized isolated Google/Docker source-adapter repair passed
while preserving all eight named volumes; it did not validate the combined
full-runnable packaged UI. This override controls the older August 5-6 wording
below where it describes preview-only behavior as the latest state.

- Publish and require green checks at the new exact PR head.
- Generate a new exact-source full-runnable package in an approved environment;
  do not reuse the historical `4327fb6` or `4fc5390` artifacts.
- Validate packaged UI-driven Docker Google, Azure, and controlled recovery.
- Validate Podman only after an approved non-Docker-Desktop Compose provider is
  configured separately.
- Keep Task-086 as the supported fallback. Technical/security review and
  normal-user preview integration are the next gates; Task-100 owns signing
  and representative managed-endpoint validation in October.
- The overdue disposition was recorded August 19 as Proceed to unsigned
  preview integration under ADR-019.

## Historical August 5 Task-087 Provisional Addendum

ADR-018 authorizes a reversible Windows launcher feasibility prototype instead
of continuing directly toward activation of the dormant browser-to-loopback
helper. This addendum controls where the July 23 Task-087 mechanism conflicts;
the required user outcome, Task-086 fallback, runtime matrix, and final
milestones remain unchanged.

- Keep all browser/helper activation gates off and PR #64 on hold.
- Build a thin visible launcher proof, beginning with non-mutating status and
  TLS repair preview.
- Publish the bounded proof as a Draft PR and build only
  `Task-087-validation-<short-SHA>` from its exact commit. This artifact is not
  a candidate and receives no tag, GitHub Release, or cdcai publication.
- Start approved signing-path coordination in parallel with development.
- Do not merge or ship the launcher until the production-shaped signed artifact
  passes representative managed-endpoint validation.
- Decide proceed, conditional, or stop by August 14. A failed proof returns to
  the Task-086 user-run command repair without moving the September/October
  milestones.

### Historical August 5-6 Checkpoint Status

- Draft PR #67 remains the review surface; all browser/helper activation gates
  remain off.
- Commits `18082cf` and `4327fb6` stabilized the fixed shell-free Windows
  runtime probe and added clean-source build provenance plus atomic validation
  artifact publication. The assembler now distinguishes the non-runnable
  `launcher-policy` artifact from the `full-runnable` functional package.
- The exact-source unsigned `full-runnable` package from
  `4327fb6288f4f8c83202f548a2ba7cb2dcf9bab6` passed pristine sidecar/internal
  checksum verification and fresh isolated Docker CPU setup on port 5008. It
  reached healthy `setup_required` readiness with verified assets, CPU selected,
  and the exact pinned image digest.
- On August 6, reboot persistence and automatic Docker-project resume passed.
  The exact launcher reported Docker running and reachable across three
  consecutive refreshes, and its fixed Google/Docker preview displayed the
  expected target, CPU/GPU-off profile, and port 5008. The preview inspected no
  certificates, changed no trust, stopped or restarted no container, and did
  not run the dormant helper.
- A provider key entered only in the Setup Wizard produced the sanitized
  expected `tls_ca_untrusted` category and Task-086 repair-command guidance.
  No key, raw provider response, or certificate detail was captured. Normal-
  size controls were clipped at this host's display scaling and became visible
  when maximized; that is a non-blocking UI follow-up before the signed build.
- The next external gate is an organization-approved signed production-shaped
  build running under representative managed endpoint policies. The current
  artifact remains unsigned validation-only evidence, not a release candidate
  or release. The later isolated source-adapter transaction is governed by the
  August 11 override and does not authorize tag, merge, shipment, additional
  mutation, or cdcai change before the applicable gates pass.

Current sanitized evidence:
[`FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md`](../../../tasks/active/TASK-087/FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md).
The earlier `REVIEW-EVIDENCE-2026-08-05.md` remains historical static-review
evidence.

## Executive Decision

Use a fix-first approach while pilot users continue testing the unchanged
`v0.1.2` package.

The fork remains the pilot, development, and candidate-validation surface.
`cdcai/TowerScout` remains unchanged until the cdcai owner and project lead
qualify a final candidate and explicitly approve adoption.

Before final-candidate freeze, TowerScout must:

- finish the guided Google/Azure managed-network TLS repair
- add a user-confirmed Exit/Stop TowerScout feature
- qualify Docker CPU, Docker GPU, Podman CPU, and Podman GPU
- clean repository and user-facing documentation
- update the external Setup Guide and demo video
- leave a tool-neutral maintenance and AI-assisted-development foundation
- complete owner-operated qualification, recovery, release, and handoff
- complete Task-100 production signing and representative managed-endpoint
  qualification after the unsigned package is satisfactory

Task-058 and Task-059 are stretch work. They cannot displace required release,
runtime, documentation, or handoff work.

## Repository And Release Roles

### `J-Schulein/TowerScout`

- Hosts the immutable `v0.1.2` pilot.
- Hosts development, immutable unsigned `v0.1.3-preview.N` prereleases, and
  signed `v0.1.3-rc.N` candidates.
- Retains pilot, release, and source-provenance history after handoff.

### `cdcai/TowerScout`

- Remains unchanged during the pilot and candidate-development hold.
- Receives only the owner-qualified final baseline.
- Publishes the official final release after the final tag/title decision.

### Release Naming

- Fork unsigned previews use `v0.1.3-preview.N`, remain GitHub prereleases, and
  are never marked `Latest`.
- Task-100 builds/signs under `v0.1.3-rc.N`; that exact candidate is published
  and frozen only after Task-100 qualification passes.
- A candidate tag does not reserve or authorize `v0.1.3` final.
- Before official publication, the cdcai owner and project lead select the
  cdcai tag and display title.
- Official images, packages, manifests, checksums, filenames, source refs, and
  documentation are rebuilt consistently for that identity.

## Work Sequence

### Phase 1 - Rebaseline And Investigate

**Target**: July 23-August 14; reforecast after Task-090 classification
**Status**: COMPLETE - Task-090 and Task-098 closed July 27

**August 6 Post-Closeout Amendment**: The July Phase 1 result remains complete
and historical. Four advisories disclosed August 4-5 are owned by the new
Task-099 follow-up rather than reopening Tasks 090/098. Task-099 cleared its
critical/high and default-branch alert-reconciliation gates on August 11
through PRs #68/#69. Task-087 continues under its own remaining qualification
gates.

1. Task-095 Phase A roadmap/workspace rebaseline and readiness cleanup:
   complete July 23.
2. Task-090 bounded runtime, custom-image, and dependency security
   investigation: complete.
3. The 62-alert baseline was classified and the separate Task-098 scope was
   approved.
4. Task-098 patching, compatibility decisions, regression, and residual
   disposition: complete through PR #51 / `e499b50`.
5. At the July 27 closeout, release-blocking findings were resolved and eight
   non-blocking medium/low torch advisories remained visible for future
   coordinated ML requalification.

July 27 exit evidence:

- One canonical roadmap is active.
- Task state and context navigation are consistent.
- Every open alert has an evidence-backed disposition.
- No unresolved release-blocking critical/high finding remains.
- Any residual critical/high risk has written project-lead/cdcai-owner
  acceptance and compensating controls.
- Required Task-098 remediation is complete.

### Phase 2 - Required Owner Fixes

**Target**: Begin as soon as Phase 1 passes

1. Complete technical/security review of Draft PR #67 and preserve the exact-
   source Docker/Podman Google/Azure, recovery, provider-installer, and rootless
   Podman evidence.
2. Record the August 19 Proceed-to-unsigned-preview disposition under ADR-019.
3. Integrate the accepted launcher into the normal release-package path; do not
   publish or relabel any Task-087 validation-only ZIP.
4. Publish and refine immutable unsigned `v0.1.3-preview.N` GitHub prereleases
   through approved clean unmanaged-machine testing until the package is
   declared satisfactory.
5. Reuse Task-087's fixed-target confirmation, runtime
   validation, sanitized state, and recovery pattern for Task-096 Exit/Stop on
   Docker and Podman.
6. Preserve Task-086 as the supported fallback for every scope not yet accepted
   in a preview or signed candidate.

Exit:

- Task-087 has a recorded August 19 Proceed-to-preview decision.
- Guided TLS repair passes technical/security, product, package, and clean
  unmanaged-machine preview gates for its stated scope.
- Exit/Stop safely removes the selected application container while retaining
  named volumes.

### Phase 3 - Podman And Four-Profile Qualification

1. Complete Task-097.
2. Validate Podman without Docker Desktop.
3. Validate approved Compose-provider selection, package-local installer, and
   manual fallback.
4. Validate Podman CPU and GPU/CDI.
5. Validate Task-087 and Task-096 behavior on Podman.
6. Investigate Podman-machine image-pull and source-build TLS separately.

Exit:

- Docker CPU, Docker GPU, Podman CPU, and Podman GPU have defined and passing
  qualification evidence.
- Required packaged-runtime blockers are fixed.
- Any non-blocking source-build limitation is documented and owner-accepted.

### Phase 4 - Conditional Architecture Work

Task-058 may begin immediately when all of the following are true:

- Tasks 090 and 098 are complete.
- Task-099 passes its August dependency-security follow-up gate.
- Task-087 passes its functional/security and unsigned-preview package gates.
- Task-096 passes Docker and Podman acceptance.
- Task-097 passes required final-path qualification.
- No pilot blocker requires priority.
- September 18 code complete remains credible.

August 28 is the latest responsible capacity checkpoint, not a wait date.

Task-059 may begin only after Task-058 is accepted and required milestones
remain protected.

### Phase 5 - Qualification, Documentation, And Freeze

Required work:

- Task-091 preview-based owner-runnable harness/custody rehearsal; the final
  signed acceptance run occurs under Task-100
- Task-092 repository/user documentation currentness
- Task-093 persistent-data lifecycle and recovery rehearsal
- Task-094 only when pilot/support evidence justifies it
- Task-095 Phase B governance, backlog, and maintenance handoff

Documentation includes:

- repository README and support docs
- release notes and troubleshooting
- external step-by-step Setup Guide
- replacement demo video
- decision on whether the external guide/video should be linked from README
- public-accessibility checks for linked guide/video when included

Exit:

- September 18: code complete.
- September 25: feature/documentation complete and the satisfactory unsigned
  package decision targeted.
- October 1: Task-100 may start only if that decision is recorded.

### Phase 6 - Owner Acceptance And Transfer

1. Complete Task-100 controlled production signing, post-sign package/hash
   generation, and representative managed-endpoint qualification.
2. Freeze the signed `v0.1.3-rc.N` candidate under the blocker-only rule.
3. Project lead and cdcai owner qualify the signed final candidate.
4. Select the official cdcai tag and display title.
5. Build/sign the official cdcai image/package consistently under the approved
   identity and custody model.
6. Exercise release, rollback/reject, recovery, and known-risk procedures.
7. Complete Task-089 only after explicit adoption authorization.
8. Transfer backlog, custody, access, and maintenance procedures.

Exit:

- October 9: signed candidate frozen; blocker-only change rule begins.
- October 16: Task-100 and acceptance complete.
- October 23: owner-operated handoff rehearsal complete.
- October 30: operational closeout and sign-off complete.
- October 31: no planned work or outgoing-developer dependency remains.

## Task Definitions

| Task | Canonical purpose | Disposition |
| --- | --- | --- |
| `TASK-087` | Universal guided Google/Azure provider TLS repair on Docker/Podman | Required |
| `TASK-088` | Immutable `v0.1.2` pilot distribution and custody | Complete |
| `TASK-089` | Owner-gated cdcai release/adoption and ownership transfer | Required after qualification |
| `TASK-090` | Runtime, custom-image, and dependency-security investigation, including the 62-alert Trivy baseline | Complete July 23 |
| `TASK-091` | Preview-based owner-runnable qualification harness and custody rehearsal; signed acceptance reused under Task-100 | Required |
| `TASK-092` | Documentation currentness and information architecture | Required minimum; broader redesign bounded |
| `TASK-093` | Persistent-data lifecycle and recovery rehearsal | Required minimum |
| `TASK-094` | Sanitized support snapshot | Evidence-gated |
| `TASK-095` | Governance and tool-neutral maintenance/handoff foundation | Required; Phase A complete, Phase B through closeout |
| `TASK-096` | User-confirmed Exit/Stop TowerScout | Required |
| `TASK-097` | Podman CPU/GPU final-path hardening and qualification | Required |
| `TASK-098` | Dependency-security remediation, compatibility validation, and release disposition | Complete July 27 |
| `TASK-099` | August dependency-advisory remediation and release-gate reconciliation | Complete August 11 |
| `TASK-100` | October production signing, post-sign package verification, and representative managed-endpoint qualification | Required after satisfactory unsigned package |
| `TASK-058` | Background jobs and durable run state | Conditional stretch |
| `TASK-059` | Backend decomposition and logging consolidation | Conditional stretch after Task-058 |

No canonical task file existed for Tasks 090-095 before this rebaseline; their
earlier mentions were provisional planning references. Tasks 096 and 097 were
new unique identifiers at rebaseline. Task-098 was added on July 23 after the
live 62-alert code-scanning inventory established a separate remediation need.
Task-098's project-lead approval gate was satisfied July 23 and the task
completed July 27. cdcai-owner approval remains reserved for residual
critical/high acceptance, changes to `cdcai/TowerScout`, and official
adoption.

Task-099 was added August 6 for alerts `#72-#75`, which GitHub disclosed after
the Task-098 closeout. While it remained active, the August 7 npm audit added
`GHSA-5p4m-2wfm-xmqj`. Its narrow `aiohttp`, transitive `ip-address`, and
transitive `js-yaml` remediation plus stale root-graph refresh completed
August 11. Alert `#74` closed without dismissal, the inventory returned to the
eight documented torch residuals, and Task-099 no longer blocks preview or
signed-candidate work; Task-087 and Task-100 retain their separate gates.

Task-100 was added August 19 after the project lead chose to refine unsigned
normal-user previews before production signing. It stays in the backlog until
October and the ADR-019 satisfactory-package decision, then must complete
before signed-candidate acceptance or official cdcai publication.

## Stop Rules

Stop or defer optional work when:

- a pilot, security, data-integrity, runtime, or qualification blocker appears
- a critical/high dependency finding remains release-blocking or lacks an
  approved residual-risk disposition
- required work threatens September 18 code complete
- documentation/package work threatens September 25
- the satisfactory unsigned package slips past September 30 and leaves
  insufficient time for Task-100 before October 16
- a non-blocker change would enter after October 9 freeze
- owner rehearsal or custody work is not on track for October 23

Do not:

- modify released `v0.1.2` bytes
- relabel validation-only artifacts as previews or use an unsigned `-rc.N`
- publish `v0.1.3` final prematurely
- treat candidate naming as the final cdcai decision
- change cdcai without explicit owner authorization
- expose Docker/Podman sockets or arbitrary host commands to the app
- combine application-provider TLS with silent Podman-machine trust changes

## Deferred Decisions With Assigned Gates

These are intentionally not blockers today:

- Final cdcai tag and display title: decide before the official build.
- External guide/video placement in README: decide during Task-092.
- Podman source-build limitation disposition: decide in Task-097 after
  investigation.
- GitHub Issues in addition to the Markdown backlog: decide near handoff.
- Task-094 implementation: decide only from real pilot/support evidence.

## Runtime Startup Coordination

Before runtime-dependent work, the active agent must identify whether Docker
Desktop, Podman, or both are needed and ask the user to start them. Wait for
confirmation before runtime validation because Docker Desktop may require a
workstation restart.
