# Current Tasks - Sprint 09

**Sprint Period**: August 8-August 21, 2026
**Last Updated**: August 19, 2026
**Focus**: Complete Task-087 technical/security review and integrate the
launcher into a normal-user unsigned preview package while keeping the frozen
pilot and cdcai boundaries unchanged. Production signing is scheduled as
Task-100 in October after the package is satisfactory.

**Current Release State**:

- Fork-side `v0.1.2` is the immutable pilot package.
- Iterative unsigned fork packages use immutable `v0.1.3-preview.N` GitHub
  prereleases and are never marked `Latest`.
- `v0.1.3-rc.N` is reserved for the signed production-shaped candidate created
  under Task-100.
- `cdcai/TowerScout` remains unchanged until final owner qualification and
  explicit adoption approval.
- October 30 is operational closeout; October 31 is the hard project end.

---

## Sprint 08 Closeout

Sprint 08 completed Tasks 090 and 098 within the July 23-August 7 period and
cleared the original dependency-security gate. Task-099 began during Sprint 08
but completed on August 11 after the declared period, so its completion belongs
to Sprint 09. Tasks 087, 089, and 095 carry forward.

Retrospective:
[`SPRINT-08-RETROSPECTIVE-ANALYSIS-2026-08-11.md`](./context/analysis/SPRINT-08-RETROSPECTIVE-ANALYSIS-2026-08-11.md)

---

## Sprint 09 Task State

### **TASK-095: Governance And AI-Ready Handoff Foundation**

**Status**: IN_PROGRESS - Phase A roadmap/workspace rebaseline is complete;
Phase B governance and final handoff maintenance continue through closeout
**Type**: C (Governance / Documentation / Handoff)
**Priority**: HIGH
**Estimated Effort**: Phase A 1-2 days; Phase B 2-4 distributed days
**Task File**:
`.agent_work/tasks/active/TASK-095-governance-ai-ready-handoff.md`

**Current Scope**:

- Keep task disposition, navigation, backlog, release evidence, and owner
  handoff sources current through October 30.
- Preserve one canonical fix-first roadmap and the immutable pilot/adoption
  boundary.
- Close sprint and task-state drift when live evidence changes the plan.

### **TASK-099: August Dependency Advisory Follow-Up**

**Status**: COMPLETED - PR #68 merged the narrow dependency fixes as
`f460445`; PR #69 merged the root-manifest refresh as `0133b50`. Dynamic graph
run `31510493332` replaced the stale snapshot, alert `#74` closed without
dismissal, the SBOM contains only `aiohttp==3.14.3`, and the open inventory is
exactly the eight documented torch residuals
**Completed**: August 11, 2026
**Type**: C (Security Remediation / Release Gate)
**Priority**: HIGH
**Task File**:
`.agent_work/tasks/active/TASK-099-august-dependency-advisory-follow-up.md`

**Release Boundary**: Task-099 cleared the dependency-security release gate.
Task-087 preview integration and Task-100 production signing/managed-endpoint
qualification remain separate release gates.

### **TASK-087: Host-Side TLS Repair Control Plane**

**Status**: IN_PROGRESS - the exact-source `7ef879c` full-runnable CPU packages
passed Docker and approved-provider Podman Google/Azure TLS repair plus
controlled recovery. Follow-up head `3990bc0` closes provider-installer
dependency drift with a hash-approved offline wheelhouse. Head `5737a58`
enforces the selected Windows rootless-Podman boundary; its exact-source
package rejected rootful mode before provider discovery or container mutation
while preserving the user's machine mode and volumes. The August 19 decision
is Proceed to unsigned preview integration. Technical/security review,
normal-release-package integration, and clean unmanaged-machine preview
validation remain open; signing and representative managed-endpoint validation
move to Task-100 in October.
**Type**: B/C (Runtime Support / Setup UX / TLS Trust)
**Priority**: HIGH
**Estimated Effort**: Complete review and preview integration in Sprint 09;
production signing is separately estimated under Task-100
**Task File**:
`.agent_work/tasks/active/TASK-087-host-side-tls-repair-control-plane.md`

**Current Scope And Gates**:

- Preserve the visible Python/Tkinter launcher and bounded native transaction
  on top of the current security and Sprint 09 tracking history.
- Preserve the Google/Azure functional evidence from accepted implementation
  head `7ef879c` and the provider-installer reproducibility evidence from
  follow-up head `3990bc0`; their applicable exact-head CI and CPU package gates
  are green.
- Preserve the passed exact-head Docker and approved-provider Podman
  Google/Azure/recovery results as unsigned development-workstation evidence.
- Keep the approved Podman Compose provider explicit. Head `3990bc0` replaces
  live dependency resolution with exact per-artifact URLs and SHA-256 pins,
  installs only from the verified local wheel cache with dependencies disabled,
  checks the environment and exact versions, and binds it only after approval.
  Fresh packaged installation and managed replacement passed; no unapproved
  provider or dependency was accepted.
- Treat rootless Podman CPU as the provisional Windows support boundary. The
  unchanged exact package reached native Windows localhost and retained that
  reachability across scoped restart in rootless mode. Rootful mode remained
  healthy only inside the Podman WSL distribution and did not expose Windows
  localhost, with Docker fully exited; user-mode networking did not fix it.
  Head `5737a58` now rejects rootful Windows Podman before Compose-provider
  discovery or container mutation, explains the separate rootful/rootless
  stores, and never switches the user's machine mode automatically.
- Record the NVIDIA result accurately: the workstation passed Docker GPU and
  Blackwell model execution, but the selected PyTorch 2.6/CUDA 12.6 release
  profile cannot execute compute capability 12.0. A non-release PyTorch
  2.7/CUDA 12.8 feasibility image passed the deterministic model harness.
  Keep dependency/profile selection and final Docker/Podman GPU package
  qualification in Task-097 rather than expanding the Task-087 release claim.
- Keep all existing `Task-087-validation-*` packages validation-only. Build a
  new normal-user package for any `v0.1.3-preview.N` publication; do not rename
  or upload an existing validation ZIP.
- Complete technical/security review before merge or preview publication, then
  test the actual GitHub download path on an approved unmanaged clean Windows
  machine with truthful unsigned and support-boundary warnings.
- Treat the August 19 decision as Proceed to unsigned preview integration under
  ADR-019. Signing, `v0.1.3-rc.N`, and representative managed-endpoint
  qualification belong to Task-100 in October after the satisfactory-package
  gate.
- Keep Task-086 as the supported command-based fallback until the replacement
  launcher path is accepted for its stated preview or signed-candidate scope.

### **TASK-089: cdcai Adoption Preparation And Deferred Ownership Transfer**

**Status**: BLOCKED / OWNER-GATED - preparation only; no cdcai mutation
**Type**: C (Repository Migration / Release Ownership / Handoff)
**Priority**: HIGH
**Estimated Effort**: 1-2 days after qualification and authorization
**Task File**:
`.agent_work/tasks/active/TASK-089-cdcai-migration-execution.md`

**Current Boundary**:

- The final cdcai tag and release title are selected before the official build.
- Neither `v0.1.3-preview.N` nor `v0.1.3-rc.N` dictates the final cdcai
  identity.
- Task-100 must complete the signed-candidate and managed-endpoint gate before
  official publication.
- Execution waits for owner qualification, explicit adoption approval, and an
  approved release/package/backlog transfer plan.

---

## Sprint 09 Sequence

1. Close Sprint 08 and attribute the August 11 Task-099 completion to Sprint
   09: complete through this tracking follow-up.
2. Draft PR #67 is reconciled with current `main` while retaining both the
   Task-099 closeout and the current Task-087 implementation state.
3. Exact-head checks through implementation checkpoint `5737a58` are green
   locally, and all required Draft PR checks are green on evidence head
   `ae78b06`.
4. The exact-source full-runnable Task-087 package was generated and verified
   in the approved development environment.
5. Docker and approved-provider Podman Google/Azure plus controlled recovery
   validation passed from exact-head packages.
6. Podman-provider installer dependency drift is resolved. Rootless Podman CPU
   is the provisional native-forwarding boundary, and the exact-source package
   now enforces that boundary without changing machine mode or runtime state.
7. Complete technical/security review and integrate the launcher into a new
   normal-user unsigned preview-package path with accurate manifests,
   checksums, notices, and user guidance.
8. Record the August 19 Proceed-to-preview decision and keep production signing
   plus representative managed-endpoint validation scheduled as Task-100 for
   October after package satisfaction.
9. Test each published `v0.1.3-preview.N` through the actual GitHub download
   path on an approved unmanaged clean Windows machine without security
   exclusions or bypass instructions.
10. Select Task-096 next, followed by Task-097. Keep Tasks 091-093 behind the
    stable unsigned package/runtime-shape boundary; Task-091 prepares the
    owner-runnable harness before Task-100, while signed acceptance occurs
    under Task-100.

Task-058 and Task-059 remain conditional stretch work. Task-094 remains
evidence-gated. Task-100 remains in the backlog until its October entry gate is
met. Task-099 stays in `tasks/active/` until Sprint 09 closeout.

---

## Runtime Coordination

Before any Docker- or Podman-dependent work:

1. Tell the user which runtime profile is required.
2. Ask the user to start Docker Desktop and/or the Podman machine.
3. Wait for confirmation before beginning runtime-dependent validation.
4. Allow time for a workstation restart when Docker Desktop requires it.

Planning, documentation, static source review, and branch reconciliation do
not require a runtime startup request.

---

## Related Sources

- [Canonical October Fix-First Roadmap](./context/status/Handoff-Planning/2026-07-23-OCTOBER-FIX-FIRST-IMPLEMENTATION-ROADMAP.md)
- [Pilot And Adoption Track](./context/status/Handoff-Planning/PILOT-FEEDBACK-AND-CDC-AI-ADOPTION-PLAN.md)
- [Task Backlog](./task-backlog.md)
- [Requirements](./requirements.md)
- [Design](./design.md)
- [Completed Tasks](./completed-tasks.md)
