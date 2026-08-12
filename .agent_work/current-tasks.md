# Current Tasks - Sprint 09

**Sprint Period**: August 8-August 21, 2026
**Last Updated**: August 12, 2026
**Focus**: Reconcile the Task-087 launcher prototype with current `main`,
complete its exact-source package and managed-endpoint decision gates, and keep
the frozen pilot and cdcai boundaries unchanged.

**Current Release State**:

- Fork-side `v0.1.2` is the immutable pilot package.
- New development uses immutable `v0.1.3-rc.N` candidate identities.
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
Task-087 signing, candidate inclusion, and final-release qualification remain
subject to Task-087's own package, signing, and managed-endpoint gates.

### **TASK-087: Host-Side TLS Repair Control Plane**

**Status**: IN_PROGRESS - the exact-source `7ef879c` full-runnable CPU packages
passed Docker and approved-provider Podman Google/Azure TLS repair plus
controlled recovery. Follow-up head `3990bc0` closes provider-installer
dependency drift with a hash-approved offline wheelhouse. Head `5737a58`
enforces the selected Windows rootless-Podman boundary; its exact-source
package rejected rootful mode before provider discovery or container mutation
while preserving the user's machine mode and volumes. Technical/security
review, signing, representative managed-endpoint validation, and the August 14
disposition remain open.
**Type**: B/C (Runtime Support / Setup UX / TLS Trust)
**Priority**: HIGH
**Estimated Effort**: Prototype through August 14; proceed, revise, or stop at
that decision gate
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
- Keep signing, representative managed-endpoint validation, candidate
  inclusion, and merge as separate later gates.
- Record proceed, conditional, or stop by August 14 under ADR-018.
- Keep Task-086 as the supported command-based fallback until every Task-087
  gate passes.

### **TASK-089: cdcai Adoption Preparation And Deferred Ownership Transfer**

**Status**: BLOCKED / OWNER-GATED - preparation only; no cdcai mutation
**Type**: C (Repository Migration / Release Ownership / Handoff)
**Priority**: HIGH
**Estimated Effort**: 1-2 days after qualification and authorization
**Task File**:
`.agent_work/tasks/active/TASK-089-cdcai-migration-execution.md`

**Current Boundary**:

- The final cdcai tag and release title are selected before the official build.
- `v0.1.3-rc.N` candidate names do not dictate the final cdcai identity.
- Execution waits for owner qualification, explicit adoption approval, and an
  approved release/package/backlog transfer plan.

---

## Sprint 09 Sequence

1. Close Sprint 08 and attribute the August 11 Task-099 completion to Sprint
   09: complete through this tracking follow-up.
2. Draft PR #67 is reconciled with current `main` while retaining both the
   Task-099 closeout and the current Task-087 implementation state.
3. Exact-head checks through implementation checkpoint `5737a58` are green
   locally; its current Draft PR CI run is tracked separately until complete.
4. The exact-source full-runnable Task-087 package was generated and verified
   in the approved development environment.
5. Docker and approved-provider Podman Google/Azure plus controlled recovery
   validation passed from exact-head packages.
6. Podman-provider installer dependency drift is resolved. Rootless Podman CPU
   is the provisional native-forwarding boundary, and the exact-source package
   now enforces that boundary without changing machine mode or runtime state.
7. Complete technical/security review, signing-path coordination, and
   representative managed-endpoint validation as applicable.
8. Record the August 14 Task-087 proceed/conditional/stop decision.
9. If Task-087 proceeds, select Task-096 next, followed by Task-097. Keep Tasks
   091-093 behind the stable candidate/runtime boundary.

Task-058 and Task-059 remain conditional stretch work. Task-094 remains
evidence-gated. Task-099 stays in `tasks/active/` until Sprint 09 closeout.

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
