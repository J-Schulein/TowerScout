# Current Tasks - Sprint 09

**Sprint Period**: August 8-August 21, 2026; active-task continuation retained
through the current Task-087 Gate A work
**Last Updated**: September 11, 2026
**Focus**: Task-101 is complete. Task-087 is the active implementation task.
Its canonical detailed
[`Gate A burn-down`](./tasks/active/TASK-087/GATE-A-STATUS.md) fixes the approved
nine-slice scope and distinguishes complete, built-but-unwired, partial,
not-started, and validation states. At source head `f0a9d81bf6a8`, contracts are
complete; runtime/target foundations, including the reviewed native observation
executor, production authority factory, owned exact-target bridge, and stable
authenticated target-plan assembler, are substantially built but unwired;
Windows trust/security are partial; durable recovery, transaction refactoring,
provider-installer completion, and final proof remain. At earlier source head
`0674805`, all applicable checks passed in CI/CD run `34515408041`, Task-087 run
`34515408156`, and external Trivy job `102999589403`; the PR-only build skipped
as designed. Documentation head `c15967e` also passed all applicable exact-head
checks in CI/CD run `34535776318` and Task-087 run `34535776293`; its PR-only
build skipped as designed. Independently reviewed source checkpoint `7f354bc`
binds the target plan to native Windows trust and awaits exact-head workflows.
No repair or mutation is enabled. Gate B preview integration and Task-100
signing remain separate.

**Current Release State**:

- Fork-side `v0.1.2` is the immutable pilot package.
- Iterative unsigned fork packages use immutable `v0.1.3-preview.N` GitHub
  prereleases and are never marked `Latest`.
- `v0.1.3-rc.N` is reserved for the signed production-shaped candidate created
  under Task-100.
- Task-101 is complete; alert `#76` closed as fixed without dismissal. Its
  reconciliation and lifecycle evidence remains in the completed-task record.
- Task-087 source checkpoint `7f354bcc8d20` is independently validated locally;
  PR #67 remains Draft.
  Gate A remains open and mutation remains disabled. Detailed status and
  evidence are maintained in the
  [`Gate A burn-down`](./tasks/active/TASK-087/GATE-A-STATUS.md), not duplicated
  in this release-state summary.
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
dismissal, the SBOM contains only `aiohttp==3.14.3`, and the August 11 closeout
inventory was exactly the eight documented torch residuals
**Completed**: August 11, 2026
**Type**: C (Security Remediation / Release Gate)
**Priority**: HIGH
**Task File**:
`.agent_work/tasks/active/TASK-099-august-dependency-advisory-follow-up.md`

**Release Boundary**: Task-099 cleared its scoped dependency-security gate on
August 11. Alert `#76` opened afterward and belongs to separately activated
Task-101 rather than rewriting Task-099. PR #72 restored the blocking frontend
gate, alert `#76` closed as fixed, and Task-101's downstream PR #67 exact-head
gate passed at `946deaf`. Task-099 remains the dated August 11 closeout;
reviewer input may continue.

### **TASK-101: extract-zip Advisory Assessment And Release-Gate Disposition**

**Status**: COMPLETED - PR #72/default-branch security gates and PR #73's
checkpoint passed; PR #67 reconciliation head `946deaf` then passed CI/CD run
`32383065903` and Task-087 run `32383065959`, and this lifecycle update records
Task-101 completion plus Task-087's explicit resume
**Completed**: August 20, 2026
**Type**: C (Security Remediation / CI And Release Gate)
**Priority**: HIGH
**Estimated Effort**: 1-2 days plus CI rerun timing
**Task File**:
`.agent_work/tasks/active/TASK-101-extract-zip-advisory-release-gate.md`

**Current Scope And Gates**:

- Preserve Task-099 as the dated August 11 closeout. Task-101 uniquely owns
  alert `#76`, the current npm lock graph, and restoration of the blocking
  frontend dependency-security gate.
- Treat the finding as a CI/developer-browser-install risk, not a shipped
  TowerScout runtime dependency. Do not claim exploitation or end-user runtime
  exposure without new evidence.
- Preserve the locally validated Node `>=22.12.0` / Puppeteer `25.8.0` path,
  whose locked browser tooling removes vulnerable `extract-zip`; do not use
  `npm audit fix --force`, weaken the high-severity gate, or dismiss the alert.
- Preserve the green final PR #72 evidence at `820b649`: CI/CD run
  `32308971393` and Task-087 run `32308971392`. Preserve the exact-main
  post-merge evidence at squash commit `0cc189c`: CI/CD run `32310281115` and
  Task-087 run `32310281051` passed, and alert `#76` closed as fixed without
  dismissal.
- Preserve PR #73's post-merge governance checkpoint at squash commit
  `9276084`: exact-main CI/CD run `32377736719` and Task-087 run `32377736797`
  passed. This merge semantically integrates that current `main` into PR #67
  while preserving ADR-019 and the branch's recorded evidence.
- Align the maintained Node baseline across CI, `package.json`, and the Docker
  frontend stage, and remove the redundant Puppeteer browser-download path
  from Task-087 workflows that already install a pinned browser separately.
- Keep the Docker frontend-stage build blocking on pull requests; the full
  runtime-image build remains the separately documented main-branch advisory
  check.
- Treat those narrowly scoped Task-101 security-workflow edits as gate work;
  those edits alone did not resume broader Task-087 implementation. Resumption
  occurs only through this explicit post-green lifecycle update.
- Require clean install/audit/lock-graph, frontend bundle/contracts, Task-087
  browser/Windows-helper, and Docker build validation before acceptance.
- Preserve the green PR #67 reconciliation evidence at `946deaf`: CI/CD run
  `32383065903` and Task-087 run `32383065959` passed with all required jobs
  successful.
- The lifecycle update marked Task-101 complete and explicitly resumed
  Task-087. Exact-head CI/CD run `32385304086` and Task-087 run `32385304052`
  passed at `6e0f744`; Task-101 has no remaining acceptance gate.

### **TASK-087: Host-Side TLS Repair Control Plane**

**Status**: IN_PROGRESS / IMPLEMENT - Gate A is materially advanced but not
near exit. At `f0a9d81bf6a8`, slice 1 is complete; slices 2-3 are substantially
built but unwired, with the owned native exact-target bridge and stable
authenticated target-plan assembler now checkpointed;
slices 4-5 and 8 are partial; slices 6-7 are not started;
and slice 9 continues incrementally but lacks its final live proof. Mutation is
disabled and PR #67 remains Draft.
**Type**: B/C (Runtime Support / Setup UX / TLS Trust)
**Priority**: HIGH
**Remaining Estimate**: Track the four remaining outcome groups in the
canonical burn-down; re-estimate after exact-target wiring
**Task File**:
`.agent_work/tasks/active/TASK-087-host-side-tls-repair-control-plane.md`
**Canonical Gate A Burn-Down**:
[`TASK-087/GATE-A-STATUS.md`](./tasks/active/TASK-087/GATE-A-STATUS.md)

**Current Scope And Gates**:

- Use the [fixed Gate A burn-down](./tasks/active/TASK-087/GATE-A-STATUS.md)
  for present status, evidence pointers, remaining criteria, and the next
  outcome sequence.
- Implement only the approved August 20 source-remediation design. Mutation
  remains disabled until the exact target, Windows trust/security, durable
  recovery, and transaction requirements are integrated and reviewed.
- Preserve the visible Python/Tkinter launcher, Google/Azure and Docker/rootless-
  Podman boundaries, all eight named volumes, supported OneDrive behavior, and
  the independent Task-086 fallback.
- Keep historical package/runtime evidence in the Task-087 file. It proves only
  the exact bytes and environments previously tested and does not close the
  current Gate A source findings.
- Keep Gate A source acceptance, Gate B artifact/preview integrity, and
  Gate C/Task-100 signing and managed-endpoint qualification separate. PR #67
  remains Draft.
- Source checkpoint `f0a9d81` implements the independently reviewed native
  Windows-store trust provider under slice 4 while keeping it unwired. Source
  checkpoint `7f354bc` binds that native result into target-plan ownership and
  discards caller-asserted certificate identity. Finish slices 2-3 by
  constructing the remaining retained non-certificate inputs, connecting the
  checkpointed owned exact target ahead of confirmation, and wiring stage-
  specific revalidation.

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

1. [x] Preserve the completed Task-099 evidence and activate Task-101 for the
   newly disclosed alert `#76`.
2. [x] Complete Task-101's supported Node/Puppeteer remediation and required
   clean-install, audit, lock-graph, frontend, browser, Windows-helper, and
   Docker-build validation.
3. [x] Merge PR #72 after its final exact-head checks pass, then confirm alert
   `#76` closes without dismissal on the default branch.
4. [x] Bring the accepted Task-101 change into Draft PR #67 and preserve its
   recorded ADR-019 proceed disposition during semantic reconciliation.
5. [x] Require green checks at the new exact PR #67 head.
6. [x] Explicitly resume Task-087 only after steps 4-5 pass.
7. [x] Require green checks on the Task-101 completion / Task-087 resume
   lifecycle head. At `6e0f744`, CI/CD run `32385304086` and Task-087 run
   `32385304052` passed.
8. [x] Validate the PR #67 technical/security remediation design through both
   `.agent_work` validators, diff/link/sanitization checks, current upstream
   toolchain review, and independent runtime/recovery/security-boundary audits.
9. [x] Obtain explicit project-lead approval before IMPLEMENT; approval was
   recorded August 21 for the August 20 remediation design.
10. [ ] Implement the exact-target, trusted-runtime, Windows-trust, durable-
   recovery, cross-session-lock, filesystem, and provider `.env` source gate;
   run adversarial/local/live-isolated validation without reviving earlier
   helper, bypass, admin, runtime-default, or volume-deletion paths.
11. [ ] Require exact-head CI/Task-087 checks and independent technical/security
    re-review before any PR #67 merge decision.
12. [ ] Complete staged-byte/archive verification and the explicit hash-locked
    Python 3.12 provenance-v2 build gate, then integrate a new normal-user
    unsigned preview-package path with accurate manifests, checksums, notices,
    and user guidance.
13. [ ] Test each published `v0.1.3-preview.N` through the actual GitHub download
    path on an approved unmanaged clean Windows machine without security
    exclusions or bypass instructions.
14. [ ] Keep production signing and representative managed-endpoint validation
    scheduled as Task-100 after the ADR-019 satisfactory-package decision.
15. [ ] Select Task-096 next, followed by Task-097. Keep Tasks 091-093 behind
    the stable unsigned package/runtime-shape boundary; Task-091 prepares the
    owner-runnable harness before Task-100.

Task-058 and Task-059 remain conditional stretch work. Task-094 remains
evidence-gated. Task-101 is completed, and Task-087 is active in PR #67 Gate A
IMPLEMENT. Task-099 and Task-101 stay in `tasks/active/` until
Sprint 09 closeout.

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
