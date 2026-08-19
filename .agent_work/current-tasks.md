# Current Tasks - Sprint 09

**Sprint Period**: August 8-August 21, 2026
**Last Updated**: August 19, 2026
**Focus**: Complete the active Task-101 dependency-security gate while new
Task-087 implementation and package work are paused. Preserve Draft PR #67 for
reviewer input, then resume Task-087 after the blocking audit and required
compatibility checks pass.

**Current Release State**:

- Fork-side `v0.1.2` is the immutable pilot package.
- New development uses immutable `v0.1.3-rc.N` candidate identities.
- Dependabot alert `#76` is an open high-severity development-only transitive
  `extract-zip==2.0.1` finding. Task-101 is active; PR #67 review may continue,
  but new Task-087 implementation, merge, and candidate publication wait for
  Task-101 acceptance.
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
Task-101 rather than rewriting Task-099. The blocking frontend gate prevents
Task-087 resumption, PR #67 merge, and candidate publication until Task-101
passes; reviewer input may continue.

### **TASK-101: extract-zip Advisory Assessment And Release-Gate Disposition**

**Status**: IN_PROGRESS - selected August 19; exact dependency and supported-
path reachability are classified, while the focused Node/Puppeteer remediation
and regression validation remain open
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
- Implement and validate a supported Node/Puppeteer dependency path that
  removes vulnerable `extract-zip`; do not use `npm audit fix --force`, weaken
  the high-severity gate, or dismiss the alert.
- Align the maintained Node baseline across CI, `package.json`, and the Docker
  frontend stage, and remove the redundant Puppeteer browser-download path
  from Task-087 workflows that already install a pinned browser separately.
- Require clean install/audit/lock-graph, frontend bundle/contracts, Task-087
  browser/Windows-helper, and Docker build validation before acceptance.
- Keep PR #67 open for reviewer input. New Task-087 implementation, merge, and
  candidate-package work remain paused until Task-101 passes.

### **TASK-087: Host-Side TLS Repair Control Plane**

**Status**: PAUSED / DEPENDENCY-GATED - Draft PR #67 and its recorded Task-087
implementation evidence remain preserved and reviewable. No new launcher or
package implementation, merge, or publication proceeds until active Task-101
restores the blocking frontend dependency gate. After Task-101 passes, bring
the accepted change into PR #67 and resume from the preserved checkpoint.
**Type**: B/C (Runtime Support / Setup UX / TLS Trust)
**Priority**: HIGH
**Estimated Effort**: Prototype through August 14; proceed, revise, or stop at
that decision gate
**Task File**:
`.agent_work/tasks/active/TASK-087-host-side-tls-repair-control-plane.md`

**Current Scope And Gates**:

- Preserve the visible Python/Tkinter launcher, bounded native transaction,
  existing evidence, and reviewer context while Task-101 is active.
- Queue implementation-producing review changes until Task-087 resumes;
  clarification and documentation review may continue.
- Generate the full-runnable validation package from the accepted
  post-reconciliation commit in an approved environment; local PowerShell
  policy blocks the normal base-package generator on this workstation.
- Run UI-driven Docker Google Maps, Azure Maps, and controlled
  recovery/rollback validation while preserving named volumes.
- Configure an approved non-Docker-Desktop Podman Compose provider separately
  before any Podman mutation; do not silently install or select a provider.
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

1. Preserve the completed Task-099 evidence and activate Task-101 for the
   newly disclosed alert `#76`.
2. Complete Task-101's supported Node/Puppeteer remediation and required
   clean-install, audit, lock-graph, frontend, browser, Windows-helper, and
   Docker-build validation.
3. Reconcile alert `#76` without dismissal, then bring the accepted Task-101
   change into Draft PR #67 and resume Task-087.
4. Require green checks at the new exact PR #67 head.
5. Generate and verify the exact-source full-runnable Task-087 package in an
   approved environment.
6. Complete the Docker Google/Azure and controlled recovery validation, then
   the approved-provider Podman coverage.
7. Complete technical/security review, signing-path coordination, and
   representative managed-endpoint validation as applicable.
8. Record the Task-087 proceed/conditional/stop decision.
9. If Task-087 proceeds, select Task-096 next, followed by Task-097. Keep Tasks
   091-093 behind the stable candidate/runtime boundary.

Task-058 and Task-059 remain conditional stretch work. Task-094 remains
evidence-gated. Task-101 is active with its Type C task file; Task-087 remains
active in tracking but paused on that gate. Task-099 stays in `tasks/active/`
until Sprint 09 closeout.

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
