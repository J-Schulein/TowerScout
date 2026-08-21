# Current Tasks - Sprint 09

**Sprint Period**: August 8-August 21, 2026
**Last Updated**: August 21, 2026
**Focus**: Task-101 is complete and Task-087's lifecycle head `6e0f744` passed
its exact-head CI/CD and Task-087 matrices. Independent technical/security
review then requested source changes on Draft PR #67. Complete and approve the
Task-087 remediation design, implement the source gate, obtain exact-head
re-review, and only then continue unsigned preview-package integration under
ADR-019. Production signing remains Task-100 work in October after the package
is satisfactory.

**Current Release State**:

- Fork-side `v0.1.2` is the immutable pilot package.
- Iterative unsigned fork packages use immutable `v0.1.3-preview.N` GitHub
  prereleases and are never marked `Latest`.
- `v0.1.3-rc.N` is reserved for the signed production-shaped candidate created
  under Task-100.
- Dependabot alert `#76` closed as fixed, without dismissal, after PR #72
  squash-merged as `0cc189c`. PR #73's checkpoint then squash-merged as
  `9276084` and passed exact-main checks. PR #67 reconciliation head `946deaf`
  then passed CI/CD run `32383065903` and Task-087 run `32383065959` with all
  required jobs successful. Task-101 is complete. The lifecycle update
  `6e0f744` then passed CI/CD run `32385304086` and Task-087 run `32385304052`.
  Task-087 is active in Gate A IMPLEMENT under the project lead's August 21
  approval after the independent source review requested changes; PR #67
  remains Draft.
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

**Status**: IN_PROGRESS / IMPLEMENT - the exact-source `7ef879c`
full-runnable CPU packages passed Docker and approved-provider Podman
Google/Azure TLS repair plus controlled recovery. Follow-up head `3990bc0`
closed provider-installer dependency drift with a hash-approved offline
wheelhouse, and head `5737a58` enforced the selected Windows rootless-Podman
boundary without changing machine mode or volumes. PR #72 and alert `#76`
default-branch reconciliation passed, and PR #67 head `946deaf` passed CI/CD
run `32383065903` plus Task-087 run `32383065959`. Task-101 is complete, and
the lifecycle update resumed Task-087 while preserving the evidence and
ADR-019. That exact lifecycle head `6e0f744` passed CI/CD run `32385304086` and
Task-087 run `32385304052`. Independent technical/security review then
requested source changes. On August 21, the project lead explicitly approved
moving Task-087 to IMPLEMENT under the August 20 remediation design. Gate A
source implementation is now active while PR #67 remains Draft.
**Type**: B/C (Runtime Support / Setup UX / TLS Trust)
**Priority**: HIGH
**Remaining Estimate**: Rebaselined after review: approximately 6-10 focused
implementation days plus live Windows/Docker/Podman validation and re-review
timing; preview integration remains a later gate
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
- Treat the August 20 external review as outside input rather than authority.
  Independent inspection agrees that runtime/endpoint/Compose/target binding,
  durable verified rollback, Windows-only trust selection, cross-session
  locking, Windows file safety, staged-byte provenance, build-toolchain
  integrity, and root `.env` backup handling require correction. Follow the
  task-local
  [`TECHNICAL-SECURITY-REMEDIATION-DESIGN-2026-08-20.md`](./tasks/active/TASK-087/TECHNICAL-SECURITY-REMEDIATION-DESIGN-2026-08-20.md).
- The first local Gate A increment is intentionally inert. Local commit
  `7ad221d` disables the default application mutation path and adds immutable
  target contracts; the follow-on local checkpoint adds fixed read-only
  Docker/Podman command plans, handle-bound Windows file identity primitives,
  canonical mutex-name derivation, and a pure Windows-root selection policy.
  Focused and broad unit/static checks plus three independent scoped reviews
  pass. No new source checkpoint has been pushed, no process executor or native
  trust verifier is wired, and mutation remains disabled while runtime policy,
  provider import proof, ACL/mutex/journal/recovery, and `.env` transaction work
  remain open.
- Keep source, preview, and signing gates separate. Findings 1-8 and the
  source-level provider `.env` correction gate PR #67 source re-review;
  staged-copy/provenance-v2 and the explicitly approved exact-patch/hash-locked
  Python 3.12 build gate a new validation artifact or unsigned preview;
  Task-100 still owns production
  signing and representative managed-endpoint qualification.
- Preserve the existing no-helper/no-listener/no-PowerShell/no-admin boundary,
  explicit Task-086 fallback, rootless-Podman-without-default-change boundary,
  all eight named volumes, and normal OneDrive-compatible package behavior.
  PR #67 remains Draft, and no merge, package, or publication acceptance is
  implied by lifecycle checks or the design checkpoint.
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
