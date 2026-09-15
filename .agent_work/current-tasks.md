# Current Tasks - Sprint 09

**Sprint Period**: August 8-August 21, 2026; active-task continuation retained
through the current Task-087 Gate A work
**Last Updated**: September 15, 2026
**Focus**: Task-101 is complete. Task-087 is the active implementation task.
Its canonical detailed
[`Gate A burn-down`](./tasks/active/TASK-087/GATE-A-STATUS.md) fixes the approved
nine-slice scope and distinguishes complete, partial, not-started, and
validation states. The September 14 checkpoint closes slices 2-3: confirmation
now consumes and retains the native exact target, shows only its public summary,
times out and cleans up safely, and exposes ordered revalidation hooks. Slice 4
remains partial: cache-only revocation was restored during independent review,
and the current workstation now fails closed for Azure because cached
revocation status is offline/unknown. Earlier network-disabled Docker and
rootless-Podman checks prove one-root transport containment only. Windows
security remains partial, but the protected Local AppData and current-user
DPAPI foundation is now independently reviewed with focused/native proof.
Secure `.env` absence ownership is independently reviewed and checkpointed.
The pure, unwired `.env` byte-transform/state-classification prerequisite for
atomic replacement is committed, independently reviewed, and exact-head
validated. Independently reviewed implementation checkpoint `1c45445df82e`
adds private, journal-gated, same-directory native candidate staging with
restrictive ACL, identity, flush/readback, and no-follow reopen verification.
It passed exact-head CI/CD run `35005869321`, Task-087 run `35005869200`, and
Trivy; the main-only build skipped as designed. Documentation checkpoint
`42180b10e7f` then passed CI/CD run `35006846090`, Task-087 run `35006846025`,
and Trivy, with the main-only build skipped as designed. Independently reviewed
and exact-head validated checkpoint `8bb6b33` adds strict canonical encoding,
DPAPI-backed generation authentication, and fail-closed unique-chain/pointer
classification for the environment-temp prelude. Checkpoint `53bed46` adds
protected-root-owned persistence/enumeration orchestration, and checkpoint
`4a96dd2` adds native protected-DACL generation enumeration/create/read with
flush/reopen verification. Pointer repair, backup/recovery actions,
promotion/replacement, transaction refactoring, provider-installer completion,
and final proof remain.
No repair or mutation is enabled. Gate B preview integration and Task-100
signing remain separate. Earlier independently reviewed checkpoint `2edcb8e`
adds the protected Local AppData/current-user DPAPI
foundation. Earlier checkpoint `0882017` connects the retained inputs through
Windows trust and native observation to a revalidated, still-held exact target
and consumes that owner in production confirmation. Earlier checkpoint
`caf3f1c` retains the package and Windows process environment, runtime and
endpoint, acceleration evidence, and final exact-plan inputs. Earlier
checkpoint `17d813f` retains the authenticated managed Podman provider and its
base CPython dependency closure.

**Current Release State**:

- Fork-side `v0.1.2` is the immutable pilot package.
- Iterative unsigned fork packages use immutable `v0.1.3-preview.N` GitHub
  prereleases and are never marked `Latest`.
- `v0.1.3-rc.N` is reserved for the signed production-shaped candidate created
  under Task-100.
- Task-101 is complete; alert `#76` closed as fixed without dismissal. Its
  reconciliation and lifecycle evidence remains in the completed-task record.
- Task-087 implementation checkpoint `95ca37d68e2` is independently reviewed,
  pushed, and exact-head validated: CI/CD run
  `35021545053`, Task-087 run `35021545062`, and Trivy passed; the main-only
  build was neutral as designed. It adds native protected pointer reads and
  same-directory temp creation, write/flush/dual verification,
  close-before-rename `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`,
  source-name absence proof, and destination identity/DACL/path/byte
  verification above checkpoint `221612c`'s pure pointer policy. Documentation
  checkpoint `145e0b9` passed exact-head CI/CD run `35022713082`, Task-087 run
  `35022713013`, and Trivy; the main-only build was neutral as designed. A local
  independently reviewed source candidate now accepts an ordinary move API
  error as success only when the same call proves the source absent and the
  destination has the exact pre-move identity, protected DACL, path, size, and
  bytes. It performs no cleanup and has no restart classification, durable
  temp-identity binding, backup/recovery action, staging integration, promotion,
  `.env` replacement, or repair mutation. PR #67 remains Draft.
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

**Status**: IN_PROGRESS / IMPLEMENT - Gate A is materially advanced and remains
open. Slices 1-3 are complete. The September 14 checkpoint connects the
retained exact-target facade to bounded typed confirmation and adds ordered
revalidation hooks. Slice 4 remains partial: the independently reviewed native
path limits authorization to one eligible Windows root and a bounded exact
intermediate snapshot, but the supported fixed-host proof remains open because
cache-only revocation currently fails closed with offline/unknown status.
Earlier Docker/rootless-Podman checks prove transport containment only. Slices
5 and 8 are partial; slice 5's protected Local AppData/current-user DPAPI
foundation and secure-absence owner are independently reviewed and
checkpointed. Its pure `.env` byte-transform/state-classification prerequisite
is committed, independently reviewed, and exact-head validated. Independently
reviewed checkpoint `1c45445` adds private journal-gated restrictive temp
staging with native Windows DACL, identity, complete-write, flush/readback, and
no-follow reopen proof. Its exact-head CI/CD and Task-087 workflows pass.
Durable journal storage, native promotion/replacement, indeterminate-result
classification, and cleanup remain open. Slice 6 is now partial: independently
reviewed and exact-head validated checkpoint `8bb6b33` adds strict DPAPI-
protected generation/pointer codecs and unique-chain selection for the
environment-temp prelude. The selector authenticates every sealed candidate
internally. Independently reviewed and exact-head validated checkpoint
`53bed46` adds only root-owned persistence/enumeration orchestration over an
injected storage port. No
pointer repair, backup, or recovery action existed at that checkpoint. The next
increment implemented the native generation-file adapter, passed two independent
source/security reviews, was checkpointed at `4a96dd2`, and is exact-head
validated. Checkpoint `221612c` adds pointer-aware authenticated load and pure
missing/stale pointer repair orchestration through an injected port and is
exact-head validated. Checkpoint `95ca37d` adds native pointer replacement and
exact success-path verification and is independently reviewed and exact-head
validated. A local independently reviewed source candidate adds exact same-call
completed-move reconciliation after an ordinary API error. Restart
classification, durable temp-identity binding, and cleanup remain open. Slice 7
is not started; slice 9 continues incrementally. Mutation is disabled and PR #67
remains Draft.
**Type**: B/C (Runtime Support / Setup UX / TLS Trust)
**Priority**: HIGH
**Remaining Estimate**: Complete slice 4's revocation-aware fixed-host and
container proof, then track the three remaining implementation/proof outcome
groups in the canonical burn-down
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
  discards caller-asserted certificate identity. Independently reviewed
  checkpoint `c84998c` removes certificate identity from the retained
  input-owner contract entirely; the public production handoff accepts it only
  from its internal fixed Windows-trust wrapper before assembly. Reviewed and
  pushed checkpoint `ebd53c9` corrects the Docker source adapter to use the real
  retained PE/Authenticode runtime owner and jointly revalidates the exact
  Docker runtime/endpoint pair. Independently reviewed and pushed checkpoint
  `6c51441` adds the separately authenticated Docker Compose executable, binds
  both Docker executables to one policy and installation directory, and emits
  only redacted target identities. Independently reviewed and pushed checkpoint
  `e59f150` jointly retains and revalidates the authenticated Podman runtime,
  package-selected rootless endpoint, machine configuration, and identity key.
  Independently reviewed and pushed checkpoint `c0639c7` authenticates the exact
  managed-provider catalog bytes and wheel-derived installed inventory;
  corrective checkpoint `454af79` keeps the build-inspector policy pin in sync.
  Independently reviewed checkpoint `7a0c35a` reconciles the deterministic provider-only
  installed `site-packages` inventory with retained verified wheels, a self-reported compatible
  CPython 3.12.10 installer input, exact wheel-byte materialization, no embedded
  packaging bootstrap or wrapper, and bytecode suppression across the current
  PowerShell Podman-provider path. The future native command adds `-I -B` but
  remains unwired. The external
  installer does not authenticate that ambient Python; the retained native
  owner must establish interpreter trust before any provider use.
  Checkpoint `caf3f1c` adds the retained package/process environment and
  acceleration authorities plus the final exact-input composer. Checkpoint
  `db7aee8` connects those inputs through Windows trust and native observation
  to one revalidated, still-held exact target. Test-only checkpoint `9993b4d`
  repairs Linux package imports in the four new runtime/target test modules;
  both Python 3.11 and 3.12 GitHub unit jobs pass at that exact branch head.
  The September 14 checkpoint makes confirmation consume that owner and adds
  ordered stage-specific revalidation. Independent review reconciled three
  findings: invalid ordering now invalidates the transaction, cache-only
  revocation is enforced, and candidate intermediates must belong to the exact
  bounded Windows-`CA`/server snapshot. Slices 2-3 close here; slice 4 remains
  open pending a successful revocation-aware fixed-host and repeated container
  containment proof.

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
