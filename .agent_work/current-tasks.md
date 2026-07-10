# Current Tasks - Active Sprint

**Sprint Period**: Sprint 07 begins July 2, 2026
**Last Updated**: July 10, 2026
**Focus**: Distribute the validated fork-side `v0.1.2` pilot, establish an owner-controlled feedback/support path, preserve a clean handoff if the project ends July 15, and defer cdcai adoption until the owner reviews pilot feedback.
**Status**: The `v0.1.2` release passed the full four-cell Docker/Podman CPU/CUDA matrix with both Google and Azure providers and is ready for pilot distribution. `cdcai/TowerScout` remains intentionally unchanged during the feedback hold. A possible three-month extension does not change the immediate pilot-first plan.

---

## Sprint 06 Closeout Summary

Sprint 06 produced the V1 RC / pilot-ready Windows package path and carried it from RC1 package validation through RC7.1 tester-facing release validation. Final V1 completion is still separate: it depends on pilot/UAT feedback, blocker triage, and explicit disposition of remaining support or V1 patch work.

Completed Sprint 06 task artifacts moved from `.agent_work/tasks/active/` to `.agent_work/tasks/completed/`:

- `TASK-065`: release packaging and runtime support follow-through
- `TASK-066`: release candidate validation gate
- `TASK-067`: CI release gate tightening
- `TASK-069`: license and release policy review
- `TASK-071`: end-user release package documentation
- `TASK-072`: release asset bundle contract
- `TASK-073`: clean-machine pilot / UAT execution plan
- `TASK-074`: runtime prerequisite preflight
- `TASK-075`: single GPU-capable package implementation
- `TASK-079`: RC1 reliability fixes and performance instrumentation
- `TASK-080`: UAT user guide and setup process simplification
- `TASK-081`: RC3 runtime hardening and Podman independence
- `TASK-082`: RC4 documentation and package organization
- `TASK-083`: RC5 Podman independence, GPU CDI, and release validation
- `TASK-084`: GA packaging hardening and Podman provider onboarding
- `TASK-085`: dataset ZIP restore path traversal hardening
- `TASK-086`: provider TLS auto-repair and setup triage

Sprint 06 closeout records:

- Retrospective: [SPRINT-06-RETROSPECTIVE-ANALYSIS-2026-07-02.md](./context/analysis/SPRINT-06-RETROSPECTIVE-ANALYSIS-2026-07-02.md)
- Archived Sprint 06 plan: [SPRINT-06-PLAN.md](./context/archive/2026-07/status/SPRINT-06-PLAN.md)
- Completed task record: [completed-tasks.md](./completed-tasks.md)

---

## Sprint 07 Goal

Deliver a proof-backed, support-safe host-side control plane that can guide managed-network TLS repair and restart from the TowerScout setup experience without exposing arbitrary host-command execution or leaking certificate/provider details.

Sprint 07 starts with helper transport and security proof. Product UI integration and package inclusion are gated until the helper can prove loopback binding, token/origin controls, allowlisted script invocation, sanitized progress states, and correct runtime-profile targeting.

Because the project end date is now close, Sprint 07 also carries a bounded
pilot-transition lane. The exact fork-side `v0.1.2` assets will be distributed
for user feedback while `cdcai/TowerScout` remains unchanged. `TASK-089`
migration execution starts only after the cdcai owner reviews feedback and
approves an adoption baseline. That work must preserve the `TASK-086` fallback
and must not weaken the dark-control-plane guardrails.

---

## Active Sprint 07 Tasks

### **TASK-087: Host-Side TLS Repair Control Plane**
**Status**: IN_PROGRESS - Gate 3 non-mutating proof merged on `main`; later helper enablement and managed-network validation remain deferred
**Type**: B/C (Runtime Support / Setup UX / TLS Trust)
**Priority**: MEDIUM-HIGH
**Estimated Effort**: 4-7 days (32-56 hours), plus managed-network package validation
**Target Sprint**: Sprint 07
**Task File**: `.agent_work/tasks/active/TASK-087-host-side-tls-repair-control-plane.md`

**Objective**: Design and implement a support-safe host-side repair control plane that lets TowerScout present a guided "repair TLS trust and restart" action when provider setup detects a managed-network TLS certificate trust failure, while reusing the validated `TASK-086` repair flow.

**Sprint 07 Entry Conditions**:
- `TASK-086` remains the validated command-based repair baseline and fallback.
- RC7.1 tester-facing package validation has passed.
- The helper must be package-local, loopback-only, token-protected, allowlisted, and support-safe before it reaches product UI.

**Current Sprint 07 Work Sequence**:
1. Gate 1 / Gate 2 helper proof: merged in PR #45 with controlled Docker CPU/off live-wrapper evidence and helper security constraints.
2. Gate 3 non-mutating proof: merged through PR #46 on `main`, including the reviewed CI/gate hardening.
3. Gate 3 follow-up: add visible fallback/repair UI only after release work allows the later helper-availability and browser-mutation enablement slice to begin.
4. Gate 4 managed-network package validation: blocked until the later helper enablement slice passes and the release owner approves user-facing package inclusion.

**Evidence Handling**:
Do not record provider keys, helper tokens, certificate subjects, raw thumbprints, raw provider responses, `.env` files, raw logs, browser network traces, screenshots, private AOIs, or local environment dumps in task evidence. Use sanitized operation states and public-safe summaries only.

### **TASK-088: Stable Release And Handoff Closeout**
**Status**: IN_PROGRESS - `v0.1.2` is the frozen validated pilot baseline; remaining closeout is pilot-facing guide/support wording, owner-controlled feedback routing, evidence custody, and final handoff bookkeeping
**Type**: C (Release Engineering / Documentation / Handoff)
**Priority**: HIGH
**Estimated Effort**: 2-4 days (16-32 hours), excluding owner-gated migration follow-through
**Target Sprint**: Sprint 07
**Task File**: `.agent_work/tasks/active/TASK-088-stable-release-and-handoff-closeout.md`

**Objective**: Close out the validated fork-side pilot release, make the Monday distribution/support path unambiguous, and leave a clean handoff record that works whether the project ends July 15 or receives the possible three-month extension.

**Current Scope**:
1. Formalize the reviewed handoff plan into task-tracked execution rather than leaving it only in status analysis.
2. Record the merged PR #46 baseline and execute the pre-tag source pass required for a trustworthy stable release.
3. Validate the rebuilt stable package set and publish the fork-side stable release under the post-fix release identity.
4. Finalize pilot-facing guidance that distinguishes the fork download, the unchanged official cdcai repository, and the owner-controlled feedback channel.
5. Preserve a migration-ready handoff without changing cdcai before pilot feedback and owner approval.

**Important Boundaries**:
- Keep the fork release self-consistent even if cdcai release recreation happens later.
- Resolve the namespace/download-home sequencing explicitly before the first public stable package is published.
- Do not publish final GitHub Release assets under the current `v0.1.0` or `v0.1.1` identities; the active path is the `v0.1.2` release line built from the post-PR-48 frozen main baseline.
- Treat any `rc7.1` promotion fallback as an explicit release-identity decision, not as an implicit rename.
- Do not rebuild or replace the validated `v0.1.2` pilot assets; fixes require a new version.
- Do not present `cdcai/TowerScout` as the pilot download or modify it during the owner-approved feedback hold.

### **TASK-089: cdcai Adoption Preparation And Deferred Ownership Transfer**
**Status**: DEFERRED / OWNER-GATED - prepare the handoff now, but do not change cdcai until pilot feedback is reviewed and the owner approves an adoption baseline
**Type**: C (Repository Migration / Release Ownership / Handoff)
**Priority**: HIGH
**Estimated Effort**: 1-2 days (8-16 hours) once prerequisites are satisfied
**Target Sprint**: Sprint 07
**Task File**: `.agent_work/tasks/active/TASK-089-cdcai-migration-execution.md`

**Objective**: Prepare a safe, reviewable cdcai adoption package while keeping the official repository unchanged during the pilot, then transfer the owner-approved baseline only after feedback review.

**Execution Gates**:
1. Pilot feedback is collected and triaged.
2. The cdcai owner explicitly approves the version to adopt.
3. cdcai collaborator write, Actions, and package-publish ownership are confirmed.
4. A durable backlog/feedback destination is approved; it need not be cdcai Issues during the hold.
5. The image-copy-versus-rebuild and validation path is approved for the selected baseline.

---

## Near-Term Backlog Watch

These are not active Sprint 07 work unless explicitly selected:

| Task | Reason To Pull Forward |
|---|---|
| `TASK-076` Provider API Key Exposure And Restriction Policy | Needed before broader distribution if provider-key ownership/restriction policy is still informal. |
| `TASK-068` Windows Test Portability And Script Validation | Useful if Sprint 07 helper work exposes PowerShell or runtime-script gaps that should be covered outside manual validation. |
| `TASK-027` Enhanced Error Handling | Useful for the non-blocking v0.1.2 finding where Google mode reports a generic network error if a user clicks "Find towers" before defining a search area or boundary. |
| `TASK-077` Public Release Manifest And Asset Import Hardening | Remaining staged/allowlist asset-activation hardening if release feedback shows import risk. |
| `TASK-070` Restricted-Network Package Enhancements | Pull forward only if restricted-network/offline support becomes a launch requirement. |

---

## Sprint 07 Guardrails

- Do not weaken the manual `repair-provider-tls.cmd` fallback while building the guided helper.
- Do not mount Docker or Podman control sockets into the container for this feature.
- Do not let browser input become shell command text.
- Do not expose helper tokens or raw certificate/provider details through readiness, status, logs, DOM attributes, console output, task files, or support evidence.
- Do not start unrelated V2 architecture work while the host-side TLS repair proof is active unless the team intentionally pauses Sprint 07.

---

## Related Documentation

- [Current Pilot And Adoption Plan](./context/status/Handoff-Planning/PILOT-FEEDBACK-AND-CDC-AI-ADOPTION-PLAN.md)
- [Task Backlog](./task-backlog.md)
- [Completed Tasks](./completed-tasks.md)
- [Sprint 06 Retrospective](./context/analysis/SPRINT-06-RETROSPECTIVE-ANALYSIS-2026-07-02.md)
