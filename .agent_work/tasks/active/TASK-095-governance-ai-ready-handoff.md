# TASK-095: Governance And AI-Ready Handoff Foundation

**Status**: IN_PROGRESS - Phase A complete; Phase B continues through handoff
**Priority**: HIGH
**Type**: C (Governance / Documentation / Handoff)
**Estimated Effort**: Phase A 1-2 days; Phase B 2-4 distributed days
**Target**: Phase A July 23, 2026; Phase B complete by October 30, 2026
**Owner**: Project lead with cdcai owner participation
**Created**: July 23, 2026

## Objective

Maintain one accurate, low-noise project control plane and leave the cdcai
owner a tool-neutral foundation for future maintenance, backlog work, and
optional AI-assisted development.

## Requirements

- WHEN the roadmap changes, THE PROJECT SHALL update one canonical roadmap and
  archive superseded drafts.
- WHEN task work is selected, THE PROJECT SHALL keep current, backlog,
  completed, and individual task records synchronized.
- WHEN ownership transfers, THE PROJECT SHALL provide repository-native,
  tool-neutral maintenance instructions and backlog context.
- WHEN old context remains useful only as history, THE PROJECT SHALL archive it
  rather than leave it in active status.
- BEFORE runtime-dependent validation, THE ACTIVE AGENT SHALL ask the user to
  start the required Docker Desktop and/or Podman runtime.

## Phase A - Roadmap And Workspace Rebaseline

### Acceptance Criteria

- [x] Establish one canonical October fix-first roadmap.
- [x] Record the fix-first/repository/release-naming decision in an ADR.
- [x] Confirm unique definitions for Tasks 090-097.
- [x] Close Sprint 07 and open Sprint 08.
- [x] Move completed Task-088 to `tasks/completed/`.
- [x] Reconcile `current-tasks.md`, `task-backlog.md`, and
  `completed-tasks.md`.
- [x] Replace obsolete current requirements/design with concise current
  sources and preserve their previous versions in the archive.
- [x] Archive superseded planning drafts, reviews, release checklists, and
  historical implementation strategies.
- [x] Keep the `v0.1.2` Pilot plan current for the pilot track while marking the
  new roadmap as the forward-development source.
- [x] Update `.agent_work` navigation, `HANDOFF.md`, and primary agent guidance.
- [x] Record the runtime-startup coordination preference.
- [x] Pass the quick workspace check, canonical validator, link/reference
  review, and `git diff --check`.

## Phase B - Ongoing Governance And Final Handoff

### Acceptance Criteria

- [ ] Keep task disposition and milestone status current through freeze.
- [ ] Maintain a prioritized, owner-readable Markdown backlog.
- [ ] Document tool-neutral task planning, implementation, validation, release,
  rollback, and maintenance procedures.
- [ ] Record optional AI-assisted workflows without requiring a particular
  vendor or tool.
- [ ] Decide whether GitHub Issues supplement the Markdown backlog.
- [ ] Verify repository access, release/package custody, and external guide/
  video custody.
- [ ] Keep Task-100's satisfactory-package entry gate, October signing work,
  and managed-endpoint acceptance synchronized across release/handoff sources.
- [ ] Keep newly disclosed critical/high dependency findings assigned to unique
  follow-up tasks without rewriting completed-task history or weakening gates.
- [ ] Ensure final documentation identifies current, historical, and archived
  sources unambiguously.
- [ ] Complete owner review and final sign-off by October 30.

## Dependencies

- Project lead and cdcai owner roadmap decisions
- Tasks 087 and 089
- Tasks 090-101 as formalized by current roadmap decisions
- Final candidate and handoff evidence

## Implementation Log

### 2026-08-20 - PR #67 Current-Main Reconciliation

**Objective**: Preserve the accepted Task-087/ADR-019 branch record while
integrating the completed Task-101/default-branch state into Draft PR #67.

**Context**: PR #73 squash-merged the post-PR72 checkpoint as `9276084`, and
its exact-main CI/CD and Task-087 workflows passed. PR #67 remained Draft and
conflicted at `c095389` with nineteen evidence-bearing branch commits.

**Decision**: Merge current `main` normally, resolve the shared control-plane
sources semantically, and leave Task-101 active plus Task-087 paused until the
new exact PR #67 head passes. Preserve the unsigned-preview/Task-100 sequence.

**Execution**: Integrated `main` through `9276084` without rebasing or
force-pushing. Preserved ADR-019, current Task-087 evidence, the immutable
pilot/cdcai boundary, and Task-100 while importing the Node/Puppeteer security
baseline and current Task-101 gate state.

**Validation**: PR #73/default-main evidence is green. Local reconciliation
passed the broad executable unit suite, clean npm/audit and exact dependency
graph, bundle/contracts, Docker frontend plus full-image builds with the CA
secret absent and present, secret non-persistence inspection, both agent-work
validators, and diff checks. Endpoint antivirus blocked local loading of the
unchanged PowerShell host-helper script; no bypass was used, and the new exact
PR #67 workflow matrix remains pending. This entry does not complete Task-101
or resume Task-087.

**Next**: Push the merge commit and require green exact-head checks before a
separate lifecycle-transition update.

### 2026-08-20 - Task-101 Post-Merge Governance Checkpoint

**Objective**: Reconcile the current control-plane sources after the accepted
Task-101 remediation reached the default branch.

**Context**: PR #72 final head `820b649` passed CI/CD run `32308971393` and
Task-087 run `32308971392`, then squash-merged as `0cc189c`. Exact-main CI/CD
run `32310281115` and Task-087 run `32310281051` passed. Alert `#76` is fixed
through dependency reconciliation and has no dismissal metadata.

**Decision**: Mark the PR #72 and default-branch alert gates complete without
marking Task-101 complete or resuming Task-087. Task-101 remains active for PR
#67 semantic integration and exact-head validation; Task-087 remains paused /
reconciliation-gated through that checkpoint.

**Execution**: Updated the current task, backlog, requirement, design, roadmap,
pilot, handoff, task, decision, and agent-guidance sources. Historical task
logs, completed-task records, pilot assets, and the cdcai hold remain unchanged.

**Validation**: PASS. The quick workspace checker, canonical `.agent_work`
validator, and `git diff --check` passed on August 20. The checkpoint records
only sanitized GitHub identifiers and state.

**Next**: Merge current `main` normally into Draft PR #67, resolve the shared
governance sources semantically while preserving ADR-019 and branch evidence,
and require the reconciled exact-head matrix before closing Task-101 or
resuming Task-087.

### 2026-08-19 - Task-101 Quality Review Gate Reconciled

**Objective**: Keep the Task-101 evidence and Task-087 resume boundary
unambiguous after PR #72's independent quality review.

**Context**: The implementation head passed its main CI and all three Task-087
compatibility jobs. The review found the committed evidence state lagged those
runs and several current sources could be read as resuming Task-087 before PR
#67's new exact-head validation.

**Decision**: Record implementation head `a87ab53`, CI/CD run `32300398378`,
and Task-087 run `32300398377`. Standardize the downstream order as PR #72
merge, alert `#76` closure without dismissal, PR #67 semantic integration,
green PR #67 exact-head checks, and only then Task-087 resumption. Keep final
PR #72 check evidence in the PR description so an evidence-only commit does
not invalidate its own claim.

**Execution**: Reconciled the current task, backlog, requirement, design, ADR,
roadmap, Task-087, handoff, and Copilot sources. The CI quality ratchet also
adds a blocking Docker frontend-stage PR job and focused semantic contract.

**Validation**: The focused suite passed `12` tests; the uncached Docker
frontend-stage build, CI workflow summary, both agent-work validators, and
`git diff --check` passed. No raw log, provider data, certificate detail, or
local path was added to repository evidence.

**Next**: Require the review-remediation commit's exact-head PR checks, then
preserve the ordered post-merge gates without resuming Task-087 early.

### 2026-08-19 - Task-101 Activated And Task-087 Paused

**Objective**: Reflect the project lead's decision to resolve the blocking
dependency-security gate before continuing Task-087 implementation.

**Context**: Alert `#76` is a development/browser-install exposure rather than
an end-user runtime dependency. The frontend audit is intentionally blocking,
and a supported upstream removal path requires a tested Node/Puppeteer change.

**Decision**: Select Task-101 directly into the active Sprint 09 lane and
pause, rather than discard, Task-087. Keep PR #67 open for reviewer input and
preserve its evidence. Resume implementation, merge, and package work only
after Task-101 passes.

**Execution**: Created the active Type C Task-101 record, marked Task-087
dependency-gated, and reconciled current roadmap, requirement, design, handoff,
and agent-guidance sources. Completed Task-099 history remained unchanged.

**Output**: One immediate implementation lane, an explicit paused-but-
reviewable Task-087 state, and a testable security-gate path back to candidate
package work.

**Validation**: PASS for the lifecycle transition on August 19, 2026. The
TowerScout quick workspace checker and canonical `.agent_work` validator
passed, `git diff --check` found no whitespace errors, and current relative
Markdown links resolved across the changed files.

**Next**: Implement and validate Task-101 from current `main`, reconcile alert
`#76`, bring the accepted result into PR #67, and then resume Task-087 from its
preserved checkpoint.

### 2026-08-19 - Alert 76 Current-Gate Reconciliation

**Objective**: Keep the live security inventory and release gates accurate
after GitHub surfaced a new high-severity dependency advisory.

**Context**: Pushing the ADR-019 documentation update caused the current
blocking frontend audit to evaluate Dependabot alert `#76`. The alert opened
August 12, after Task-099 completed on August 11, and affects development-only
transitive `extract-zip==2.0.1` through Puppeteer. The dependency is not shipped
in the product runtime image or end-user ZIP, but the browser-install test path
can execute it and no patched `extract-zip` release is currently listed.

**Decision**: Preserve Task-099 as a dated historical closeout and add backlog-
only Task-101 for supported-path assessment and release-gate disposition.
Allow reviewer feedback to continue, but hold PR #67 merge and preview/
candidate publication behind the deliberately blocking high-severity gate.

**Execution**: Reconciled the current task, backlog, requirements, design,
roadmap, adoption, handoff, status navigation, and agent-guidance sources. No
dependency, workflow, runtime, package, or historical Task-099 artifact was
changed, and no remediation direction was preselected.

**Output**: One current nine-alert inventory, a unique Task-101 backlog entry,
and an explicit distinction between review continuity and merge/publication
gates.

**Validation**: PASS on August 19, 2026. The quick workspace checker and
canonical `.agent_work` validator passed, and `git diff --check` found no
whitespace errors after reconciliation.

**Next**: Select Task-101 for bounded reachability and compatibility assessment
before PR #67 merge or any preview/candidate publication.

### 2026-08-19 - Preview And October Signing Rebaseline

**Objective**: Turn the project lead's sequencing decision into one consistent
release, task, and handoff policy.

**Context**: Task-087's functional package evidence had passed, but active
sources still required parallel signing and a signed managed-endpoint result
before merge or any GitHub release. The project lead instead wants to refine a
normal-user package first and complete signing in October once it is
satisfactory.

**Decision**: Separate immutable unsigned `v0.1.3-preview.N` GitHub
prereleases from signed `v0.1.3-rc.N` candidates. Add Task-100 as required
October backlog work after the ADR-019 satisfactory-package gate. Preserve all
existing Task-087 validation artifacts as nonpublishable and keep cdcai
owner-gated.

**Execution**: Added ADR-019 and reconciled active trackers, requirements,
design, roadmap/adoption navigation, Task-087/089 boundaries, launcher release
guidance, agent guidance, and handoff documentation. Task-100 remains in the
backlog until selected in October, so no premature active task file was
created.

**Output**: One documented preview-to-signing sequence with objective package
satisfaction, signing, endpoint, naming, and adoption gates.

**Validation**: PASS on August 19, 2026. The quick workspace checker and
canonical `.agent_work` validator passed; every changed-file Markdown link
resolved; the current-source contradiction audit found only explicitly
superseded historical wording; the release-boundary check confirmed the
existing Task-087 assembler remains validation-only and the normal release
builder still requires launcher integration; and `git diff --check` passed.

**Next**: Complete Task-087 review and normal release-package integration,
then refine unsigned previews until the Task-100 entry gate can be recorded.

### 2026-07-23 - Phase A Rebaseline

**Objective**: Replace the pre-decision planning state with one executable
fix-first roadmap before Task-090 begins.

**Context**: Sprint 07 still stated that no implementation task had been
selected. Active Handoff-Planning contained multiple drafts/reviews, while
prototype-era requirements/design text contradicted the current release and
runtime model.

**Decision**: Use the July 23 fix-first roadmap as the current execution source;
retain the Pilot plan for the unchanged `v0.1.2` track; archive superseded
material; keep Task-095 active through final handoff.

**Execution**:

- Closed Sprint 07 and created a concise recent completion record.
- Opened Sprint 08 with Tasks 095, 090, 087, and owner-gated 089.
- Formalized roadmap definitions for Tasks 090-097.
- Rebuilt current requirements/design around the October plan.
- Archived older planning, review, and prototype-era source files.
- Updated navigation, handoff, pilot, and agent guidance.
- Added the Docker/Podman startup coordination rule.
- Archived three completed Task-087/PR #46 status packets, the superseded RC1
  repository intake workflow, and stale Sprint/source-install guides.
- Removed one byte-identical duplicate archive snapshot and replaced the
  status/guide placeholders with current navigation.
- Recorded the 62-alert GitHub code-scanning baseline and inserted Tasks
  090/098 into the security gate.

**Output**: One current roadmap plus separated pilot, historical, active-task,
and archive sources.

**Validation**: PASS on July 23, 2026:

- `check_agent_work_quick.py`: passed
- `validate_agent_work.py`: passed
- current-source Markdown link check: passed
- contradiction phrase audit: no active stale-plan match
- `git diff --check`: passed

**Next**: Start Task-090 only after explicit implementation approval. Use its
classification to approve the separate Task-098 remediation scope before
Task-087 resumes.

## Validation Results

### Phase A - July 23, 2026

**Test Status**: PASS

- [x] Active task membership matches `current-tasks.md`.
- [x] No loose task Markdown files exist in `tasks/`.
- [x] Active status contains the current roadmap, Pilot plan, Pilot custody
  record, and active Pilot validation evidence.
- [x] Superseded roadmap/review material is under the July archive.
- [x] Current-source Markdown links resolve.
- [x] No secret-bearing or raw runtime evidence was added.
- [x] Workspace validator and diff checks pass.
- [x] Completed loose status packets and superseded RC1/stale-guide workflows
  are archived outside the current information surface.
- [x] GitHub code-scanning findings are durably inventoried and connected to a
  separate remediation gate.

Phase A is complete. Task-095 remains active for Phase B governance and final
handoff maintenance.
