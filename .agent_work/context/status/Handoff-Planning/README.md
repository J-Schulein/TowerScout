# Handoff Planning - Current Navigation

## Read First

1. [`2026-07-23-OCTOBER-FIX-FIRST-IMPLEMENTATION-ROADMAP.md`](./2026-07-23-OCTOBER-FIX-FIRST-IMPLEMENTATION-ROADMAP.md)
   - canonical forward-development, qualification, release, and handoff plan
2. [`PILOT-FEEDBACK-AND-CDC-AI-ADOPTION-PLAN.md`](./PILOT-FEEDBACK-AND-CDC-AI-ADOPTION-PLAN.md)
   - current rules for the unchanged `v0.1.2` pilot and cdcai feedback hold
3. [`PILOT-OPERATIONS-PACKET.md`](./PILOT-OPERATIONS-PACKET.md)
   - completed July 13 pilot distribution, support, and custody record
4. [`GITHUB-CODE-SCANNING-READINESS-ASSESSMENT-2026-07-23.md`](../../analysis/GITHUB-CODE-SCANNING-READINESS-ASSESSMENT-2026-07-23.md)
   - 62-alert dependency inventory, applicability, and Tasks 090/098 gate
5. [`.agent_work/current-tasks.md`](../../../current-tasks.md)
6. [`ADR-019: Unsigned Preview And October Production Signing`](../../../decisions/019-unsigned-preview-and-october-production-signing.md)
7. [`HANDOFF.md`](../../../../HANDOFF.md)

## Current Decision

- Keep the six `v0.1.2` pilot assets immutable.
- Refine owner-requested fixes through immutable unsigned
  `v0.1.3-preview.N` fork-side GitHub prereleases; never mark them `Latest`.
- Reserve `v0.1.3-rc.N` for the signed production-shaped candidate produced
  under Task-100.
- Do not publish `v0.1.3` final prematurely.
- Keep `cdcai/TowerScout` unchanged until the owner-qualified final candidate
  receives explicit adoption approval.
- Qualify Docker CPU, Docker GPU, Podman CPU, and Podman GPU.
- Task-090 alert classification and Task-098 mandatory remediation are
  complete as of their July 27 closeout.
- Task-099 completed alerts `#72-#75` plus npm finding
  `GHSA-5p4m-2wfm-xmqj` through PRs #68/#69. Alert `#74` closed without
  dismissal, and its August 11 closeout contained the eight documented torch
  residuals.
- High-severity development-transitive `extract-zip` alert `#76` opened after
  that closeout. Task-101's focused Node/Puppeteer remediation passed final PR
  and exact-main validation, PR #72 squash-merged as `0cc189c`, and the alert
  closed as fixed without dismissal. PR #73 recorded the post-merge checkpoint,
  squash-merged as `9276084`, and passed exact-main CI/CD and Task-087 checks.
- The merge integrated `main` through `9276084` into Draft PR #67 while
  preserving ADR-019 and its evidence. Reconciliation commit `946deaf` then
  passed exact-head CI/CD run `32383065903` and Task-087 run `32383065959`,
  completing Task-101's remaining acceptance gate.
- This governance update marks Task-101 complete and explicitly resumes
  Task-087 from its preserved checkpoint. Task-087 is resumed /
  governance-head-validation-pending: PR #67 remains open for reviewer input,
  but no further
  implementation proceeds until CI/CD and Task-087 workflows pass at the new
  governance head. Merge to `main` and preview/candidate publication remain
  behind Task-087's other applicable gates.
- Existing Task-087 validation ZIPs remain nonpublishable.
- Complete Task-100 production signing and representative managed-endpoint
  qualification in October after the unsigned package is satisfactory.
- Complete operational closeout by October 30, 2026.

## Active Validation Record

The frozen Pilot Package remains active while feedback is collected. Its
sanitized validation record remains under:

- [`v0.1.2-Validation-Evidence/`](./v0.1.2-Validation-Evidence/)

This evidence proves the Pilot Package; it does not certify a future candidate.

The separate current Task-087 functional record is:

- [`../../../tasks/active/TASK-087/FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md`](../../../tasks/active/TASK-087/FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md)

That record covers authorized unsigned development-workstation validation only
and cannot be uploaded or renamed as a preview. Later exact-source Task-087
evidence passed packaged Docker and approved-provider Podman Google/Azure,
recovery, provider-install, and rootless-Podman gates. The August 19 decision
allows technical/security review and a separate normal-user unsigned preview-
package path. Task-101's remediation, default-branch result, and checkpoint have
passed, and reconciliation commit `946deaf` passed its exact-head matrix. This
governance update completes Task-101 and explicitly resumes Task-087, but the
new governance head must pass CI/CD and Task-087 workflows before further
implementation. Task-087's remaining gates still control merge and publication;
Task-100 signing and representative managed-endpoint qualification remain
required before any signed-candidate or production claim.

## Archived Planning And Release History

Superseded strategies, July 22 roadmap iterations, external reviews, and
v0.1.0-v0.1.2 publication checklists moved to:

- [`context/archive/2026-07/Handoff-Planning/`](../../archive/2026-07/Handoff-Planning/)

They are historical evidence only. Their dates, commands, and adoption
recommendations do not authorize current execution.
