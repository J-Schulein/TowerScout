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
  dismissal, and the August 11 closeout contained only the eight documented
  torch residuals.
- High-severity development-transitive `extract-zip` alert `#76` opened after
  that closeout. Backlog Task-101 owns its assessment; review may continue, but
  PR #67 merge and preview/candidate publication remain gated.
- Task-087 proceeds through technical/security review and preview-package
  integration. Existing validation ZIPs remain nonpublishable.
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
package path. Task-101 now gates merge and publication; Task-100 signing and
representative managed-endpoint qualification remain required before any
signed-candidate or production claim.

## Archived Planning And Release History

Superseded strategies, July 22 roadmap iterations, external reviews, and
v0.1.0-v0.1.2 publication checklists moved to:

- [`context/archive/2026-07/Handoff-Planning/`](../../archive/2026-07/Handoff-Planning/)

They are historical evidence only. Their dates, commands, and adoption
recommendations do not authorize current execution.
