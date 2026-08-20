# TowerScout Pilot Feedback And cdcai Adoption Plan

**Decision Date**: July 10, 2026; rebaselined July 23, 2026
**Last Reconciled**: August 20, 2026
**Status**: CURRENT for the Pilot Package and cdcai hold
**Forward Development Plan**:
[`2026-07-23-OCTOBER-FIX-FIRST-IMPLEMENTATION-ROADMAP.md`](./2026-07-23-OCTOBER-FIX-FIRST-IMPLEMENTATION-ROADMAP.md)
**Pilot Baseline**: validated fork-side `v0.1.2`
**Pilot Distribution**: completed July 13, 2026
**Operational Closeout**: October 30, 2026
**Hard Project End**: October 31, 2026

## Pilot Decision

Keep `cdcai/TowerScout` unchanged while users test the `v0.1.2` Pilot Package
and while the fork develops and qualifies a fix-first successor.

Pilot identity:

- Download:
  `https://github.com/J-Schulein/TowerScout/releases/tag/v0.1.2`
- Source ref: `718a56485a59182f060a537e8f11d4ce71a1f0d4`
- Assets: existing six checksum-verified `v0.1.2` release assets
- Description: **TowerScout v0.1.2 validated pilot release**

Do not rebuild, rename, replace, or silently modify these assets.

## Repository Roles

### `J-Schulein/TowerScout`

- Hosts the immutable Pilot Package.
- Hosts new development, unsigned `v0.1.3-preview.N` GitHub prereleases, and
  later signed `v0.1.3-rc.N` candidates.
- Retains pilot and source-provenance history after handoff.

### `cdcai/TowerScout`

- Continues to represent the currently adopted application.
- Is not the `v0.1.2` pilot download.
- Receives no new source, tags, releases, images, issues, or banner changes
  during the hold without explicit owner authorization.
- Will host the official final release after qualification and adoption.

## Feedback And Support

- The project lead maintains feedback in a fillable Word document outside the
  repository and will notify the development team of actionable findings.
- `.agent_work` does not duplicate intake or tracking.
- Primary and backup support owners are confirmed with appropriate access.
- Their contact details remain in the sent communication and access-controlled
  records, not this public repository.

## Fix-First Development During The Pilot

The cdcai owner selected the fix-first path:

1. Preserve `v0.1.2`.
2. Complete required security, TLS, Exit/Stop, Podman, qualification,
   documentation, and handoff work in the fork.
3. Publish and refine immutable unsigned previews as
   `v0.1.3-preview.N` GitHub prereleases; never mark them `Latest`.
4. Continue to accept pilot and clean-machine preview feedback; blocker
   feedback takes priority.
5. Record when the normal-user package satisfies ADR-019's exact-source,
   package-integrity, documentation, functional, and runtime-boundary gate.
6. Complete Task-100 production signing and representative managed-endpoint
   qualification in October, producing signed `v0.1.3-rc.N` candidates.
7. Have the project lead and cdcai owner qualify the signed candidate.
8. Select the final cdcai tag and display title before the official build.
9. Execute Task-089 only after explicit owner adoption approval.

The Tasks 090/098 security gate passed, and Task-087's later exact-source
packages passed Docker and approved-provider Podman Google/Azure repair plus
controlled recovery. Follow-up evidence closes the hash-pinned Podman provider
installer gap and enforces the selected Windows rootless-Podman boundary while
failing closed before mutation in rootful mode. These artifacts remain
validation-only and cannot be renamed or published. Under the August 19
ADR-019 decision, the next work after the governance-transition head passes is
technical/security review and a newly integrated normal-user unsigned preview
package. Task-100 owns production signing and representative managed-endpoint
validation in October after that package is satisfactory. See the current
sanitized
[`Task-087 full-package validation record`](../../../tasks/active/TASK-087/FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md).

Tasks 090/098 passed on July 27 and remain completed historical records.
GitHub disclosed four additional Dependabot advisories on August 4-5, and the
blocking npm audit added `GHSA-5p4m-2wfm-xmqj` on August 7 while Task-099 was
still active. Task-099 completed that follow-up on August 11 through PRs
#68/#69, successful main CI and root graph refresh, and alert closure without
dismissal. Its August 11 closeout inventory contained the eight documented
torch residuals. GitHub opened high-severity development-transitive
`extract-zip` alert `#76` afterward; Task-101 owned that separate focused
remediation and release-gate disposition. PR #72 passed its final exact-head
matrix and squash-merged as `0cc189c`; alert `#76` then closed as fixed without
dismissal, and the exact-main checks passed separately. PR #73 recorded that
post-merge checkpoint and squash-merged as `9276084`; its exact-main CI/CD and
Task-087 workflows passed. The merge integrated `main` through `9276084` into
Draft PR #67 while preserving ADR-019 and the branch's recorded evidence.
Reconciliation commit `946deaf` then passed exact-head CI/CD run `32383065903`
and Task-087 run `32383065959`, satisfying Task-101's remaining acceptance gate.
This governance update marks Task-101 complete and explicitly resumes Task-087
from its preserved checkpoint. Task-087's evidence remains valid and reviewer
input may continue, but no further implementation proceeds until CI/CD and
Task-087 workflows pass at the new governance head. PR #67 merge to `main` and
preview/candidate publication remain behind Task-087's other applicable gates.

## Release Naming Boundary

- `v0.1.3-preview.N` is the unsigned fork prerelease convention for iterative
  normal-user testing; previews are never `Latest` or managed-endpoint claims.
- `v0.1.3-rc.N` is reserved for production-shaped packages built and signed
  within Task-100; publish those exact bytes only after qualification passes.
- No `v0.1.3` final release is implied or authorized by that convention.
- The final cdcai tag and display title are decided before the official build.
- The official image, package, manifests, checksums, filenames, and docs must
  be rebuilt consistently; candidate ZIPs are not simply renamed.

## Adoption Gate

Task-089 remains blocked until:

1. Pilot feedback and candidate findings are reviewed.
2. Required four-profile qualification passes.
3. Task-101 remains complete after its green PR #67 reconciliation gate.
4. Task-087's governance-transition head and remaining applicable gates pass.
5. Task-100 production signing and representative managed-endpoint
   qualification pass.
6. The project lead and cdcai owner qualify the final signed candidate.
7. The owner explicitly approves adoption.
8. Repository, Actions, package, release, and backlog ownership are ready.
9. The official identity and rebuild/verification plan are approved.

If the final candidate is not ready, preserve the fork, evidence, feedback,
backlog, and migration-ready handoff without changing cdcai.

## Task Ownership

- Task-087: resumed guided Google/Azure application-provider TLS repair on
  Docker and Podman; governance-head validation is pending before further
  implementation.
- Task-088: completed Pilot Package distribution and custody.
- Task-089: owner-gated cdcai adoption and ownership transfer.
- Task-090: completed bounded runtime/custom-image/dependency security
  investigation, including the 62-alert Trivy baseline.
- Tasks 091-095: qualification, docs, recovery, evidence-gated support, and
  governance/handoff.
- Task-096: user-confirmed Exit/Stop.
- Task-097: Podman CPU/GPU final-path qualification.
- Task-098: completed July 27 dependency remediation, compatibility
  validation, and release-risk disposition through PR #51 / `e499b50`.
- Task-099: completed August 11 for alerts `#72-#75` plus npm finding
  `GHSA-5p4m-2wfm-xmqj`; the critical/high gate and default-branch inventory
  reconciliation passed without reopening Task-098.
- Task-100: October production signing, signed-package verification, and
  representative managed-endpoint qualification after the satisfactory
  unsigned-package decision.
- Task-101: completed August 20 after reconciliation commit `946deaf` passed
  exact-head CI/CD run `32383065903` and Task-087 run `32383065959`; the focused
  remediation removed the development-transitive `extract-zip` path and alert
  `#76` closed as fixed without dismissal.

## Superseded Instructions

This plan supersedes earlier immediate-migration instructions, the earlier
"wait before selecting implementation" state, and any plan to use `v0.1.2` as
the automatic cdcai baseline. Older documents remain archived as historical
evidence.
