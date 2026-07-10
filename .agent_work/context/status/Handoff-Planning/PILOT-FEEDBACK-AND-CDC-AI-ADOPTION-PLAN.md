# TowerScout Pilot Feedback And cdcai Adoption Plan

**Decision Date**: 2026-07-10
**Status**: CURRENT - canonical release-transition and ownership plan
**Decision Owner**: TowerScout project lead with the `cdcai/TowerScout` owner
**Pilot Baseline**: validated fork-side `v0.1.2` release
**Expected Pilot Distribution**: Monday, 2026-07-13
**Current Project End**: 2026-07-15, with a possible three-month extension

## Decision

Keep `cdcai/TowerScout` unchanged while the `v0.1.2` pilot is distributed and
user feedback is collected. The existing cdcai repository remains the official
repository for the currently adopted application. It must not be overwritten,
repointed, or presented as the source of the pilot package before the cdcai
owner reviews the pilot results and approves an adoption baseline.

Use the exact validated fork-side release as the pilot distribution:

- pilot download: `https://github.com/J-Schulein/TowerScout/releases/tag/v0.1.2`
- source ref: `718a56485a59182f060a537e8f11d4ce71a1f0d4`
- release assets: the existing six checksum-verified `v0.1.2` assets
- pilot description: **TowerScout v0.1.2 validated pilot release**

Do not rebuild, rename, replace, or silently modify the `v0.1.2` release assets
for the pilot. Any accepted fix must use a new version identity.

## Repository Roles During The Pilot

### `cdcai/TowerScout`

- Remains unchanged until the owner approves adoption after reviewing feedback.
- Continues to represent the application version currently adopted by cdcai.
- Must not be used as the pilot download location.
- Receives no source, tags, releases, images, backlog issues, or repository
  banner changes during the feedback hold unless the owner explicitly changes
  this decision.

### `J-Schulein/TowerScout`

- Hosts the exact validated `v0.1.2` pilot package and validation record.
- Remains the pilot development and fix-validation surface during the hold.
- Must be retained as a release/provenance archive even after later adoption.
- May produce a new pilot patch only when feedback justifies a change and the
  change receives proportionate package validation.

### Feedback And Support Channel

- Must be controlled by the cdcai owner or an organization-controlled team,
  not solely by the current developer.
- Should be a shared email address, form, Teams channel, SharePoint list, or
  another explicitly approved durable destination.
- Must be named in the pilot communication before distribution.
- Must identify a backup person who can receive reports if the current
  developer is unavailable.
- Should capture user, engine, package flavor, attempted action, observed
  result, severity/blocking impact, and sanitized support evidence.

Do not enable cdcai Issues merely to satisfy the earlier migration plan while
the owner wants the official repository unchanged. Issues may be enabled later
as part of the adoption decision.

## Before Pilot Distribution

1. Freeze the existing `v0.1.2` release and preserve its six-asset checksum
   record.
2. Update the pilot email/setup guide to distinguish:
   - the fork-side validated pilot download
   - the unchanged official cdcai repository
   - the organization-controlled feedback/support destination
3. Confirm the backup support owner and hand over the release assets,
   checksums, validation summary, known findings, and troubleshooting material.
4. Finish `TASK-088` documentation/evidence custody and leave a clean,
   reviewable repository record.
5. Prepare the `TASK-089` migration inputs, but do not push or publish anything
   to cdcai.

## During The Feedback Hold

- Collect and triage pilot feedback against the exact `v0.1.2` baseline.
- Classify findings as setup/support questions, non-blocking improvements,
  release blockers, or security/data-integrity issues.
- Keep the cdcai repository unchanged.
- Do not enable the dark Task-087 browser-to-host repair flow as part of pilot
  support.
- If a fix is necessary, implement and validate it in the fork under a new
  version such as `v0.1.3`; never replace the existing `v0.1.2` bytes.

## Adoption Decision After Feedback

The cdcai owner selects one of these outcomes.

### Outcome A - Adopt The Validated Baseline

If feedback finds no adoption-blocking issue, approve `v0.1.2` or a reviewed
successor as the cdcai migration baseline, then execute `TASK-089`.

### Outcome B - Fix Before Adoption

If feedback identifies important defects, keep cdcai unchanged, fix and
validate a new fork-side pilot version, and adopt only the corrected baseline.

### Outcome C - Do Not Adopt Yet

If the pilot is not ready, preserve the fork, evidence, feedback, and prepared
handoff material. The owner can resume adoption work later without changing the
current cdcai repository.

## Project Extension Branch

If the project receives the three-month extension:

1. Prioritize pilot feedback, installation reliability, user guidance, and
   supportability before optional feature work.
2. Continue pilot fixes in the fork until the owner approves an adoption
   baseline.
3. Use new release identities for every changed package set.
4. Move active development and future official releases to cdcai only after
   adoption is approved and the migrated package passes its required checks.

## No-Extension Branch

If the project ends on 2026-07-15:

1. Freeze the fork-side pilot and documentation state.
2. Give the cdcai owner the feedback record, release assets/checksums,
   validation summary, known findings, backlog, and migration runbook.
3. Prepare a reviewable comparison or draft handoff PR if the owner wants one,
   but do not merge or modify cdcai without approval.
4. Keep the fork available as the validated pilot and provenance archive.
5. Leave the final adoption/merge timing with the cdcai owner.

## Task Ownership

- `TASK-088` owns pilot distribution readiness, guide/support wording,
  evidence custody, and fork-side closeout.
- `TASK-089` owns migration preparation now and migration execution only after
  pilot feedback plus explicit cdcai-owner adoption approval.
- `TASK-087` remains dark and deferred unless separately selected after the
  pilot/release transition.

## Superseded Instructions

This plan supersedes any earlier instruction to migrate immediately after
release publication or as soon as repository/package permissions become
available. Earlier strategy, decision, checklist, and review documents remain
valuable historical evidence, but their migration dates and `v0.1.0`/
`v0.1.1` execution commands are not current instructions.
