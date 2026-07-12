# TowerScout v0.1.2 Pilot Operations Packet

**Prepared**: 2026-07-12

**Pilot date**: 2026-07-13

**Baseline**: `v0.1.2` at `718a56485a59182f060a537e8f11d4ce71a1f0d4`

**Release**: `https://github.com/J-Schulein/TowerScout/releases/tag/v0.1.2`
**Status**: READY except for the owner-controlled feedback destination and
backup support owner, which must be filled in before distribution

This packet turns the canonical pilot/adoption plan into a short operating
checklist. It does not authorize changes to `cdcai/TowerScout`.

## Information To Fill In Before Sending

- **Feedback/support destination**: `[PENDING OWNER INPUT]`
- **Backup support owner**: `[PENDING OWNER INPUT]`
- **Primary pilot coordinator**: `[PENDING]`
- **Expected response window**: `[PENDING]`
- **Location of the durable feedback register**: `[PENDING OWNER INPUT]`

Do not send the pilot until the first two fields are confirmed. The destination
must be controlled by the cdcai owner or organization and remain accessible if
the current developer is unavailable.

## Send-Ready Pilot Message

Subject: TowerScout v0.1.2 pilot package and setup guide

> We are inviting you to test the validated TowerScout v0.1.2 pilot release.
>
> Download the pilot only from:
> https://github.com/J-Schulein/TowerScout/releases/tag/v0.1.2
>
> This pilot comes from the development repository. The existing
> `cdcai/TowerScout` repository remains unchanged and continues to represent
> the version currently adopted by cdcai. Please do not use that repository as
> the source of this pilot package.
>
> For normal Windows testing, download the CPU Application Package and the
> shared Model & Data Package, together with their two `.sha256` checksum
> files. Follow `docs/quick-start.md` from the Application Package. Use the
> CUDA package or Podman only when support specifically assigns that path.
>
> Send questions, setup problems, and test feedback to:
> **[FEEDBACK/SUPPORT DESTINATION]**
>
> When reporting a problem, include your Windows version, container engine,
> package filename, what you were trying to do, what happened, and whether the
> problem stopped your testing. Do not send API keys, unredacted logs, map
> coordinates, screenshots containing sensitive information, or raw network
> traces.
>
> Backup support contact: **[BACKUP SUPPORT OWNER]**

Replace both bracketed fields before sending. If a separate attachment or web
page is used, check that it contains the same release URL and support details.

## Pre-Send Gate

- [x] Release URL identifies the fork-side `v0.1.2` release.
- [x] Source ref is frozen at
  `718a56485a59182f060a537e8f11d4ce71a1f0d4`.
- [x] The six validated assets remain the pilot set:
  - `towerscout-v0.1.2-cpu.zip`
  - `towerscout-v0.1.2-cpu.zip.sha256`
  - `towerscout-v0.1.2-cuda121.zip`
  - `towerscout-v0.1.2-cuda121.zip.sha256`
  - `towerscout-v0.1.2-assets-towerscout-v1-assets-2026-05-05.zip`
  - `towerscout-v0.1.2-assets-towerscout-v1-assets-2026-05-05.zip.sha256`
- [x] Pilot wording distinguishes the development repository from the
  unchanged official cdcai repository.
- [x] Normal users are directed to Docker Desktop plus the CPU package.
- [x] GPU and Podman paths are described as support-assigned.
- [x] The message warns users not to share secrets or sensitive evidence.
- [ ] Feedback/support destination is inserted and tested by the project team.
- [ ] Backup support owner confirms access to that destination.
- [ ] Backup support owner confirms access to the release, quick start,
  package guide, validation summary, known findings, and migration preparation.
- [ ] Final outbound email, attachment, or hosted guide is checked against this
  packet immediately before distribution.

## Feedback Intake Template

Use one record per report. Assign an ID such as `PILOT-001`; do not use a
person's name as the identifier.

| Field | Value |
| --- | --- |
| Feedback ID | `PILOT-___` |
| Date received | |
| Reporter/contact location | Keep in the approved private channel |
| TowerScout version | `v0.1.2` unless a later pilot is assigned |
| Application package | CPU or CUDA filename |
| Container engine/version | Docker or support-assigned Podman |
| Windows version | |
| Map provider | Google or Azure; never record the key |
| Attempted action | |
| Observed result | |
| Expected result | |
| Reproducible? | Yes / No / Unknown |
| Testing blocked? | Yes / No |
| Sanitized evidence location | Optional; access-controlled |
| Classification | Support question / Improvement / Release blocker / Security or data integrity |
| Owner | |
| Next action | |
| Status | New / Triaged / In progress / Waiting / Resolved / Deferred |
| Resolution/version | |

## Triage Rules

1. **Security or data-integrity issue**: stop the affected workflow, restrict
   evidence access, notify the project lead and cdcai owner, and do not publish
   sensitive details in a public issue.
2. **Release blocker**: testing cannot proceed, installation consistently
   fails on the supported path, or a core workflow is materially incorrect.
   Keep cdcai unchanged and decide whether a new fork-side version is needed.
3. **Support question**: help the user through the documented path and update
   guidance only if the question exposes a repeatable documentation gap.
4. **Non-blocking improvement**: record it for prioritization after blockers.
   An extension does not automatically make every suggestion immediate work.

Any changed package must receive a new version identity. Never replace the
published `v0.1.2` bytes.

## Daily Pilot Register

Keep the detailed records in the approved owner-controlled destination. This
summary may be maintained in the handoff material without personal data or
sensitive evidence.

| ID | Date | Classification | Blocked? | Owner | Status | Target version/action |
| --- | --- | --- | --- | --- | --- | --- |
| | | | | | | |

At the end of each pilot day, record total reports, open blockers, security or
data-integrity escalations, documentation-only findings, and the next review
time.

## Owner-Accessible Custody Checklist

The following are already durable in the repository or public release:

- [x] Stable release and six assets: the `v0.1.2` GitHub Release.
- [x] Source identity: tag `v0.1.2` and commit shown above.
- [x] User setup: `docs/quick-start.md` and packaged HTML equivalent.
- [x] First-line support: `docs/package-guide.md`.
- [x] Handoff and accepted risks: `HANDOFF.md`.
- [x] Validation summary and reproduction guide:
  `v0.1.2-Validation-Evidence/` in this folder.
- [x] Pilot/adoption decision:
  `PILOT-FEEDBACK-AND-CDC-AI-ADOPTION-PLAN.md`.
- [x] Deferred adoption preparation:
  `.agent_work/tasks/active/TASK-089-cdcai-migration-execution.md`.

The following require human confirmation:

- [ ] cdcai owner can access the development repository and `v0.1.2` release.
- [ ] Backup support owner can access this packet and the approved feedback
  destination.
- [ ] Durable feedback register location is recorded above.
- [ ] Any private validation or support evidence needed after July 15 is moved
  to an owner-accessible, access-controlled location.
- [ ] The owner knows that `cdcai/TowerScout` remains unchanged until a later
  feedback review and explicit adoption decision.

## Decision Points After Distribution

- If the project is extended, continue triage and supportability work in the
  fork before optional features.
- If the project ends July 15, hand this packet and the feedback register to
  the cdcai owner; do not perform an unapproved migration to meet the date.
- After feedback review, the owner chooses to adopt the validated baseline,
  require a corrected successor, or defer adoption. Only then does Task-089
  move from preparation to execution.
