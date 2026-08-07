# Task-087 Windows Helper Pivot Review

**Status**: SUPERSEDED - ADR-018 accepted the bounded launcher feasibility
direction on August 5, 2026; retained as decision-history input
**Date**: August 4, 2026
**Audience**: TowerScout reviewers, project lead, release owner, security
reviewers, and the `towerscout-windows-helpers` owner
**Decision Scope**: Decide whether Task-087 should move from a browser-to-host
loopback control plane to an explicit desktop launcher/maintenance workflow
**Release Effect**: None. The existing Task-087 browser mutation path remains
disabled and the command-based Task-086 repair remains the supported fallback.

## Executive Summary

Task-087 was intended to turn TowerScout's validated but manual managed-network
TLS repair into a guided experience: detect a repairable Google Maps or Azure
Maps certificate-trust failure, repair container trust from the Windows host,
restart TowerScout with the same engine/GPU/port profile, and return the user to
provider setup.

The current implementation proves much of the narrow security and operation
contract, but it uses a package-local PowerShell host helper with a loopback
listener so browser code can request the host-side operation. A hidden detached
PowerShell child-process experiment was blocked by local endpoint
protection/AMSI and was removed. A later visible PowerShell helper passed one
local lifecycle check without an alert, but that did not establish acceptability
on the target managed Windows environment. It also leaves TowerScout with a
visible helper window and an authenticated local listener whose existence may
be difficult to explain to users and security reviewers.

The [`wcedens/towerscout-windows-helpers`](https://github.com/wcedens/towerscout-windows-helpers)
repository demonstrates a less network-intrusive trust boundary: a user starts
a Windows desktop launcher, chooses a maintenance action, confirms repair, and
the launcher invokes TowerScout's package-local scripts directly. It does not
open an additional inbound listener or pass host-operation authority through
the browser. That approach can deliver a similar repair outcome, but it cannot
provide a literal one-click browser button without reintroducing some form of
browser/native bridge.

The recommended direction is a bounded pivot proof: adapt the desktop
maintenance UX into the TowerScout repository, retain TowerScout's stronger
current certificate-selection and repair scripts, and carry forward Task-087's
operation locking, state, sanitization, cancellation, and runtime-profile
controls. Do not copy the external TLS prototype wholesale, do not publish an
unsigned UPX-packed executable, and do not enable or remove the existing
browser helper until the desktop proof receives security, UX, Docker/Podman,
and managed-network review.

## Decision Requested From Reviewers

Reviewers are asked to advise on these questions:

1. Is a user-launched TowerScout desktop maintenance action an acceptable
   replacement for a repair button inside the browser Setup Wizard?
2. Should the first proof be limited to **Check/Repair Map Connections**, or
   should it also include the external repository's broader startup, setup,
   download, cleanup, and diagnostics capabilities?
3. Should the adapted launcher live and release from the TowerScout repository
   as a package component, or remain a separately versioned companion? This
   review recommends a TowerScout-owned package component to avoid version and
   support drift.
4. What Authenticode, binary reputation, Defender/ASR, application-control, and
   software-distribution requirements apply on the target managed endpoints?
5. Is browser-native one-click repair a mandatory requirement? If it is, the
   external repository alone does not satisfy Task-087 and a reviewed native or
   loopback IPC design is still required.
6. After a desktop proof passes, should the dormant browser helper be removed
   from release packages to reduce attack surface, or retained disabled for a
   defined period while the replacement is qualified?

## Current Task-087 Situation

The canonical Task-087 record is
[`TASK-087-host-side-tls-repair-control-plane.md`](../../../tasks/active/TASK-087-host-side-tls-repair-control-plane.md).
Its current state is **planned/reselected**: the Gate 3 non-mutating proof is
merged, resumption remains behind the Tasks 090/098 security gate, and the work
targets a future `v0.1.3-rc.N` candidate rather than the immutable `v0.1.2`
pilot.

The merged proof at TowerScout commit `4b93caf` is deliberately dormant:

- `.env.example` defaults `TOWERSCOUT_HOST_HELPER_REVIEW_ENABLED` to `0`.
- `webapp/ts_host_helper.py` keeps the public provider-repair capability false.
- `webapp/js/src/setup-wizard.js` keeps browser-triggered mutation false.
- The manual `repair-provider-tls.cmd`, stop, and start sequence remains the
  supported and audited fallback.

The reviewed [`scripts/host-helper.ps1`](../../../../scripts/host-helper.ps1) is a
thin host-side entry point, not a general-purpose command server. It supports
self-test and session invalidation, creates a per-run token and captured runtime
profile, and delegates to the allowlisted helper library. In the merged review
configuration, it starts on loopback with controlled repair execution disabled.
The fixed worker script is the only intended path to the repair/stop/start
sequence when mutation is eventually authorized.

Task-087 has already established useful controls that should survive any
pivot:

- fixed Google/Azure and Docker/Podman enums
- fixed TowerScout-owned script paths and argument arrays
- per-package operation locking and duplicate-operation handling
- scoped, expiring authorization for browser discovery/planning/polling
- runtime-profile preservation across repair, stop, and restart
- session lease, listener supervision, timeout, cancellation, and cleanup
- sanitized public operation states instead of raw subprocess output
- explicit user confirmation and a documented command fallback

The [`live-wrapper-validation-2026-07-06.md`](../../../tasks/active/TASK-087/live-wrapper-validation-2026-07-06.md)
record shows that the allowlisted Docker CPU repair/stop/start sequence
eventually returned TowerScout to readiness after a lifecycle defect was fixed.
That validates the underlying orchestration goal; it does not authorize the
browser transport or a user-facing release.

## What Task-087 Was Intended To Fix

Task-086 demonstrated that TowerScout can recover from a managed-network TLS
inspection failure by selecting an appropriate Windows certificate authority,
making it available to the container trust bundle, and preserving the required
Python/OpenSSL trust configuration. The remaining user-experience problem is
that a user or support technician must leave the browser, open a terminal, run
the package-local repair command, stop TowerScout, restart it with the correct
runtime profile, wait for readiness, and retry provider setup.

Task-087 was intended to make that sequence guided and support-safe for both
Google Maps and Azure Maps, on Docker and Podman, without:

- giving the browser arbitrary host-command execution
- mounting a Docker or Podman control socket into the application container
- silently changing certificate trust or installing a Podman Compose provider
- exposing provider keys, helper credentials, certificate details, raw process
  output, local paths, or environment contents
- losing the user's selected engine, GPU mode, port, or package identity during
  restart

The architectural difficulty is real: the containerized web application cannot
inspect the Windows certificate stores or safely control the host runtime, and
ordinary browser JavaScript cannot invoke package-local repair scripts. The
choice is therefore not whether host-side code is needed, but where its trust
boundary and user interaction should live.

## Defender/AMSI Finding And Why A Pivot Is Being Considered

The Task-087 evidence supports a narrow conclusion:

- A hidden detached PowerShell child-process implementation embedded in the
  helper path was blocked by the local endpoint-protection/AMSI path on July 2.
  The triggering code was removed before commit.
- A transparent, visible PowerShell helper later passed one local lifecycle
  check without an observed alert, quarantine, or suspicious-process notice.
- Target managed-endpoint policy and packaged-binary behavior were not proven.
- The evidence does **not** establish that the loopback listener itself caused
  the alert. The known trigger involved the hidden detached PowerShell process
  pattern. Listener behavior, script content, process ancestry, execution-policy
  flags, packaging, signature reputation, or a combination may still affect
  endpoint controls.

A pivot is worth review because it can remove multiple sources of concern at
once: no extra inbound listener, no browser-held host-operation authority, no
hidden long-lived PowerShell helper, and no need to keep a helper window open.
It also makes the consent boundary visible: a user deliberately chooses a
maintenance action in a Windows application.

This is risk reduction, not a promise that Defender will accept the result.
Unsigned or compressed PyInstaller binaries, PowerShell child processes,
execution-policy bypasses, downloaded executables, certificate handling, and
container-runtime control can each attract EDR scrutiny. The replacement must
be signed, packaged, and validated as a managed-endpoint product rather than
treated as a way around security controls.

## What `towerscout-windows-helpers` Does

This review examined public `main` at commit
[`f957efb`](https://github.com/wcedens/towerscout-windows-helpers/tree/f957efbab413b29ac368265cad78452c6fc1114c),
which was reverified as the repository's current `main` HEAD on August 4, 2026.

The repository is a small Windows companion-tool project with two Python/Tkinter
desktop applications, PowerShell support tools, PyInstaller build definitions,
tests, and a GitHub Actions release workflow.

### Desktop Launcher

The
[`TowerScout launcher`](https://github.com/wcedens/towerscout-windows-helpers/blob/f957efbab413b29ac368265cad78452c6fc1114c/apps/launcher/towerscout_launcher.py)
provides guided Docker/Podman selection, TowerScout startup and readiness
polling, browser opening, diagnostics, and maintenance actions. Its map repair
flow:

1. Ensures the selected container runtime is available.
2. Starts TowerScout without opening a duplicate browser when needed.
3. Uses `docker exec` or `podman exec` to run a fixed Python `requests` probe
   from inside the application container against the known Google and Azure map
   hosts. No provider API key is required for the TLS handshake check.
4. Distinguishes certificate failures from non-TLS HTTP results in the launcher
   repair flow.
5. Requests explicit user confirmation.
6. Calls TowerScout's package-local `repair-provider-tls.cmd` with fixed
   provider, engine, GPU, and apply arguments.
7. Stops and restarts TowerScout, waits for readiness, and rechecks both map
   endpoints.

The launcher does not bind another listening port and does not expose a
browser-to-host API. Its subprocess calls use fixed argument lists rather than
browser-supplied shell strings.

### Setup Helper

The
[`setup helper`](https://github.com/wcedens/towerscout-windows-helpers/blob/f957efbab413b29ac368265cad78452c6fc1114c/apps/setup-helper/towerscout_setup_helper.py)
adds prerequisite and package checks, CPU/GPU selection, GitHub release asset
download, staged extraction, installation/update, cleanup, progress reporting,
and the same general map-repair workflow. Particularly useful implementation
ideas include:

- release-asset digest and SHA sidecar verification
- archive size/file-count limits
- path-traversal, duplicate-entry, symlink, and junction rejection
- staging before install and exact verification before reuse
- nonsecret shared settings under `%LOCALAPPDATA%`
- conservative cleanup UX with retained volumes as the default

The setup helper is broader and less runtime-neutral than the launcher. Several
paths are Docker-specific even when Podman is selected, and its repair
eligibility is not as narrowly classified as Task-087 requires. These portions
need redesign before reuse.

### Build And Release Shape

The
[`build workflow`](https://github.com/wcedens/towerscout-windows-helpers/blob/f957efbab413b29ac368265cad78452c6fc1114c/.github/workflows/build-release.yml)
uses PyInstaller to produce Windows executables. At the inspected revision, the
PyInstaller specifications enable UPX and do not configure code signing. The
repository also has no visible license/notice file at that revision.

The source-level validation reviewed for this assessment passed 33 unit tests
and PowerShell parser checks. No claim is made for live Docker/Podman behavior,
packaged-executable reputation, Authenticode, Defender/ASR acceptance, or the
target managed network because those were not validated in this review.

## Architecture Comparison

| Concern | Dormant Task-087 control plane | External desktop-helper model |
| --- | --- | --- |
| User entry point | Browser Setup Wizard | Windows launcher/maintenance UI |
| Host boundary | Authenticated loopback HTTP helper | Direct local subprocess calls |
| Additional listener | Yes, loopback-only and dynamically scoped | No additional inbound listener |
| Browser authority | Narrow, expiring operation authorizations | None |
| User confirmation | Browser confirmation plus helper contract | Native desktop confirmation |
| Restart continuity | Helper/session/worker supervision | Launcher process remains responsible |
| Recovery controls | Package mutex, operation state, replay handling, cancellation | Primarily in-process command-running state |
| Provider classification | Structured repairable categories required | Launcher distinguishes TLS failures; setup helper is broader |
| Docker/Podman intent | Both, explicitly gated | Both exposed, but some setup/cleanup paths are Docker-specific |
| Certificate repair implementation | TowerScout's hardened current scripts | Calls package script, plus a weaker prototype script in the helper repo |
| Endpoint-policy surface | PowerShell listener, worker, browser bridge | Packaged Python GUI plus PowerShell/package-script children |
| Exact browser one-click | Possible after all gates pass | Not provided |

## Recommended Incorporation Strategy

### 1. Run A Narrow Desktop-Maintenance Proof First

Adapt only the **Check/Repair Map Connections** workflow and the minimum
launcher/readiness behavior needed to support it. Keep the proof in the
TowerScout repository and package so one release manifest, checksum set,
version, and support owner cover both the web application and the maintenance
tool. Avoid a git submodule or runtime dependency on the external repository.

The browser Setup Wizard can continue to classify a repairable TLS failure and
tell the user to return to **TowerScout Launcher > Maintenance > Check/Repair
Map Connections**. If a launcher is already kept open while TowerScout runs,
this becomes a short guided handoff without an IPC listener. The manual command
remains available for support and recovery.

### 2. Reuse TowerScout's Repair Logic, Not The External TLS Prototype

Continue using
[`scripts/repair-provider-tls.ps1`](../../../../scripts/repair-provider-tls.ps1)
and its package-local command wrapper. TowerScout's implementation is more
defensive than the helper repository's prototype: it fixes the allowed Google
and Azure hosts, checks CA/basic-constraint and signing properties, prefers
Windows-store matches, rejects ambiguous equal-score candidates, and already
supports the project's engine abstraction.

The desktop UI should use a two-phase contract:

1. Inspect/dry-run and classify the failure.
2. Present a private, user-readable summary of the proposed trust action.
3. Require confirmation for the exact selected certificate identity.
4. Apply through the fixed TowerScout wrapper.
5. Restart with the captured engine/GPU/port/package profile.
6. Wait for readiness and verify Google and Azure independently.

Certificate subject, issuer, thumbprint, provider responses, and raw command
output may be shown locally only when necessary for informed consent; they must
not be copied into support-safe status, browser payloads, default logs, release
evidence, or clipboard diagnostics.

### 3. Port Task-087's Mature Controls Into The Desktop Coordinator

The external launcher is simpler, but Task-087 has stronger lifecycle controls.
The adapted coordinator should retain or implement:

- a package-root-derived cross-process mutex, not only an in-process Boolean
- one operation journal with sanitized phases and terminal state
- idempotent duplicate-click and multiple-launcher-instance handling
- process-tree supervision, bounded timeouts, cancellation, and close behavior
- recovery after launcher crash or Windows restart
- package identity and runtime-profile freshness checks
- fixed command paths resolved under the selected package root
- enum-only engine, GPU, provider, and port validation
- Docker/Podman parity through TowerScout's runtime abstraction
- no `shell=True`, caller-provided command strings, or arbitrary extra arguments

This preserves the strongest work already completed under Task-087 while
removing the browser transport.

### 4. Treat Packaging Reputation As A Product Gate

For the managed-endpoint proof:

- disable UPX and compare one-directory versus one-file packaging behavior
- Authenticode-sign the launcher and relevant PowerShell entry points with a
  project-controlled certificate and timestamping policy
- avoid `ExecutionPolicy Bypass` in normal user-facing launch paths
- publish checksums, provenance, dependency inventory/SBOM, and exact source
  revision with every candidate
- use fixed, verified package assets and TowerScout's release-manifest identity
- keep helper logs under a known `%LOCALAPPDATA%` location with explicit
  redaction and retention
- test with the target Defender/ASR/application-control policy; never request
  exclusions or suppressions merely to make the proof pass

### 5. Decide The Fate Of The Browser Helper After Evidence, Not Before

Keep all current Task-087 activation gates off during the proof. If the desktop
workflow satisfies UX and managed-endpoint requirements, prepare a separate
reviewed change to remove unused listener/bridge artifacts from release
packages while preserving relevant tests, operation-state utilities, and design
evidence. If browser-native repair remains mandatory, use the proof to refine a
small signed native supervisor or another approved IPC design; do not revive the
rejected hidden PowerShell pattern.

## Components Worth Leveraging Later

After the narrow repair proof, these external ideas may improve TowerScout's
overall Windows user experience:

- guided runtime selection and readiness polling
- browser launch only after health/readiness succeeds
- shared nonsecret settings in `%LOCALAPPDATA%`
- safe release download, checksum verification, staged extraction, and update
- explicit CPU/GPU package selection
- support-safe diagnostics with a reviewed clipboard/export boundary
- conservative cleanup with volumes preserved by default and destructive
  choices requiring stronger confirmation
- pinned build/test workflow patterns and launcher documentation/screenshots

Each should be adopted as TowerScout-owned code with project conventions,
tests, and release controls. The safest sequencing is repair UX first, then
startup/readiness, then setup/update; cleanup and diagnostics should remain
separate security/privacy reviews.

## Issues And Risks To Resolve

### Permission, License, And Provenance

The external repository owner is supportive of TowerScout leveraging the work.
That materially improves feasibility, but the inspected revision has no visible
license or notice file. Before copying or distributing source or binaries, the
owner and TowerScout should record written permission through an explicit
license or contribution agreement, identify any attribution/notice
requirements, and pin the approved source revision. This is project-governance
guidance, not legal advice.

### Endpoint Protection May Still Object

Removing a listener and hidden detached PowerShell reduces suspicious surface,
but does not eliminate it. Unsigned PyInstaller executables, UPX compression,
one-file self-extraction, downloaded executables, PowerShell children,
certificate-store access, and Docker/Podman control may still trigger Defender,
ASR, WDAC/AppLocker, or enterprise EDR. Signing and target-policy validation are
required acceptance evidence.

### Browser UX Becomes A Guided Handoff

Without IPC, a browser cannot activate the desktop repair directly or know its
live state. Users must return to the launcher and later retry provider setup.
Copy-to-clipboard commands, custom URL protocols, watched files, or a localhost
callback may look convenient but reintroduce spoofing, registration, listener,
or secret-handling concerns. They should not be added unless the reviewer
rejects the simpler handoff and approves a separate threat model.

### Runtime And Package Drift

The launcher must repair the same TowerScout package instance and the same
engine/GPU/port profile the user is running. Multiple extracted packages,
multiple launcher instances, stale settings, an unavailable local image, or a
different Docker/Podman Compose project can otherwise repair or restart the
wrong target. Package identity, profile freshness, and cross-process locking are
release requirements.

### Docker/Podman Parity Is Incomplete Externally

The external launcher exposes both engines, but the setup helper contains
Docker-specific assumptions in setup, cleanup, and repair paths. TowerScout
must use its existing engine abstraction and separately validate Docker CPU,
Docker GPU, Podman CPU, and Podman GPU. Podman Compose-provider installation and
Podman-machine image-pull/source-build trust remain separate operations and must
not be silently coupled to provider TLS repair.

### Failure Classification Must Stay Narrow

Only certificate-trust failures should offer repair. Invalid keys, quota,
provider-disabled, HTTP, DNS, proxy, timeout, and generic network failures must
not change trust. The external launcher's check is closer to this rule than its
setup helper, but TowerScout's structured provider-validation categories should
remain authoritative.

### Certificate Selection Is Security-Sensitive

The external TLS prototype allows a caller-supplied hostname and uses
subject-name heuristics to find a likely inspection CA. Those behaviors should
not be imported. TowerScout must keep its provider allowlist, CA/key-usage
checks, trusted-store preference, ambiguity rejection, exact-confirmation
contract, and post-repair verification.

### Logging And Diagnostics Can Leak Sensitive Detail

Raw repair output can contain local paths or certificate identity details.
Provider errors may include request information, and clipboard diagnostics are
easy to overshare. Default logs and status must use sanitized categories and
bounded retention. Detailed local evidence should be opt-in, visibly labeled,
and excluded from release/support artifacts unless separately scrubbed.

### Process Lifetime And Recovery Need Hardening

The external tool primarily prevents concurrent work within one process.
Multiple application instances, launcher close during repair, orphaned child
processes, and interrupted stop/start can leave state ambiguous. Task-087's
mutex, operation record, session/liveness checks, process-tree cancellation,
and fallback recovery should be adapted before user-facing release.

### Broader Setup Scope Could Delay The Required Fix

The external setup helper contains attractive installation/update features,
but adopting all of them would expand Task-087 into package management,
download security, cleanup, diagnostics, and support ownership. The repair UX
should be proven first; broader reuse should receive separately scoped tasks and
acceptance gates.

## Proposed Proof And Decision Gates

### Gate A - Permission And Design

- Record the external owner's reuse permission/license and attribution terms.
- Approve desktop handoff UX versus browser-native repair.
- Approve same-repository packaging and define the signed binary owner.
- Threat-model the desktop process, fixed subprocess boundary, local state, and
  certificate confirmation flow.

### Gate B - Non-Mutating Desktop Proof

- Detect TowerScout package identity and captured runtime profile.
- Classify Google and Azure TLS results without provider keys.
- Demonstrate Docker and Podman command planning with fixed arguments.
- Prove no listener, arbitrary shell surface, secret-bearing state, or raw
  support output.
- Prove cross-process lock, duplicate action, cancellation, and crash recovery.

### Gate C - Controlled Repair Proof

- Use TowerScout's existing repair wrapper only.
- Validate explicit confirmation, exact certificate selection, repair, stop,
  restart, readiness, and provider retry.
- Validate recovery when repair, stop, start, or readiness fails.
- Preserve the command fallback and avoid automatic trust changes.

### Gate D - Package And Managed-Endpoint Qualification

- Build without UPX, sign, timestamp, and verify the candidate.
- Validate release manifest, checksums, provenance/SBOM, and package contents.
- Validate Defender/ASR/application-control behavior on the target managed host.
- Validate Docker/Podman and CPU/GPU profiles required by the release roadmap.
- Obtain reviewer and release-owner approval before changing any current helper
  activation gate or removing fallback behavior.

## Recommended Reviewer Disposition

Approve a **time-boxed, non-mutating desktop-maintenance proof** as the next
Task-087 architecture investigation after its existing Tasks 090/098 gate.
Keep browser mutation disabled, keep the manual repair supported, and limit the
proof to map connection classification, fixed operation planning, runtime
profile continuity, and endpoint-policy-friendly packaging.

Do not yet approve a wholesale copy of the external setup helper, a release
binary, trust mutation, removal of the existing Task-087 scaffolding, or any
browser/native IPC. Those decisions should follow the proof evidence and the
reviewer answers above.

## Evidence Basis And Limitations

This note is based on:

- the canonical Task-087 plan and its July 2 endpoint-protection/AMSI record
- the sanitized July 6 live repair/stop/start validation
- the dormant merged control-plane state at TowerScout `4b93caf`
- static review of `towerscout-windows-helpers` at `f957efb`
- 33 passing external-repository unit tests and PowerShell parser checks

No runtime, release, security-policy, or managed-network behavior was changed
for this review. No provider key, helper credential, certificate identity, raw
subprocess output, private network detail, or user-specific path is recorded in
this artifact.
