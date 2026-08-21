# TowerScout Requirements

**Last Updated**: August 20, 2026
**Current Planning Horizon**: October 31, 2026 hard project end
**Operational Closeout**: October 30, 2026
**Canonical Roadmap**:
[`2026-07-23-OCTOBER-FIX-FIRST-IMPLEMENTATION-ROADMAP.md`](./context/status/Handoff-Planning/2026-07-23-OCTOBER-FIX-FIRST-IMPLEMENTATION-ROADMAP.md)

This document records the current product, release, and handoff requirements.
The broader prototype-era requirements were archived at
[`2026-07-23-pre-rebaseline-requirements.md`](./context/archive/2026-07/2026-07-23-pre-rebaseline-requirements.md).

## Product Boundary

- TowerScout is a single-user local Windows 11 AMD64 application.
- Google Maps and Azure Maps are first-class supported providers.
- Docker CPU, Docker GPU, Podman CPU, and Podman GPU are equally supported
  final-package profiles when their documented prerequisites are satisfied.
- Mac, ARM64, hosted multi-user deployment, VDI, and fully offline installation
  remain out of scope unless separately validated and approved.
- Detection, manual review, provider switching, export, restore, and setup
  behavior must remain compatible unless an authorized task changes them.

## Pilot And Candidate Requirements

### REL-001: Immutable Pilot Baseline

WHEN development continues during pilot feedback, THE PROJECT SHALL keep the
published fork-side `v0.1.2` pilot assets immutable.

Acceptance:

- The six released assets are not replaced or renamed.
- Pilot users continue to use the existing fork release.
- Any code or package change receives a new version identity.

### REL-002: Fix-First Preview And Candidate Lines

WHEN owner-requested fixes are iterated before production signing, THE PROJECT
SHALL produce immutable unsigned fork-side previews named
`v0.1.3-preview.N`. WHEN production signing begins after package satisfaction,
THE PROJECT SHALL reserve `v0.1.3-rc.N` for signed candidates.

Acceptance:

- Preview and candidate tags/assets are immutable and never overwritten.
- Preview releases are GitHub prereleases, are not marked `Latest`, and state
  that they are unsigned and not managed-endpoint-qualified.
- No unsigned package uses an `-rc.N` identity.
- No `v0.1.3` final release is published before final approval.
- Preview/candidate packages, images, manifests, checksums, source refs, and
  documentation agree on their exact identity.
- Preview or candidate naming does not reserve or require the final cdcai
  version.

### REL-003: Final cdcai Identity

WHEN the official cdcai release is prepared, THE cdcai OWNER AND PROJECT LEAD
SHALL select the official tag and display title before the official image and
package are built.

Acceptance:

- The official cdcai package is rebuilt consistently under the chosen version.
- Candidate ZIP files are not merely renamed.
- The cdcai release is published only after owner qualification and adoption
  approval.

### REL-004: Repository Boundary

WHILE the owner-approved feedback and qualification hold is active, THE PROJECT
SHALL NOT overwrite, repoint, or publish the new candidate through
`cdcai/TowerScout`.

Acceptance:

- `J-Schulein/TowerScout` remains the pilot and fix-validation surface.
- `cdcai/TowerScout` remains unchanged until explicit owner authorization.
- Technical access alone is not migration authorization.

### REL-005: Validation-Only Artifact Boundary

WHEN a Task-087 launcher artifact is built for feasibility validation, THE
PROJECT SHALL bind it to one exact committed source identity and keep it
separate from the candidate and release channels.

Acceptance:

- The artifact identity is `Task-087-validation-<short-SHA>` and records the
  full source commit in its manifest or evidence packet.
- The artifact receives no version tag, GitHub Release, `v0.1.3-rc.N`
  identity, or cdcai publication.
- The source branch is published only through a Draft PR against `main`, and
  the PR remains unmerged while validation is incomplete.
- Unsigned output is limited to static inspection or an explicitly approved
  isolated functional environment. This restriction applies to the
  validation-only artifact, not a separately assembled preview under REL-006.
  Managed-endpoint evidence uses the organization-approved signed
  production-shaped build.
- A failed validation closes the code PR unmerged and records the Stop decision
  plus Task-086 fallback through a separate documentation-only PR from current
  `main`; no code revert is required.

### REL-006: Unsigned Normal-User Preview Publication

WHEN the project publishes a package to refine through normal-user testing,
THE PROJECT SHALL create a new normal-release-path package and publish it only
as an explicitly unsigned fork-side GitHub prerelease.

Acceptance:

- The package includes the launcher and intended normal-user entry points; it
  is not a renamed or republished `Task-087-validation-*` artifact.
- The package binds an exact committed source ref to a fresh digest-pinned
  image and includes complete manifests, SHA-256 checksums, required assets,
  source/SBOM/notice material, and accurate user documentation.
- Release notes state the tested runtime/profile scope, known limitations,
  unsigned publisher status, unmanaged-test-machine boundary, and supported
  fallback.
- The actual GitHub download/extract path is tested on an approved clean
  unmanaged Windows machine without instructions to disable or bypass Windows
  security controls.
- Source merge requires applicable technical/security review and CI. Preview
  publication additionally requires package/integrity checks; its actual
  GitHub download is then clean-machine tested before that preview is accepted
  as feedback evidence or contributes to package satisfaction. None of those
  actions claims managed-endpoint or production-signing acceptance.

### REL-007: Staged-Byte And Preview Build Integrity

WHEN the project assembles a new Task-087 validation artifact or unsigned
normal-user preview, THE PROJECT SHALL derive provenance and publication
metadata from the exact copied staged bytes and a constrained, hash-locked
launcher build rather than from mutable pre-copy inputs.

Acceptance:

- Base-package and launcher inputs are copied into protected staging before
  their authoritative identity, provenance, safety, and checksum checks run.
- The staged directory, internal checksums, ZIP inventory/content, adjacent
  archive sidecar, source identity, and launcher provenance agree before a
  transactional output set becomes consumable. Final-destination bytes are
  reopened/reverified, and consumers require one atomic public-safe commit
  marker binding the relative names and hashes. A failed/crash-left set remains
  uncommitted and is reconciled by exact transaction identity rather than a
  glob. Unsafe, duplicate, normalization-conflicting, or case-colliding archive
  members are rejected.
- Launcher builds use an explicitly selected exact CPython 3.12 Windows AMD64
  patch/artifact rather than a floating minor alias, a dedicated environment,
  hash-locked reviewed wheels, disabled user-site injection, exact installed-
  distribution verification, and provenance that binds the actual interpreter/
  build inputs and complete output tree. The interpreter artifact requires an
  explicit security/integrity disposition before use.
- Historical provenance-v1 validation artifacts keep their historical meaning
  but are not reused as new validation or preview output.
- This unsigned-preview integrity gate does not replace Task-100's later
  organization-controlled rebuild, signing/timestamping, post-sign manifests,
  signature verification, or representative managed-endpoint qualification.

### SIGN-001: October Production Signing And Endpoint Qualification

WHEN the project lead records that the unsigned normal-user package satisfies
[`ADR-019`](./decisions/019-unsigned-preview-and-october-production-signing.md)'s
release-package gate, THE PROJECT SHALL select Task-100 in October and produce
a signed production-shaped candidate before final acceptance or official cdcai
publication.

Acceptance:

- The satisfactory-package record identifies the accepted source, image
  digest, package/manifests/checksums, clean-machine results, supported profile
  matrix, documentation, and resolved or accepted limitations.
- The approved signing service/operator, certificate/key custody, timestamp
  service, renewal/revocation, and backup ownership are documented without
  secrets or sensitive certificate identifiers.
- The signed-file boundary covers every organization-required project-owned
  executable, installer, or script in the normal path; incompatible
  execution-policy bypass behavior is removed, redesigned, or explicitly
  rejected before acceptance.
- Signing/timestamping occurs before final ZIP assembly. Manifests and
  checksums are regenerated from the signed bytes, and required signatures
  verify both before packaging and after clean extraction.
- The signed `v0.1.3-rc.N` package passes normal-user clean-machine and
  representative managed-endpoint validation without security exclusions,
  execution-policy bypasses, unusual endpoint-policy changes, or
  administrator-only normal setup.
- The reproducible build/sign/verify/release procedure and custody record are
  ready for the cdcai owner.

## Required Fix And Runtime Requirements

### TLS-001: Guided Provider TLS Repair

WHEN Google Maps or Azure Maps validation encounters a repairable managed-network
certificate trust failure, THE SYSTEM SHALL offer a support-safe guided repair
while retaining the command-based fallback.

Acceptance:

- Google and Azure are supported.
- Docker and Podman are supported.
- The selected host mechanism is package-local, operation-allowlisted, free of
  arbitrary command execution, and does not expose Docker or Podman control
  sockets to the application container.
- Provider keys, helper credentials, certificate details, and raw responses are
  not exposed in logs, UI, or evidence.
- Managed-network validation passes before candidate inclusion.

Provisional Task-087 feasibility interpretation, effective August 5, 2026:

WHILE the Windows launcher feasibility checkpoint is active, THE PROJECT SHALL
evaluate a visible package-local launcher/coordinator without enabling the
dormant browser-to-loopback-helper mutation path.

Acceptance:

- The prototype binds no listener, accepts no browser-issued host operation,
  imports no dormant host helper, uses no hidden worker or normal-path
  PowerShell execution-policy bypass, and does not modify the Windows trust
  store.
- Ordinary launch and stop do not import the dormant helper, and validation or
  end-user release packages omit its scripts, worker, state library, and
  support page.
- The Task-086 user-run command repair remains available and supported.
- Functional validation and normal-user preview iteration may use explicitly
  unsigned packages in their separately approved unmanaged environments.
- Any validation-only package follows REL-005 and is not a release candidate.
- Any public unsigned preview follows REL-006 and is not an RC or production
  claim.
- Signed-candidate inclusion requires Task-100's production-shaped artifact to
  pass representative managed-endpoint security validation.
- The August 19 Proceed-to-preview decision is recorded under ADR-019; Task-100
  owns signing and managed-endpoint qualification in October after package
  satisfaction.

### TLS-002: Exact-Target Repair Authorization

WHEN the visible launcher prepares a provider TLS repair, THE SYSTEM SHALL
resolve and authenticate the complete runtime and mutation target before asking
for confirmation, and SHALL reject any material identity change before a write
or restart.

Acceptance:

- Runtime and Compose executables are resolved without current-directory or
  ambient-PATH influence, authenticated through an approved integrity/publisher
  policy that defines signature, publisher, timestamp, revocation/offline,
  version, rollover, and hash rules, invoked by captured absolute identity, and
  revalidated before use.
- Child processes receive a minimal constructed environment. Ambient Docker,
  Podman, Compose, proxy, and CA redirection settings cannot select another
  executable, provider, daemon, context, connection, or trust source.
- Runtime output is streamed under fixed byte/time limits and the verified
  process tree is terminated on overflow/timeout; oversized certificate chains,
  candidates, or generated bundles fail before retention or mutation.
- Docker repair treats a context name as metadata and invokes the captured local
  Windows named-pipe endpoint plus exact authenticated Compose executable.
  Podman repair treats a connection name as metadata and invokes the configured
  running local WSL machine through its captured loopback URI, identity key,
  rootless user socket, exact Podman executable, and independently authenticated
  Compose provider. Rootful, unknown, arbitrary remote, mutable-name-only, or
  ambiguous targets fail before provider discovery or mutation, and TowerScout
  never changes runtime defaults or machine mode.
- The exact ordered Compose files and pre/post normalized models are bound to
  both requested `off|auto|on` mode and the effective CPU/Docker-GPU/Podman-CDI
  decision. Auto fallback and required-GPU failures preserve the existing
  package contract. Unexpected services, build directives, bind or control-
  socket mounts, privilege/namespace changes, ports, devices, configs, or
  secrets fail closed.
- Confirmation binds the actual container, immutable image ID/repository
  digest, project/service, loopback port, config-volume mount, all eight named
  engine-specific volume identities, fixed certificate destinations, selected
  provider, and a privately held Windows-store CA fingerprint. The transition
  plan permits a new container ID only after authorized stop/recreation and only
  when every other bound identity matches.
- The eight volumes remain non-external for supported first-run setup. A process
  with independent authority over the bound Docker/Podman daemon is outside the
  launcher threat boundary. If such a process removes or replaces a volume
  between checks, terminal identity verification reports a mismatch, retains
  protected recovery, and permits neither repair-success nor rollback-success.
- Only the trust anchor must come from server-auth/all-purpose-eligible Windows
  `ROOT`; server/Windows `CA` intermediates may build but never terminate the
  chain. Partial-chain anchoring fails, only the chosen root is exported, and no
  Windows trust-store mutation occurs.
- The public confirmation is specific enough to authorize the bound plan while
  exposing no local path, endpoint, key, environment content, or certificate
  subject/fingerprint.

### TLS-003: Durable Private Repair Recovery

WHEN a confirmed repair can mutate certificate or environment state, THE
SYSTEM SHALL durably arm exact-state rollback before the first mutation and
SHALL preserve protected recovery data until success or rollback is
independently verified.

Acceptance:

- A current-user/SYSTEM-only cross-session target lock prevents concurrent
  mutation of the same verified endpoint/project/config volume without requiring
  administrator privileges.
- Repair and the external provider installer share a canonical cross-session
  package/`.env` lock, acquired before the target lock, so neither overwrites the
  other's edit; context/connection names and ambiguous string concatenation are
  not lock authority.
- Under that shared lock, both paths scan the protected state root for pending
  repair and provider journals bound to the same package-parent/`.env` identity.
  New mutation remains blocked until every applicable protocol is reconciled to
  a safe terminal state, including after an abandoned mutex.
- A versioned write-ahead journal and exact prior-state backups are stored under
  Windows Known-Folder Local AppData with a protected DACL and current-user
  DPAPI confidentiality/integrity after verifying that recovery root is on a
  fixed local non-cloud/non-reparse volume; no plaintext durable recovery copy
  of `.env`, CA, local identity, key, or raw runtime output is persisted.
- Startup detects and idempotently resumes authenticated incomplete recovery
  before enabling another repair. Failed restoration keeps its encrypted data
  and reports recovery pending; it never deletes the only backup or claims the
  repair failed safely.
- Every certificate and `.env` restore/delete is checked for exact
  content/absence, identity, security metadata, and target containment. An
  unrelated post-failure user edit is never overwritten. Forward and rollback
  plaintext temps each use durable planned, created-identity/DACL, and verified-
  content substates so an abrupt process exit is unambiguously recoverable.
- If the original container is absent, recovery restores the prior environment
  and recreates the exact prior profile/image/volumes before certificate access;
  failure to regain verified access preserves recovery data and never creates
  an ad hoc volume helper or guesses a target.
- Handle-based final-path, file-ID, reparse, hard-link, ownership, and DACL
  checks detect drift and reject broad-principal/name-surrogate attacks while
  permitting a stable supported OneDrive/cloud-resolved package location. The
  boundary does not claim defense against a compromised current-user SID, a
  current-user process with bound-daemon mutation authority,
  administrator/SYSTEM, Windows trust policy, or accepted publisher.
- Successful and verified-rollback paths require all eight named-volume
  identities to match and never request `down -v`, `--volumes`, or volume
  deletion. External replacement is detected and retained as recovery-pending,
  not misreported as a completed repair or rollback.
- The Podman Compose provider installer changes only
  `PODMAN_COMPOSE_PROVIDER` through an equivalent protected atomic contract in
  its existing external PowerShell/.NET implementation, verifies the final
  bytes, and leaves no persistent whole-file plaintext root `.env`
  backup or backup-path output. A protected metadata-only transaction record
  identifies any interrupted private temp so the next invocation reconciles
  old/candidate hashes and removes only that exact orphan identity. When `.env`
  was absent, creation uses the authenticated package template and failure
  returns to absence only if the transaction-created identity is unchanged;
  unrelated concurrent files are never deleted.
- Task-086 remains a separate manual/support fallback and is never invoked
  automatically by recovery code.

### UX-EXIT-001: User-Initiated Stop

WHEN a user selects Exit/Stop TowerScout and confirms the action, THE SYSTEM
SHALL stop and remove the TowerScout application container without deleting
named volumes.

Acceptance:

- Docker and Podman are supported.
- The UI does not receive unrestricted runtime control.
- Clear success, failure, and manual fallback guidance is provided.
- Persistent configuration, assets, logs, sessions, and user data follow the
  documented lifecycle contract.

### RUNTIME-001: Final Runtime Matrix

WHEN the final candidate is qualified, THE PROJECT SHALL validate all four
advertised profiles:

1. Docker CPU
2. Docker GPU
3. Podman CPU
4. Podman GPU

Acceptance:

- Each profile passes setup, start, readiness, provider configuration,
  detection smoke, persistence, stop, and restart checks appropriate to that
  profile.
- Podman validation uses an approved non-Docker-Desktop Compose provider.
- Podman GPU validates WSL2/NVIDIA CDI prerequisites and CUDA readiness.
- Provider TLS repair and Exit/Stop behavior are exercised on both engines.
- Any remaining limitation is documented and explicitly accepted before
  freeze.

### RUNTIME-002: Podman Trust Separation

IF Podman image-pull or source-build TLS fails, THEN THE PROJECT SHALL treat it
as a Podman-machine/runtime trust issue separate from application-provider TLS.

Acceptance:

- Task-087 is not expanded to silently modify the Podman machine.
- Required final-package blockers are fixed before release.
- Source-build-only limitations may be documented only after an explicit
  Task-097 decision and owner acceptance.

### SEC-001: Dependency Security Baseline And Release Gate

WHEN GitHub code scanning or release validation reports dependency
vulnerabilities, THE PROJECT SHALL classify every finding by package,
call-path reachability, supported runtime impact, fixed-version availability,
and release severity before final-candidate inclusion.

Acceptance:

- Task-090 records a disposition for all 62 Trivy alerts open on `main` as of
  July 23, 2026.
- Approved dependency changes are implemented and validated under Task-098.
- Newly disclosed findings after the completed Task-098 baseline receive a
  unique follow-up task, fixed-version and supported-path classification, and
  proportionate regression evidence before candidate inclusion.
- No release-blocking critical/high finding remains unresolved.
- A residual critical/high finding requires written project-lead/cdcai-owner
  acceptance, compensating controls, and a follow-up disposition.
- The project does not equate a raw zero-alert count with safety; unreachable,
  ambiguous, and no-fix findings require evidence-backed disposition.
- After the baseline is remediated, CI prevents new critical/high findings or
  requires an explicit time-bounded exception.

Current result:

- Task-090 classified the 62-alert baseline and Task-098 implemented the
  approved remediation through PR #51 / merge commit `e499b50`.
- Main CI blocks new or reintroduced critical/high dependency findings while
  retaining all-severity reporting.
- At the July 27 Task-098 closeout, Dependabot reported eight open torch
  advisories—three medium and five low—that are non-reachable on supported
  paths and require a future coordinated torch/torchvision CPU/CUDA
  qualification cycle.
- Four advisories disclosed August 4-5 temporarily raised the inventory to 12:
  two high, five medium, and five low. The August 7 blocking npm audit also
  detected high-severity `js-yaml` advisory `GHSA-5p4m-2wfm-xmqj` before the
  repository inventory assigned it an alert number.
- Task-099 merged the narrow `aiohttp`, transitive `ip-address`, and transitive
  `js-yaml` fixes through PR #68 / `f460445`, then refreshed GitHub's stale
  root dependency snapshot through PR #69 / `0133b50`.
- Root graph run `31510493332` and main CI run `31510488121` passed. Alert
  `#74` closed without dismissal, the SBOM contains only `aiohttp==3.14.3`,
  and its August 11 closeout inventory contained exactly the eight documented
  torch residuals.
- Dependabot alert `#76` opened after that closeout for high-severity
  development-transitive `extract-zip==2.0.1` through
  `puppeteer@24.19.0 -> @puppeteer/browsers@2.10.8 -> extract-zip`.
- Task-101 is the completed unique follow-up. Its validated remediation uses Node
  `>=22.12.0` and exact `puppeteer@25.8.0` /
  `@puppeteer/browsers@3.2.1`, removes `extract-zip` from the lock and installed
  graphs, and restores a clean blocking frontend audit. The vulnerable path was
  absent from the shipped Python runtime image and normal-user Windows package.
  Final PR #72 CI/CD run `32308971393` and Task-087 run `32308971392` passed at
  `820b649`. PR #72 squash-merged as `0cc189c`; exact-main CI/CD run
  `32310281115` and Task-087 run `32310281051` passed, and alert `#76` closed as
  fixed without dismissal.
- PR #73 recorded the post-merge governance checkpoint and squash-merged as
  `9276084`; exact-main CI/CD run `32377736719` and Task-087 run `32377736797`
  passed. Draft PR #67 reconciliation head `946deaf` then integrated that
  current `main` while preserving ADR-019 and the branch's recorded evidence;
  CI/CD run `32383065903` and Task-087 run `32383065959` passed with all
  required jobs successful.
- Task-101 is complete. The Task-087 lifecycle head `6e0f744` passed exact-head
  CI/CD run `32385304086` and Task-087 run `32385304052`, so the temporary
  governance revalidation hold is closed. Independent technical/security review
  then requested source changes at that head. Task-087 remains active but
  remediation-gated; PR #67 stays Draft, and source merge, unsigned-preview
  publication, and signed-candidate publication retain their separate Task-087,
  ADR-019, and Task-100 gates.

## Qualification And Handoff Requirements

### QUAL-001: Owner-Runnable Qualification

WHEN the unsigned package shape is stable, THE PROJECT SHALL prepare and
rehearse a bounded qualification process the cdcai owner can execute or
supervise without the outgoing developer. WHEN Task-100 produces the signed
candidate, THE PROJECT SHALL reuse that process for final signed acceptance.

### DATA-001: Persistent Data Lifecycle

WHEN the owner rehearses upgrade, rollback, cleanup, or recovery, THE PROJECT
SHALL distinguish container removal from named-volume deletion and require
explicit confirmation for destructive actions.

### DOC-001: Documentation Currentness

WHEN the final candidate is prepared, THE PROJECT SHALL update repository
documentation, release notes, the external Setup Guide, and the demo video to
match the actual package.

Acceptance:

- Administrator documentation explains the opt-in Model Upload Key, including
  secure generation, private storage, rotation, enable/disable behavior, and
  troubleshooting without exposing a real key.
- Approved-model onboarding explains both required controls: the administrator
  key and the model file's approved SHA-256 hash.
- End-user documentation makes clear that normal users do not need the key and
  that model upload remains disabled unless an administrator explicitly
  enables it.

### HANDOFF-001: Tool-Neutral Maintenance Foundation

WHEN ownership transfers, THE PROJECT SHALL provide repository-native,
tool-neutral maintenance procedures and a prioritized Markdown backlog that do
not assume continued Codex or ChatGPT availability.

### HANDOFF-002: Hard Closeout

WHEN October 30, 2026 is reached, THE PROJECT SHALL have completed operational
sign-off, access/custody transfer, task disposition, backlog transfer, and
owner-run release/recovery rehearsal. No planned work may depend on the
outgoing developer after October 31.

## Schedule And Scope Controls

- August 28 is the latest responsible Task-058 capacity checkpoint, not an
  earliest start date.
- September 18 is the internal code-complete target.
- September 25 is the feature/documentation-complete and satisfactory unsigned
  package target.
- October 1 is the earliest Task-100 activation date, and only after the
  satisfactory-package decision is recorded.
- October 9 is the signed `v0.1.3-rc.N` content/candidate freeze target.
- October 16 is the Task-100 managed-endpoint and acceptance target.
- October 23 is the owner-operated handoff rehearsal target.
- October 30 is operational closeout.

Task-058 may start early only after Tasks 090, 098, 099, 101, 087, 096, and 097
have passed their gates. Task-059 remains optional and may start only after
Task-058 acceptance without threatening required milestones.
