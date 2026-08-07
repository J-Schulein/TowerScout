# TASK-087: Host-Side TLS Repair Control Plane

**Status**: IN_PROGRESS - the exact-source unsigned full-runnable validation
package at `4327fb6` passed pristine verification, fresh Docker CPU setup,
reboot persistence, three launcher refreshes, preview-only output, and the
expected sanitized provider-TLS classification; the signed representative
managed-endpoint gate remains open
**Type**: B/C (Runtime Support / Setup UX / TLS Trust)
**Priority**: HIGH
**Estimated Effort**: Prototype through August 14; retain or revise the prior
4-7 day implementation estimate only if the prototype passes
**Target Sprint**: Sprint 08 feasibility checkpoint, with continuation governed
by the August 14 decision and the canonical October roadmap
**Created**: 2026-06-29
**Owner**: TowerScout release owner / active agent support
**Depends On**: `TASK-086`; `TASK-090` investigation; approved `TASK-098`
dependency remediation/disposition; package launcher/runtime profile; provider setup error
classification; Docker and Podman CPU/GPU package paths

## Canonical Source Note

This file preserves the canonical gated Task-087 design and evidence. The
dormant browser/helper Gate 3 non-mutating proof is merged on `main`; the newer
ADR-018 Python/Tkinter launcher proof is implemented only on the isolated
feature branch and is not merged. The command-based Task-086 path remains the
supported fallback until all Task-087 gates pass.

The current exact-source checkpoint is commit
`4327fb6288f4f8c83202f548a2ba7cb2dcf9bab6`, which includes the launcher
runtime correction from `18082cf`. Its full-runnable package is an unsigned,
validation-only functional artifact. It is not a release candidate, release,
merge signal, or substitute for the signed representative managed-endpoint
gate.

Sanitized full-package functional evidence is recorded in
[`FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md`](./TASK-087/FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md).

## August 5, 2026 Provisional Launcher Override

This override controls wherever the older loopback-helper plan, gates,
acceptance criteria, or implementation phases below conflict. Those sections
remain as historical design and evidence; they do not authorize activation of
the helper during this checkpoint.

- Prototype a visible package-local Windows launcher/coordinator in one
  selected, maintainable technology.
- Begin with non-mutating TowerScout status and TLS repair preview. Do not bind
  a listener, import or start the dormant helper, accept browser-issued host
  operations, use hidden workers or normal-path execution-policy bypasses, or
  modify the Windows trust store.
- Keep all existing helper/browser mutation flags off. Put PR #64 on hold; do
  not merge, close, discard, or extend its activation path before the August 14
  disposition.
- Keep Task-086 as the supported user-run command repair throughout the proof.
- Start approved signing-path coordination in parallel. Unsigned or self-signed
  development evidence can prove functionality or signing mechanics only.
- Require the production-shaped signed artifact to pass representative
  managed-endpoint security validation before candidate inclusion.
- If the non-mutating proof passes, use Task-096 Stop as the preferred first
  controlled mutation before implementing transactional TLS repair.
- Record proceed, conditional, or stop by August 14 under
  [`ADR-018`](../../decisions/018-task-087-windows-launcher-feasibility-pivot.md).
- Publish the bounded source through a Draft PR, then build only
  `Task-087-validation-<short-SHA>` from its exact commit. Do not create a tag,
  GitHub Release, `v0.1.3-rc.N` identity, or cdcai change for this artifact.
- Keep the Draft PR unmerged while validation is incomplete. A failed result
  closes it unmerged and records the Stop/Task-086 disposition through a clean
  documentation-only PR from current `main`, so no code revert is needed.
- A failed proof returns to the Task-086 manual repair without changing the
  frozen pilot, cdcai, or the September/October milestones.

## July 23, 2026 Rebaseline Override

This override controls wherever older planning language below conflicts:

- The guided repair must support both Google Maps and Azure Maps.
- Application-provider TLS repair must work with Docker and Podman.
- Managed-network validation is available on the current CDC-connected device
  and is required before candidate inclusion.
- The existing helper security model, manual fallback, and gated rollout stay
  in force.
- Podman Compose-provider installation remains a separate operation and will
  not be silently coupled to TLS repair.
- Podman-machine image-pull and source-build TLS belong to Task-097, not this
  task.
- The frozen `v0.1.2` Pilot Package is unchanged; this work targets a new
  `v0.1.3-rc.N` candidate.

## Historical Dormant-Helper Design And Evidence

The sections from `Objective` through `Risks` below preserve the earlier
browser-to-loopback-helper design and its completed evidence. They are not the
current implementation plan and do not override the August 5 launcher boundary,
ADR-018, or the current Implementation Log. They remain here so reviewers can
trace why the launcher pivot occurred without treating the dormant helper as
an authorized fallback.

## Objective (Historical Dormant-Helper Plan)

Design and implement a support-safe host-side repair control plane that lets
TowerScout present a guided "repair TLS trust and restart" action when provider
setup detects a managed-network TLS certificate trust failure. The action should
reuse the validated `TASK-086` repair flow, preserve the user's selected runtime
mode, and restart TowerScout without requiring the user to manually run:

```powershell
.\scripts\repair-provider-tls.cmd -Provider google -Engine docker -Gpu off -Apply
.\scripts\stop.cmd -Engine docker
.\start.bat -Engine docker -Gpu off
```

The goal is to reduce first-cohort support friction for managed-network users
while preserving the manual command path as the fallback and audited baseline.

## Problem Statement

`TASK-086` proved that TowerScout can repair the observed Google Maps
managed-network TLS trust failure by importing the organization/root TLS
inspection CA into the
container trust bundle and persisting `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`.
However, the validated repair still requires users or support staff to leave the
browser, run package-local scripts, stop the runtime, and restart with the same
CPU/GPU mode they intended to use.

The browser UI cannot safely execute host commands directly, and the Linux
container cannot inspect the Windows certificate store or control the host
Docker/Podman runtime by itself. Any one-click UX therefore needs a narrow,
explicit, host-side control plane launched by the trusted package scripts.

Podman users have a related host-side setup risk: `podman compose version` can
fail or resolve to an unapproved Compose provider. The existing package already
contains an approved-provider gate and the
`scripts\install-podman-compose-provider.cmd -Apply` command, but users still
have to run that path manually when the Podman runtime profile is otherwise
selected. If Task-087 includes Podman runtime remediation, it should be treated
as a separate helper operation, not as part of the TLS repair command itself.

## Planning Decision

Implement this as a package-local Windows host helper, not as arbitrary command
execution from the web UI and not as a container-side Docker socket mount.

The host helper should:

- Start only from TowerScout's trusted Windows launcher/setup path.
- Bind only to loopback.
- Use a per-run random token.
- Expose a very small allowlisted API.
- Invoke only TowerScout-owned scripts with validated enum-style arguments.
- Preserve the captured runtime profile when restarting.
- Emit support-safe status messages without API keys, certificate thumbprints,
  certificate subjects, raw provider responses, or environment dumps.

The same helper framework may also expose a Podman Compose provider preflight
and remediation operation. That operation must be separate from provider TLS
repair, limited to captured `engine=podman` runtime profiles, and require
explicit user confirmation before running the existing package-local installer.
It must not silently install a Compose provider as a side effect of TLS repair.

## First Implementation Slice Boundary

The first user-facing implementation slice should focus on Docker CPU/CUDA
provider TLS repair and restart only. That slice may include sanitized Podman
Compose provider preflight status if needed to protect Podman restarts, but it
should not run the Podman Compose provider installer from the product UI until
the helper transport, security model, operation lifecycle, and Docker reconnect
UX are proven.

Podman Compose provider remediation remains valid scope for Task-087, but it is
a separate later slice unless the team explicitly approves it after Gates 1 and
2 pass. The first-slice success criterion is a support-safe Docker CPU repair
and restart path that preserves the manual `TASK-086` command fallback.
Any product UI that exposes the Podman Compose provider installer requires
explicit release-owner sign-off after the first Docker helper proof succeeds,
even if sanitized Podman preflight status is implemented earlier.

## Recommended Release Position

Do not treat `TASK-087` as part of the validated RC7.1 baseline unless the team
decides later tester workflow evidence requires one-click repair before the next
user-facing package.

`TASK-086` remains the validated repair baseline for RC7.1. `TASK-087` is now
the active Sprint 7 follow-on support UX improvement, but the command-based
repair path remains the fallback until the helper gates pass.

## Required Go/No-Go Gates

Implementation must proceed through gates. Do not start product UI integration
until Gates 1 and 2 pass.

### Gate 1: Helper Transport Proof

Proceed only if a package-local helper can:

- Bind to `127.0.0.1` without administrator URL ACL setup.
- Accept browser calls from the current TowerScout localhost origin with strict
  token and origin checks.
- Survive the TowerScout container stop/start sequence.
- Survive `setup-towerscout.ps1`, `bootstrap.ps1`, and `launch.ps1` process
  exit when needed for first-run UX, while still self-terminating through TTL,
  package-instance heartbeat, container-exit detection, or explicit stop
  cleanup.
- Integrate with the stop path so `scripts\stop.cmd` terminates or invalidates
  the helper session whenever practical.
- Launch package-local scripts reliably.
- Inspect Podman Compose provider status through the existing approved-provider
  checks when the captured runtime profile uses `engine=podman`.
- Exit cleanly when the package runtime exits.
- Work on the intended managed-network Windows validation environment.

### Gate 2: Security Proof

Proceed only if tests and review prove:

- There is no arbitrary command execution surface.
- Unknown providers, engines, GPU modes, ports, command paths, script paths, and
  extra arguments are rejected.
- Process invocations use validated argument arrays, not caller-supplied command
  strings.
- Podman provider remediation, if included, never accepts provider ids,
  install directories, Python paths, force flags, command paths, or extra
  arguments from the browser.
- The helper never changes `PODMAN_COMPOSE_PROVIDER` or installs a Compose
  provider without explicit user confirmation for a separate Podman remediation
  operation.
- Helper tokens are never written to readiness output, status output, logs,
  support bundles, browser console output, or DOM attributes.
- Helper progress is emitted as sanitized operation states, not raw subprocess
  output.
- The durable helper token never goes to the frontend. Browser-visible code may
  receive only a short-lived operation credential or one-time operation nonce
  that expires quickly and is not rendered into static HTML, DOM attributes,
  readiness payloads, status payloads, logs, or support bundles.
- The helper allows at most one active host operation per package instance.
  Duplicate starts, reloads, and double-clicks return the existing operation or
  a support-safe busy state instead of launching a second repair/install action.

### Gate 3: Product Integration Proof

Proceed only if frontend/backend tests prove:

- The repair button appears only for repairable TLS trust categories.
- Invalid-key, quota, provider-disabled, provider HTTP, and generic network
  failures never show the host repair action.
- Setup Wizard preserves structured validation details end-to-end, including
  `category`, `provider`, `repairable`, `support_action`, `repair_command`, and
  `helper_available`.
- Setup Wizard retains the last structured validation failure object per
  provider for repair-button rendering and does not collapse repairable
  failures into booleans plus message strings.
- Podman Compose provider remediation, if exposed in product UI or launcher UI,
  appears only for captured `engine=podman` runtime profiles and
  missing/unapproved/multiple-provider states.
- Product UI exposure for the Podman Compose provider installer is blocked
  until the release owner signs off after the Docker CPU/CUDA helper proof.
- Podman Compose provider remediation is not shown for Docker runs, invalid
  provider keys, quota failures, provider-disabled failures, or generic
  provider HTTP failures.
- Helper-unavailable is treated as a normal fallback path, not a broken setup
  state.

### Gate 4: Managed-Network Package Validation

Proceed to user-facing package inclusion only after managed-network validation
confirms:

- The guided button path works.
- The documented command fallback still works.
- If Podman remediation is included, the package validates the approved
  provider check, user-confirmed installer path, sanitized failure states, and
  manual fallback instructions on a Podman-assigned validation host.
- CPU and CUDA package variants include helper artifacts.
- CPU and CUDA package variants exclude helper token files, runtime profiles,
  helper logs unless explicitly support-safe, `.env`, `.env.backup.*`, TLS
  bundle material, local certificate exports, and Podman provider install
  caches unless intentionally packaged.

## Phase 1 Evidence Template

Use this template for Gate 1 and Gate 2 evidence before product UI work starts.
Record sanitized outcomes only. Do not include local listener ports, helper
tokens, operation credentials, certificate subjects, certificate thumbprints,
provider keys, raw provider responses, raw subprocess output, full local paths,
browser network traces, screenshots, `.env` values, or support logs.

```markdown
### Phase 1 Evidence - [YYYY-MM-DD] - [Scenario]

**Gate**: Gate 1 Helper Transport Proof / Gate 2 Security Proof
**Environment**: Windows package context, engine, GPU mode, package flavor, and
managed-network status using public-safe labels only
**Objective**: [What the proof validates]
**Command Category**: [helper start / health check / origin-token check /
allowlist rejection / script invocation / restart survival / stop cleanup]
**Inputs**: Provider enum, engine enum, GPU enum, confirmation value, and
sanitized operation state only
**Observed States**: [sanitized helper states such as ready, operation_busy,
restarting, readiness_waiting, rejected_unknown_provider, failed]
**Result**: PASS / FAIL / PARTIAL
**Redaction Check**: Confirm no tokens, credentials, certificate details, raw
output, local paths, `.env` values, or support logs were recorded
**Follow-Up**: [Next action or blocker]
```

## Non-Goals

- Do not silently repair TLS trust without explicit user confirmation.
- Do not expose a general-purpose command runner, shell endpoint, or script path
  parameter.
- Do not mount the Docker or Podman control socket into the application
  container.
- Do not bake a CDC, organization, or site-specific root CA into the public
  TowerScout image.
- Do not move provider validation to the host as the primary product path.
- Do not require an admin-installed Windows service for the first slice unless
  the loopback helper proof of concept fails.
- Do not silently install or reconfigure a Podman Compose provider.
- Do not let the browser choose a Podman provider id, install directory, Python
  executable, force flag, provider path, command path, or installer arguments.
- Do not treat a successful Podman Compose provider install as proof that the
  Podman machine, GPU CDI path, image pull path, or managed-network access is
  otherwise ready.
- Do not record raw certificate subjects, raw thumbprints, API keys, or provider
  response bodies in task docs, user-visible UI, support bundles, or package
  evidence.
- Do not stream raw `repair-provider-tls.cmd` or `import-tls-ca.cmd` subprocess
  output into the browser UI.

## Target User Flow

1. User starts TowerScout from the CPU or CUDA application package.
2. The launcher records the runtime profile: engine, GPU mode, port, package
   root, image/package identity, and any support-safe launch metadata needed for
   restart. Runtime profile generation should come from a shared launcher helper
   used by setup and direct start/launch paths, not from setup-only code.
3. The launcher starts a package-local host helper bound to `127.0.0.1` on a
   random available port with a durable package-local token that never reaches
   the frontend directly.
4. User reaches Setup Wizard and enters a Google Maps key.
5. Provider validation detects a repairable TLS certificate trust failure.
6. Setup Wizard shows the current support command fallback and, when the helper
   is available, a guided repair button.
7. User confirms that TowerScout will inspect the local Windows certificate
   chain, update the container CA bundle, and restart the app.
8. The UI requests the repair operation through the helper control plane.
9. The helper runs the validated `TASK-086` repair path for the current provider
   and runtime mode, then stops and restarts TowerScout with the same selected
   engine, GPU mode, port, and package.
10. The UI enters a reconnecting state and polls readiness until TowerScout is
    available again.
11. Setup Wizard resumes and revalidates the provider key without presenting the
    TLS failure as an invalid key.

Optional Podman Compose provider remediation flow:

1. User starts TowerScout with a captured `engine=podman` runtime profile, or
   support selects the Podman runtime path before launch.
2. The launcher/helper checks the existing approved-provider rules:
   `PODMAN_COMPOSE_PROVIDER`, approved providers on `PATH`, and
   `podman compose version` output.
3. If no approved provider is present, multiple approved providers are present,
   or the resolved provider is disallowed, the helper reports a sanitized
   Podman provider status and keeps the manual command fallback visible.
4. User explicitly confirms installing the package-local approved provider.
5. The helper runs only `.\scripts\install-podman-compose-provider.cmd -Apply`
   with no browser-supplied installer arguments.
6. The helper reports sanitized operation states and, on success, reruns the
   provider check before any Podman restart attempt.
7. If installation fails because Python, download access, hash validation, or
   environment policy blocks the installer, the helper shows support-safe
   fallback guidance instead of raw installer output.

## Architecture Plan

### 1. Runtime Profile Capture

Add a package-local runtime profile written by the trusted launcher path. The
profile should contain only support-safe, non-secret values:

- Engine: `docker` or `podman`.
- GPU mode: `off`, `on`, or `auto` after existing package guardrails.
- Port and effective base URL.
- Package root path.
- Package flavor: CPU or CUDA 12.1.
- Compose project name if needed to target the active container.
- Podman Compose provider status when `engine=podman`: `approved`, `missing`,
  `unapproved`, `multiple`, or `unknown`, plus a support-safe provider label
  when one can be shown without exposing full local paths.
- Image tag/digest or package manifest identity when available.
- Host helper port and token location, with the token stored outside logs.
- Helper session id and runtime profile creation timestamp.
- Package root identity and resolved script paths derived from the trusted
  launcher, not from browser input.
- Current container/service identity when available, so the helper can detect a
  stale or wrong-package operation before repairing or restarting.

Runtime profile generation belongs in a shared launcher helper that is called
by setup/bootstrap/start/launch entry points. It must not live only in
`setup-towerscout.ps1`, because direct `start.bat` / `scripts\launch.ps1`
sessions need the same profile freshness, identity checks, and restart
metadata.

The runtime profile should be ignored by git and excluded from release source
artifacts unless it is generated at package runtime.

The helper must reject stale or mismatched runtime profiles. This includes
profiles from another TowerScout folder, profiles whose package root no longer
matches the helper process, profiles whose container identity does not match the
active runtime, expired helper sessions, and multi-instance ambiguity. If the
helper cannot prove it is targeting the correct runtime, it should block the
guided repair and show the manual command fallback.

### 2. Host Helper Proof Of Concept

Build a minimal Windows helper proof of concept before UI integration. The first
candidate should be PowerShell because it is already available in the supported
Windows package environment.

The proof of concept must confirm:

- A loopback-only listener can run without requiring administrator URL ACL
  registration.
- Browser-to-loopback requests work from the current TowerScout origin with the
  intended CORS, origin, token, and private-network behavior.
- Corporate endpoint protection does not block the local listener in the target
  validation environment.
- The helper can remain available while Docker/Podman stops and restarts the
  TowerScout container.
- The helper can survive launcher/setup process exit through a deliberate
  detached, supervised, or heartbeat-based lifecycle model.
- The helper self-terminates when its TTL expires, the package-instance
  heartbeat disappears, the active container exits and is not being restarted,
  or the package stop cleanup explicitly asks it to stop.
- `scripts\stop.cmd` terminates the helper process or invalidates the helper
  session whenever practical, so a stopped package cannot retain a usable
  browser-to-host operation credential.
- The helper exits cleanly when the package runtime is stopped.

If PowerShell `HttpListener` requires admin URL ACL setup or proves brittle,
evaluate a fallback such as a small package-local native helper or a narrower
protocol/IPC mechanism before attempting product UI integration.

For the first implementation slice, prefer direct browser-to-loopback-helper
calls if the proof of concept confirms the browser, CORS, origin, token, and
private-network behavior is reliable. This keeps host-control behavior local to
the host helper and avoids requiring the container backend to reach a host-side
control endpoint. If browser-to-loopback access proves brittle in the target
environment, revisit backend brokering as a fallback rather than switching
security models without a new design review.

### 3. Helper API

Expose only narrow, allowlisted operations:

- `GET /health`
  - Returns helper availability, helper version, and sanitized runtime profile
    summary.
- `GET /runtime-profile`
  - Returns engine, GPU mode, package flavor, port, and package/image identity.
  - Must not return provider keys, environment dumps, certificate subjects, or
    thumbprints.
- `GET /runtime-preflight`
  - Returns sanitized host-runtime readiness for the captured profile.
  - For Podman, includes approved Compose provider status without raw
    `podman compose version` output or full local provider paths.
- `POST /operations/provider-tls-repair`
  - Accepts a validated provider enum such as `google` or `azure`.
  - Accepts only a fixed confirmation value such as
    `repair_tls_and_restart`; restart behavior is derived from the operation
    type and runtime profile, not from a browser-selected restart mode.
  - Creates an operation id and starts the repair asynchronously.
- `POST /operations/podman-compose-provider-repair`
  - Available only when the captured runtime profile uses `engine=podman`.
  - Accepts only an explicit confirmation boolean or equivalent CSRF-safe
    acknowledgement.
  - Runs the fixed package-local installer command
    `scripts\install-podman-compose-provider.cmd -Apply`.
  - Must not accept provider id, install path, Python path, force flag,
    provider path, command path, or arbitrary arguments from the caller.
- `GET /operations/{operation_id}`
  - Returns sanitized progress, terminal status, and support-safe next action.

The helper must reject:

- Unknown providers.
- Unknown engine or GPU values.
- Unexpected ports or package roots.
- Caller-supplied command paths.
- Caller-supplied arbitrary arguments.
- Caller-supplied Podman provider ids, install roots, Python executables, force
  flags, provider paths, or installer arguments.
- Non-loopback requests.
- Requests without the one-time token.
- Requests from unexpected origins.
- Stale helper tokens or runtime profiles.
- Requests that cannot be associated with the active TowerScout package
  instance.

Operation lifecycle rules:

- The helper must allow only one active mutating operation per package instance.
- Duplicate-clicks, page reloads, and repeated POSTs with the same operation
  nonce should return the existing operation id and status when safe.
- A different operation request while one is active should return a sanitized
  `operation_busy` state.
- Each operation must have a timeout, terminal state, cleanup path, and safe
  retry rule after terminal failure.
- Terminal-state polling must continue to work across the TowerScout restart
  window.
- Stop cleanup must terminate or invalidate active operations and helper
  credentials whenever `scripts\stop.cmd` is used for the selected engine.
- For the non-mutating control-plane slice, `planned` operations remain active
  until their operation timeout; after timeout, status polling returns
  `operation_expired` with HTTP 410 and clears the operation lock.
- Before mutating execution is enabled, each script-exit state must be classified
  as success, retryable failure, support-escalation failure, or timeout. Retrying
  with a new authorization must be allowed only after the prior operation reaches
  a terminal state or is cleared by timeout/stop cleanup.

### 4. Restart Orchestration

Reuse the existing validated scripts rather than duplicating repair logic:

```powershell
.\scripts\repair-provider-tls.cmd -Provider <provider> -Engine <engine> -Gpu <gpu> -Apply
.\scripts\stop.cmd -Engine <engine>
.\start.bat -Engine <engine> -Gpu <gpu> -Port <port> -NoBrowser
```

The helper should derive `<engine>`, `<gpu>`, and `<port>` from the launcher
runtime profile, not from the browser request. It should preserve the user's
original CPU/CUDA package intent and respect the existing CPU-package
`-Gpu on` guardrail.

When `<engine>` is `podman`, the helper should run the approved Compose
provider preflight before stopping the current app or attempting restart. If
the provider is missing, unapproved, ambiguous, or `podman compose version`
does not complete, the TLS repair operation should block with a sanitized
Podman-provider-required state and offer the separate Podman remediation path
or the manual command fallback. It should not stop a running TowerScout
container when the captured restart path is likely to fail because the Compose
provider is not approved.

Restart progress should distinguish:

- Certificate candidate selection failed.
- Multiple CA candidates had the same score and require manual support review.
- CA import failed.
- Provider TLS verification failed.
- Stop failed.
- Restart failed.
- Restart succeeded but readiness did not return before timeout.
- Restart succeeded and provider setup can be retried.

The helper must not stream raw `repair-provider-tls.cmd` or
`import-tls-ca.cmd` output into the browser. Those scripts intentionally print
support-sensitive local certificate details in the manual dry-run path. The
helper should map subprocess exit codes and known output markers to sanitized
states such as `inspecting_certificate_chain`, `ca_candidate_selected`,
`ca_candidate_ambiguous`, `importing_bundle`, `provider_tls_verified`,
`restarting`, `readiness_waiting`, `ready`, and `failed`.

#### Controlled Execution Design Review Target

The first mutating execution design must remain Docker CPU/CUDA only and must
not expose product UI or Podman remediation. The helper may execute only the
internally generated operation plan from `New-TowerScoutProviderTlsRepairOperationPlan`.
Browser input must never change script path, command path, engine, GPU mode,
app port, provider argument order, `-Apply`, `-NoBrowser`, timeout values, or
working directory.

Controlled command runner contract:

- Accept only the already accepted operation plan and runtime profile.
- Reject any plan whose `InternalCommands` script paths are not the exact
  allowlisted package-local wrappers:
  `scripts\repair-provider-tls.cmd`, `scripts\stop.cmd`, and `start.bat`.
- Resolve command paths under the captured package root and reject paths that
  escape that root.
- Build process invocations from structured argument arrays only. Do not build
  shell command strings from browser input.
- Treat Windows `.cmd` and `.bat` execution as an explicit interpreter boundary:
  the helper must select a fixed local Windows command interpreter, keep that
  interpreter non-browser-selectable, and test that browser input cannot alter
  interpreter path or interpreter flags.
- Use one package-root working directory for all steps.
- Capture stdout/stderr only for internal marker parsing and support-safe
  diagnostics. Do not return raw subprocess output to the browser, readiness,
  status, logs intended for normal users, task evidence, or PR evidence.
- Map each step outcome to the public state table below and persist only
  support-safe state, step, timestamps, operation id, provider enum, runtime
  summary, timeout metadata, and next action.
- Enforce per-step timeouts and the existing overall operation timeout. If a
  step hangs, mark `operation_timeout`, clean up the child process if possible,
  and leave restart fallback guidance.
- Keep same-authorization requests idempotent while an operation is active or
  terminal-but-retained. Different authorization while active returns
  `operation_busy`.
- Permit a new authorization only after terminal failure is retained and the
  prior operation is explicitly cleared, expires, or stop cleanup invalidates the
  helper session. Do not automatically retry without user/support confirmation.

Script-exit public-state policy:

| Public state | Source step | Classification | Retry / next action |
|---|---|---|---|
| `tls_repair_completed` | repair exit 0 | Intermediate success | Continue to runtime stop. |
| `tls_repair_selection_required` | repair exit 2 | Terminal support-escalation | Do not retry automatically; use manual dry-run/support selection. |
| `tls_repair_failed` | repair nonzero other than 2 | Terminal support-escalation | Allow new authorization only after status review or timeout/cleanup; keep manual command fallback. |
| `runtime_stopped` | stop exit 0 | Intermediate success | Continue to restart. |
| `runtime_stop_failed` | stop nonzero | Terminal retryable with support review | Do not start runtime; allow retry only after user/support confirms runtime state. |
| `ready` | start/readiness success | Terminal success when readiness passes | Return repair complete and ask user to retry provider validation. |
| `readiness_timeout` | start/readiness exit 2 | Terminal timeout | Provide fallback guidance; allow new authorization after timeout/cleanup if app remains unavailable. |
| `runtime_start_failed` | start nonzero other than 2 | Terminal support-escalation | Keep manual start command fallback; do not retry automatically. |
| `readiness_failed` | readiness nonzero other than 2 | Terminal support-escalation | Keep manual status/log guidance; do not retry automatically. |
| `operation_timeout` | any timed-out step | Terminal timeout | Kill/cleanup child process if possible, clear or expire lock according to timeout policy, and require new authorization for retry. |

Execution-runner tests required before enabling execution:

- Prove browser input cannot alter script path, command path, engine, GPU mode,
  app port, provider argument order, `-Apply`, `-NoBrowser`, or timeout values.
- Prove browser input cannot alter the fixed `.cmd`/`.bat` interpreter path or
  interpreter flags.
- Prove raw stdout/stderr, local paths, certificate details, provider keys, and
  helper tokens are absent from public operation status.
- Prove timeouts produce `operation_timeout` without leaving concurrent active
  operation locks.
- Prove same authorization remains idempotent and different authorization remains
  `operation_busy` during each active execution step.
- Prove terminal success, retryable failure, support-escalation failure, and
  timeout states follow the table above.

### 5. Podman Compose Provider Preflight And Remediation

If included, Podman Compose provider remediation should reuse the current
approved-provider implementation rather than inventing a second validation
model:

- Use the same approved-provider catalog that backs
  `scripts\install-podman-compose-provider.cmd`.
- Reuse the existing checks for `PODMAN_COMPOSE_PROVIDER`, approved providers
  on `PATH`, Docker Desktop provider rejection, and
  `podman compose version` inspection.
- Treat `missing`, `unapproved`, `multiple`, `version_failed`, and
  `install_failed` as support-safe states.
- Run only `scripts\install-podman-compose-provider.cmd -Apply` after explicit
  confirmation.
- Recheck provider status after install before continuing.
- Redact or omit full local provider paths, Python paths, install directories,
  `.env` backup paths, download URLs, and raw installer output from browser UI
  and task evidence.
- Preserve the manual command fallback:

```powershell
.\scripts\install-podman-compose-provider.cmd -Apply
```

This operation is host-runtime remediation, not provider-key validation and
not TLS certificate repair. It should be safe to skip without weakening the
validated `TASK-086` command fallback.

Product UI exposure for this installer operation requires explicit
release-owner sign-off after the Docker CPU/CUDA helper proof succeeds. Until
that sign-off exists, product UI may surface sanitized Podman preflight status
and the manual command fallback, but it must not start the installer operation.

### 6. Backend And Setup Wizard Integration

Extend the existing structured provider validation error path from `TASK-086`.

Backend responsibilities:

- Preserve existing TLS-vs-invalid-key categorization.
- Report whether a TLS failure is repairable.
- Report whether the host helper is available, without logging the helper token.
- Mediate short-lived helper operation authorization when browser-visible code
  needs to call the helper. The durable helper token should remain
  package-local and should not be emitted through config/status/readiness
  routes, hidden DOM fields, inline script state, browser console output, or
  logs.
- Keep the manual `repair_command` fallback visible in the structured details.
- Avoid treating a repairable TLS certificate failure as a bad provider key.
- Preserve and return helper-specific structured fields without exposing token
  values: `category`, `provider`, `repairable`, `support_action`,
  `repair_command`, `helper_available`, and operation status when applicable.

Frontend responsibilities:

- Show the repair button only when the error category is repairable TLS and the
  helper is available.
- Preserve the last structured validation failure per provider, including
  `category`, `provider`, `repairable`, `support_action`, `repair_command`,
  `helper_available`, and any short-lived operation authorization metadata
  needed to render and start a repair operation.
- Show any Podman Compose provider remediation action only when the captured
  runtime profile is `engine=podman` and the helper reports a provider
  readiness state that is explicitly repairable by the package-local installer.
- Show a confirmation modal before starting host repair/restart.
- Use a separate confirmation modal for Podman provider installation because it
  downloads an approved package, creates a package-local environment, backs up
  `.env`, and updates `PODMAN_COMPOSE_PROVIDER`.
- Display progress from helper operation polling.
- Move to a reconnecting state during restart.
- Poll TowerScout readiness after restart and resume the provider setup flow.
- Suppress duplicate-clicks and page-reload duplicate starts by reusing the
  active operation id when the helper reports one.
- Continue to show the command-based fallback when the helper is unavailable or
  the repair operation fails.
- Treat helper-unavailable as a normal support fallback, not as a broken setup
  state.

### 7. Security And Privacy Requirements

This task changes the trust boundary because a browser-facing UI will initiate a
host-side runtime operation. Treat that as the central design constraint.

Requirements:

- Bind the helper to `127.0.0.1` only.
- Generate a random per-launch token and require it for every mutating request.
- Keep the durable helper token package-local. Browser-visible code may receive
  only a short-lived operation credential or one-time operation nonce that is
  scoped to the requested operation, expires quickly, and is never persisted in
  static HTML, DOM attributes, readiness/status output, logs, task evidence, or
  support bundles.
- Use strict CORS/origin checks limited to the current TowerScout localhost
  origin.
- Require explicit user confirmation before repair/restart.
- Require explicit user confirmation before Podman provider installation or
  `PODMAN_COMPOSE_PROVIDER` changes.
- Validate all request inputs as enums or booleans.
- Build process invocations with argument arrays, not string-concatenated shell
  commands.
- Never accept command text, script paths, or arbitrary arguments from the UI.
- Never accept installer options, provider paths, Python paths, install
  directories, or `-Force` from the UI.
- Never expose the helper token in readiness output, status output, logs,
  support bundles, browser console output, DOM attributes, or task evidence.
- Never expose short-lived operation credentials after their immediate use, and
  never persist them in support evidence.
- Never expose raw helper subprocess output in the browser UI.
- Redact provider keys, provider URLs with keys, certificate subjects,
  thumbprints, environment variables, and raw HTTP responses from helper logs.
- Keep helper logs package-local and support-safe.
- Ensure support bundles and release packages do not include helper token files,
  local runtime profiles, `.env`, `.env.backup.*`, TLS bundle material, or
  generated Podman provider install caches unless those caches are deliberately
  included as release artifacts.

### 8. Test Plan

Automated coverage:

- Unit tests for runtime profile creation and parsing.
- Unit tests for stale, expired, wrong-package, and multi-instance runtime
  profile rejection.
- Unit tests for provider/engine/GPU enum validation.
- Unit tests proving the provider TLS repair operation accepts only provider
  enum plus the fixed confirmation value and rejects browser-selected restart
  modes.
- Unit tests for helper operation locking, duplicate-click idempotency,
  operation timeout, terminal-state cleanup, and safe retry after terminal
  failure.
- Unit tests for Podman Compose provider preflight states if that operation is
  included: approved, missing, unapproved, multiple, version failed, and
  install failed.
- Unit tests proving the helper never exposes arbitrary command execution.
- Unit tests proving the Podman provider operation cannot receive provider id,
  install directory, Python path, force flag, command path, or arbitrary args
  from browser input.
- Unit tests for sanitized progress and failure messages.
- Unit tests proving durable helper tokens and short-lived operation credentials
  are not emitted into status/readiness/log/UI/support-bundle surfaces.
- Backend tests for repairable TLS categories and helper availability metadata.
- Frontend tests for structured provider-failure retention, repair button
  visibility, confirmation, duplicate-click suppression, progress, failure, and
  reconnect states.
- Package-generation tests confirming helper scripts are included and runtime
  profile/token artifacts are excluded.
- Package-generation tests confirming `.env`, `.env.backup.*`, runtime
  profiles, helper tokens, helper logs, and generated Podman provider install
  caches are excluded unless explicitly intended.
- Secret-safety tests or assertions covering API-key and certificate redaction.

Manual validation:

- Docker CPU package on a managed TLS-inspected network.
- Docker CUDA 12.1 package on a managed TLS-inspected network, or CPU-fallback
  CUDA validation if GPU hardware is not available.
- Helper-unavailable path still shows the documented manual commands.
- Repair failure path gives actionable, sanitized support guidance.
- Restart preserves port and CPU/GPU mode.
- Duplicate-click and page-reload behavior does not start concurrent repair or
  install operations.
- Ambiguous CA candidate selection blocks one-click apply and directs support to
  the manual dry-run path.
- Setup Wizard resumes and Google Maps validation succeeds after repair.
- If included, Podman Compose provider remediation succeeds only after explicit
  confirmation and the helper revalidates `podman compose version` through an
  approved provider before restart.
- If included, Podman provider install failure due to Python, download access,
  hash verification, or policy restrictions returns sanitized fallback guidance.
- Logs and support artifacts contain no API keys, certificate subjects, raw
  thumbprints, or helper tokens.
- Multi-instance behavior is explicitly tested or blocked with a clear
  support-safe message.

Optional validation:

- Podman CPU path if selected for the same release train, including approved
  Compose provider check/remediation when that scope is included.
- Multi-instance behavior when another TowerScout package is already running.

### 9. Internal Live Wrapper Validation Runbook

Do not run the live `repair-provider-tls.cmd -Apply`, `stop.cmd`, and
`start.bat` sequence until this runbook is reviewed for the selected validation
window. The live run is internal only; it must not enable product UI,
`provider_tls_repair=true`, browser-triggered default mutation, Podman
remediation, or tester-facing guided repair packaging.

Runbook scope:

- Package/profile: current package-local checkout or validation package for PR
  #45, Docker runtime profile only, CPU/off first. CUDA can follow only after
  the Docker CPU/off sequence is understood.
- Runtime state: TowerScout may be running on the selected app port before the
  live sequence begins; the validation intentionally allows the helper runner
  to stop and restart that runtime.
- Provider: start with `google`, because `TASK-086` established the Google Maps
  managed-network TLS repair baseline. Azure may be tested later only if the
  repairable TLS category is reproduced and the same support-safety boundaries
  apply.
- Port: use the selected runtime profile port, normally `5000` unless the
  validation host already has a deliberate alternate port.
- Expected wrapper sequence: repair, stop, start. No other script or shell
  command is in scope for the helper-controlled live run.
- Expected timeout budget: repair step 300 seconds, stop step 120 seconds,
  start/readiness step 180 seconds, with the existing overall operation timeout
  and operation-lock behavior retained.
- Rollback/manual fallback: keep the audited command path available:
  `.\scripts\repair-provider-tls.cmd -Provider google -Engine docker -Gpu off -Apply`,
  `.\scripts\stop.cmd -Engine docker`, and
  `.\start.bat -Engine docker -Gpu off -Port 5000 -NoBrowser -TimeoutSeconds 180`.
- Evidence location: record only sanitized states in this task file or a
  task-local proof note under `.agent_work/tasks/active/TASK-087/` if the
  evidence needs more space.

Pre-run checklist:

- Confirm the branch/PR head under validation.
- Confirm no product UI repair button is enabled.
- Confirm the public helper runtime profile still reports
  `provider_tls_repair=false` and `podman_provider_repair=false`.
- Confirm `ExecutionEnabled` is supplied only by the internal validation path,
  not by browser input or a persisted default.
- Confirm the selected provider, engine, GPU mode, and app port match the
  intended validation profile.
- Confirm no second TowerScout package instance is using the same runtime
  profile or app port.
- Confirm the manual fallback commands above are available before the run.

Sanitized evidence to record:

- Branch or PR head SHA.
- Runtime summary: `engine=docker`, GPU mode, app port, package flavor label.
- Operation states only, such as `tls_repair_completed`, `runtime_stopped`,
  `ready`, `readiness_timeout`, `tls_repair_failed`, or `operation_timeout`.
- Step order and terminal classification.
- Whether readiness returned and provider setup could be retried.
- Confirmation that no raw subprocess output, helper token, operation
  credential, `.env` content, certificate subject, certificate thumbprint,
  provider key, local full path, browser network trace, screenshot, or support
  log was recorded.

Abort conditions:

- The wrapper contract differs from the expected repair/stop/start sequence.
- Browser input can enable execution or change wrapper paths, arguments,
  command interpreter, GPU mode, engine, port, or timeouts.
- Any public status, task evidence, PR evidence, or helper output includes raw
  subprocess output, helper credentials, certificate details, provider keys,
  `.env` values, or full local paths.
- The runtime profile is stale, ambiguous, or points at another package or app
  port.
- Endpoint protection blocks helper execution in a way that requires bypassing
  the security model.

Post-run checklist:

- Record sanitized PASS/FAIL/PARTIAL evidence.
- If the app is left stopped or degraded, run the manual start fallback before
  ending the validation window.
- Keep product UI, `provider_tls_repair=true`, browser-triggered default
  mutation, Podman remediation, and tester-facing packaging blocked until the
  live evidence is reviewed.
- Ask the reviewer to evaluate whether the live evidence is sufficient to move
  to Gate 3 product integration design.

### 10. Implementation Phases

#### Phase 1: Design Spike

- Treat Docker CPU/CUDA TLS repair and restart as the first implementation
  slice. Podman installer remediation is held until after Gates 1 and 2 unless
  separately approved.
- Decide whether the UI calls the helper directly over loopback or the backend
  brokers the helper request.
- Build a minimal loopback helper proof of concept.
- Confirm PowerShell listener feasibility without admin URL ACL setup.
- Define the runtime profile file shape and token handling.
- Define the shared runtime-profile generation helper and the setup/bootstrap/
  start/launch call sites that must refresh it.
- Define the helper lifecycle model that survives launcher exit but terminates
  through TTL, heartbeat, container-exit detection, or stop cleanup.
- Define how `scripts\stop.cmd` terminates the helper process or invalidates
  the helper session.
- Define runtime profile identity checks, stale-profile rejection, and
  multi-instance behavior.
- Decide whether Podman Compose provider remediation belongs in the first slice,
  and whether it is surfaced through launcher preflight, helper API, or both.
- Define short-lived operation authorization so the durable helper token never
  reaches frontend code.
- Define single-operation locking, idempotency keys or operation nonces,
  timeouts, terminal states, cleanup, and safe retry behavior.
- Define sanitized Podman provider status states and failure mapping.
- Define sanitized operation states and the mapping from repair/restart script
  results to those states.
- Use the Phase 1 evidence template for Gate 1 and Gate 2 proof notes.
- Document the security model and rejection cases before product integration.

Exit criteria:

- Helper transport choice is proven on the target Windows environment.
- Security model is reviewed.
- Gates 1 and 2 pass.
- Manual command fallback remains intact.

#### Phase 2: Host Helper MVP

- Add package-local helper script and `.cmd` wrapper.
- Add runtime profile generation through the shared launcher helper used by
  setup/bootstrap/start/launch paths.
- Add token generation and helper lifecycle management.
- Add stop-path cleanup so `scripts\stop.cmd` terminates or invalidates helper
  sessions whenever practical.
- Add health/runtime-profile endpoint.
- Add asynchronous repair operation endpoint using existing scripts.
- Add single-operation locking, duplicate-start idempotency, operation timeout,
  terminal-state cleanup, and safe retry handling.
- Optionally add a separate Podman Compose provider preflight and remediation
  operation using the fixed package-local installer command.
- Add support-safe progress output.
- Add stale-profile, wrong-package, and multi-instance rejection.

Exit criteria:

- From a local browser or scripted client, the helper can repair and restart a
  Docker CPU package using the captured runtime profile.
- The helper can survive launcher/setup process exit during the repair/restart
  flow and still self-terminate when the package runtime is no longer active.
- The durable helper token is never exposed to frontend-visible surfaces; only a
  short-lived operation credential or one-time operation nonce is used when
  browser-visible code initiates an operation.
- Concurrent repair/install attempts are rejected or deduplicated through a
  support-safe operation status.
- If Podman remediation is included, a scripted client can prove the separate
  operation uses only the fixed installer command, requires confirmation, and
  never accepts caller-supplied installer arguments.
- No arbitrary command execution surface exists.
- Helper progress is sanitized and helper tokens are absent from observable
  output surfaces.

#### Phase 3: Product UI Integration

- Extend backend structured provider setup payloads with helper availability.
- Add Setup Wizard repair button, confirmation, progress, and reconnect states.
- Preserve structured provider validation failures per provider so repair UI
  uses the actual failure category and support fields, not only booleans and
  message text.
- If Podman provider remediation is included in product UI, add a separate
  runtime-preflight action and confirmation path that is not tied to invalid-key
  or TLS error categories.
- Require release-owner sign-off before product UI can expose the Podman
  Compose provider installer operation.
- Preserve the manual command fallback in all failure/unavailable cases.
- Add frontend/backend tests for structured behavior.

Exit criteria:

- Repair button appears only for repairable TLS failures when helper is
  available.
- Invalid-key, quota, provider-disabled, or network-unavailable failures do not
  show the host repair action.
- Duplicate-clicks, reloads, and repeated operation starts do not create
  concurrent host-side operations.
- Gate 3 passes.

#### Phase 4: Package And Validation

- Include helper artifacts in CPU and CUDA packages.
- Exclude runtime profile/token/log artifacts from source and release packages.
- Exclude `.env`, `.env.backup.*`, generated Podman provider caches, and raw
  installer logs from source and release packages unless deliberately included.
- Build an internal validation package before any user-facing package
  inclusion.
- Validate on a managed TLS-inspected network.
- Decide whether the feature is ready for the next RC patch or a later release.

Exit criteria:

- CPU and CUDA package variants include the helper.
- Podman-assigned validation proves the approved-provider check and separate
  installer path if Podman remediation is included.
- Managed-network validation proves the button path and fallback command path.
- Task evidence records sanitized outcomes only.
- Gate 4 passes.

## Acceptance Criteria

- When Google provider validation fails with a repairable TLS certificate trust
  category and the helper is available, Setup Wizard shows a guided repair and
  restart action.
- The action requires explicit user confirmation before host-side repair begins.
- The helper runs the validated `TASK-086` repair flow with the captured engine,
  GPU mode, package root, and port.
- The first user-facing slice repairs and restarts Docker CPU/CUDA package
  profiles only; Podman provider installation is not product-exposed until the
  helper transport, security, and Docker reconnect path are proven and
  separately approved.
- TowerScout restarts in the same CPU/GPU mode the user originally selected.
- The UI enters a reconnecting state and resumes provider setup after readiness
  returns.
- The command-based `repair-provider-tls.cmd` fallback remains documented and
  visible when the helper is unavailable or fails.
- Helper-unavailable is a normal fallback state and does not block setup beyond
  the original TLS issue.
- The helper emits sanitized progress states only and never streams raw
  subprocess output to the browser.
- No API keys, helper tokens, certificate subjects, raw thumbprints, raw
  provider responses, or environment dumps appear in UI, logs, task evidence, or
  support bundles.
- Helper tokens do not appear in readiness output, status output, browser
  console output, DOM attributes, support bundles, helper logs, or task
  evidence.
- Browser-visible code receives only a short-lived operation credential or
  one-time operation nonce, and operation credentials are not persisted in
  logs, support bundles, DOM attributes, readiness/status output, or task
  evidence.
- The helper allows only one active host operation per package instance and
  handles duplicate starts, timeouts, terminal cleanup, and safe retry with
  sanitized states.
- `scripts\stop.cmd` terminates the helper process or invalidates the helper
  session whenever practical, including any active operation credentials.
- Runtime profiles include enough identity to reject stale, expired,
  wrong-package, wrong-container, and ambiguous multi-instance operations.
- Runtime profile generation is shared by setup/bootstrap/start/launch paths so
  direct `start.bat` sessions and first-run setup sessions get the same profile
  freshness and restart metadata.
- Ambiguous CA candidate selection blocks one-click apply and directs support to
  the manual dry-run path.
- If the runtime profile uses `engine=podman` and no approved Compose provider
  is available, the helper blocks guided restart with a sanitized Podman
  provider-required state rather than stopping the current runtime.
- If Podman Compose provider remediation is included, it requires explicit user
  confirmation, runs only `scripts\install-podman-compose-provider.cmd -Apply`,
  revalidates the approved provider before restart, and is exposed in product
  UI only after explicit release-owner sign-off.
- Podman Compose provider remediation is never run automatically as a side
  effect of provider TLS repair.
- Browser input cannot select Podman provider ids, install directories, Python
  executables, force flags, command paths, provider paths, or arbitrary
  installer arguments.
- CPU and CUDA package variants pass package-generation checks and managed
  network validation, or the release notes clearly state any package-variant
  validation boundary.

## Open Questions

- Can a PowerShell loopback listener be used without admin URL ACL setup on the
  intended tester machines?
- Should the browser call the helper directly with strict CORS and token checks,
  or should the container backend broker requests to the helper through a host
  gateway endpoint?
- Should the helper be launched for all runs or only when Setup Wizard/provider
  validation enters a repairable TLS state?
- How should the helper behave if multiple TowerScout packages are running on
  different ports?
- Should Podman support be included in the first implementation slice or held as
  a follow-up after Docker CPU/CUDA validation?
- If Podman support is included, should Compose provider remediation be exposed
  through the launcher before the app starts, through the loopback helper after
  the app starts, or both?
- Should the first Podman remediation slice run the connected installer, or only
  surface preflight status and manual instructions until managed-network
  download/proxy behavior is validated?

## Risks

- A host-side helper increases the security sensitivity of the setup flow.
- Endpoint security tools may block a local listener or child process launch.
- PowerShell `HttpListener` may require URL ACL behavior that is not acceptable
  for non-admin users.
- Restarting the app from a setup screen can lose UI state unless the reconnect
  path is explicit and tested.
- Multiple concurrent TowerScout instances could target the wrong runtime if
  runtime profile identity is weak.
- Over-automating repair could make certificate trust changes feel opaque to
  users; confirmation and fallback documentation are required.
- Mixing Podman provider installation with TLS repair could obscure the actual
  failure if the helper does not keep those operations separate.
- The Podman provider installer depends on Python and connected package
  download/hash verification, so managed-network or restricted-network policy
  can block the remediation even when TLS repair would otherwise work.
- Podman provider paths, Python paths, `.env` backup paths, and installer output
  can expose local environment details if helper output is not sanitized.

## Implementation Log

### 2026-08-07 - Task-099 Merge Reconciled Into Launcher Prototype

**Objective**: Rebase Draft PR #67 onto the Task-099 security-remediation merge
without losing either the final launcher implementation or the newer security
history in shared planning files.

**Context**: PR #68 squash-merged to `main` as `f460445`. A direct replay of
PR #67's 19 historical commits conflicted immediately in six planning files
because those commits contain successive snapshots from before Task-099.

**Decision**: Preserve the original PR head `02b44be` under local checkpoint
`checkpoint/task-087-launcher-prototype-pre-task099-20260807`, abort the
historical replay, and apply the final launcher tree once onto `f460445` in an
isolated worktree. Reconcile only the six shared planning files, retaining both
Task-099 evidence and the latest Task-087 repair state.

**Execution**: Git's final-tree squash merge reproduced all 41 PR files on the
new base. The launcher, runtime scripts, Compose/environment changes, and
focused tests compare byte-for-byte with the preserved `02b44be` tree. The
merged dependency pins remain `aiohttp==3.14.3`, `ip-address==10.3.1`, and
`js-yaml==4.3.1`.

**Validation**:

- Native launcher and release-package unit contracts: 49 passed.
- Combined local helper run: 55 passed and the same 19
  `ScriptContainedMaliciousContent` failures occurred only in the dormant
  PowerShell helper module under this workstation's endpoint policy.
- Agent-work quick/full validators, frontend bundle consistency, and staged
  diff checks: passed.
- Post-merge main CI run `31200873386`, Task-087 run `31200873354`, and
  dependency-graph run `31200874742`: passed.
- Dependabot alerts `#72`, `#73`, and `#75` are fixed. GitHub still reports
  `#74` open while its SBOM records both patched `aiohttp==3.14.3` and a stale
  `3.14.2` entry; no alert was dismissed.

**Next**: Publish the reconciled final-state branch to Draft PR #67, require
green exact-head CI, then produce and validate the latest exact-source
full-runnable package in an approved environment before any signing or merge
decision.

### 2026-08-06 - Visible Controlled Repair UI And Exact-Source Build Added

**Objective**: Connect the proven native transaction to the visible launcher,
preserve explicit user intent and sanitized recovery behavior, and build an
exact-source artifact without misrepresenting its authorization or combining
it with stale application source.

**Decision**: Expose a separate `Repair TLS and restart...` action after the
non-mutating plan. Show only the fixed provider/runtime/GPU/port/project/image
target and the bounded persistence/rollback statement. Require the exact typed
phrase `REPAIR TLS AND RESTART`, keep one package operation active at a time,
and publish only applying, restarting, succeeded, or recovery-required public
states. Keep `RepairCoordinator` fail-closed by default; the visible prototype
enables it only inside this explicit flow. Continue to exclude PowerShell,
`.cmd`, browser helpers, arbitrary arguments, raw output, and Windows trust
store changes.

**Execution**: Commit `0901cc5` wired the transaction into the Tkinter UI,
increased the default/minimum window height after the earlier display-scaling
observation, added transition callbacks and a public confirmation summary, and
updated the non-mutating plan wording. It also corrected validation manifests
and notices: native TLS mutation capability is now `true`, while package,
merge, release, managed-endpoint, and signature authorization remain false.

The clean commit built successfully with pinned PyInstaller 6.15.0 and Python
3.12.5. Structural inspection passed and build provenance recorded exact source
`0901cc5b8a2e5985e549f932833fd3d93c1f979b`. The launcher-policy package ZIP
sidecar, member inventory, every internal checksum, source ref, mutation
capability, and `execution_authorized=false` field passed direct archive
verification. Its executable opened and remained responsive against the
non-runnable sentinel. That sentinel lacks a release image identity, so repair
fails closed rather than targeting a container.

**Validation**: Forty-four launcher/build/package tests passed. The separated
runtime/readiness/config/container-publish selection passed 86 tests, for 130
passing targeted tests. Python compilation and `git diff --check` passed. A
combined test attempt again lost Windows access to its pytest temp root; both
separated reruns passed, so this remains an environment fixture issue rather
than a product-test failure. The initial extracted filesystem hash walk also
exceeded two minutes under endpoint scanning; direct read-only ZIP verification
completed with zero failures.

**Blocker**: A new full-runnable package cannot be generated locally from the
clean commit because the normal package generator is PowerShell and effective
policy blocks ordinary no-bypass script execution. No execution-policy bypass,
alternate shell path, older-source base, or endpoint exclusion was used. The
visible build therefore has safe UI/layout evidence and the native engine has
separate live Docker evidence, but the combined UI-driven full-package repair
has not yet run.

**Next**: Push the preserved commits to Draft PR #67. Generate the
full-runnable package from this exact commit in an approved environment after
GitHub Actions/build service recovery, then run UI-driven Google, Azure, and
controlled recovery validation. Configure an approved Podman Compose provider
separately before any Podman live repair. Keep signing and representative
managed-endpoint acceptance as later independent gates.

### 2026-08-06 - Native Docker Repair Transaction Passed Isolated Live Proof

**Objective**: Complete the bounded native repair engine, preserve rollback and
runtime data boundaries, exercise the product code against one isolated Docker
CPU package, and stop Podman before mutation when its Compose-provider boundary
is not satisfied.

**Context**: The mutation-disabled foundation had already proven exact target
binding and private Windows CA selection. The project lead authorized
continuation and confirmed Docker and Podman were running. Existing containers
and images were disposable if cleanup became necessary, but the implementation
continued to prohibit named-volume deletion. The validated port-5008
Task-087 package provided an isolated Docker target; no cleanup was required.

**Decision**: Implement the repair directly in Python with fixed
`docker`/`podman` argument arrays and `shell=False`; do not invoke PowerShell,
`.cmd`, a browser helper, or a hidden worker. Require one exact container by
Compose project/service labels and revalidate image, digest, runtime, GPU mode,
and `127.0.0.1` port binding. Stage and verify the combined CA bundle before an
atomic `.env` update. Restart only the same Compose project without a volume
flag. Roll back certificate files and `.env`, then force-recreate with the
restored environment after failure. For Podman, require one explicit approved
non-Docker-Desktop Compose provider and do not install one inside TLS repair.

**Execution**: Commits `27cc22d` and `3e77afd` added native certificate/bundle
backup and staging, exact-container inspection, provider TLS verification,
unrelated `.env`/line-ending preservation, same-profile restart, readiness and
digest checks, cleanup, rollback, and approved Podman-provider preflight. The
visible UI remains preview-only and `RepairCoordinator` still defaults to
`mutation_enabled=False`.

The current source adapter then ran one explicitly enabled Google/Docker
transaction against project `towerscout-task087-full-4327fb6`, port 5008. It
selected the CA privately, staged and verified the bundle, recreated only that
project's container, reverified provider TLS, and returned `succeeded`.
Independent post-checks recorded healthy `setup_required` readiness, matching
runtime/image digest, both CA environment settings, both certificate files, an
empty repair-staging area, and eight retained project named volumes. No
certificate identity, provider key, `.env` dump, raw subprocess output, or
local provider path was recorded.

Podman engine status remained reachable, but `podman compose version` failed
because the only discovered provider was Docker Desktop's bundled
`docker-compose.exe`, which TowerScout disallows for this path. No Podman
container, image, volume, provider installation, or TLS mutation followed.

**Validation**: Forty-two launcher tests passed, including exact-target,
ambiguous-container, `.env` preservation, provider-verification rollback,
restart rollback, volume-flag exclusion, missing Podman provider, rejected
Docker Desktop provider, and approved-provider cases. The combined launcher,
readiness/routes, config, and container-publish selection passed 129 tests with
repository-local pytest temp storage. Python compilation and `git diff
--check` passed. A first combined run produced 123 passes plus six Windows
user-Temp fixture permission errors; the repository-local rerun passed all
129. This is unsigned developer-source functional evidence, not packaged UI,
CI, signing, managed-endpoint, merge, RC, or release evidence.

**Next**: Add the visible review/confirm/progress/recovery UI around the
default-disabled coordinator, expand live proof to Azure and injected recovery,
then commit, rebuild, and validate an exact-source unsigned package. Configure
and validate an approved Podman provider separately before any Podman live
repair. Keep CI, signing, and representative managed-endpoint acceptance as
independent gates.

### 2026-08-06 - Native Repair Transaction Foundation Started

**Objective**: Begin the controlled-repair continuation with exact target
binding, private certificate selection, explicit transaction states, and a
fail-closed mutation boundary.

**Context**: The project lead confirmed Docker and Podman were running and
authorized starting the remaining prototype. A first direct adapter invoked
the existing Task-086 PowerShell script without `-ExecutionPolicy Bypass`.
Effective workstation policy blocked the script before it ran. This reproduced
the known deployment concern and proved that the visible launcher cannot depend
on `.ps1` or `.cmd` execution in its normal path. No bypass, hidden process,
policy change, or endpoint exclusion was attempted.

**Decision**: Keep Task-086 unchanged as the manual fallback and move the
launcher continuation to a native Python boundary. Bind repair transactions to
the exact package, provider, engine, GPU mode, port, Compose project, image, and
digest. Select the trusted CA from the host-verified TLS chain in memory, keep
certificate material out of representations and evidence, require the exact
confirmation phrase, and keep mutation disabled until native staging and
rollback are implemented and tested.

**Execution**: Added `launcher/towerscout_launcher/repair.py` with prepared,
confirmed, applying, restarting, succeeded, rejected, and recovery-required
states; native Google/Azure Windows certificate-chain selection; exact target
fingerprinting; sanitized errors; and fail-closed native apply/restart stubs.
Expanded launcher tests for runtime mismatch, private candidate handling,
ambiguous-chain rejection, confirmation, disabled mutation, recovery state,
and the absence of PowerShell, `.cmd`, helper, listener, and subprocess
execution in the repair module. The preview UI remains unchanged.

**Validation**: Launcher pytest increased from 29 to 36 tests and passed. Python
compilation passed. Sanitized live read-only classification selected one trusted
root for both Google and Azure without printing certificate identity. Docker
29.5.3 and Podman 5.8.2 were reachable; no container, image, or volume was
removed. `git diff --check` passed. Black, flake8, mypy, and Bandit modules were
not installed in the available Python 3.12/3.13 interpreters, so those checks
remain to be rerun in CI or the controlled validation environment.

**Next**: Implement the native fixed Docker/Podman staging transaction with
backup and rollback, then add restart/readiness/provider-verification tests.
Keep mutation disabled and do not run a live repair until that bounded slice
passes review and local validation.

### 2026-08-06 - Controlled Repair Pre-Implementation Checkpoint

**Objective**: Preserve the existing repository state and record the lessons,
non-regression boundaries, implementation order, and live-mutation prerequisites
before extending the validated preview-only launcher.

**Context**: The unsigned exact-source launcher proof passed, but Task-087 has
already exposed several failure patterns that must not be repeated: endpoint
protection blocked dormant helper imports in ordinary package paths, the older
browser/helper design created an unnecessary host trust boundary, Windows
subprocess behavior required an explicit creation-mode correction, and earlier
CI/template work demonstrated that self-referential tests can appear green
without exercising product code. The root worktree also contained uncommitted
planning and unrelated skill changes on a branch whose upstream was gone.

**Decision**: Preserve those root-worktree edits on the remote
`checkpoint/task-087-pre-implementation-20260806` branch, keep this prototype
branch isolated, and require the new
[`CONTROLLED-REPAIR-PRE-IMPLEMENTATION-CHECKPOINT-2026-08-06.md`](./TASK-087/CONTROLLED-REPAIR-PRE-IMPLEMENTATION-CHECKPOINT-2026-08-06.md)
rules before controlled-repair code or live mutation. Do not merge the
checkpoint branch wholesale; reconcile any useful documentation deliberately.

**Execution**: Recorded preservation commits `133686e` and `bfb4697`, the exact
prototype/source identities, twelve controlling lessons, the transactional
repair sequence, and a start checklist. No launcher source, runtime, container,
certificate, trust store, release asset, helper activation flag, PR #64, or
cdcai state changed.

**Validation**: Run the Task-087 documentation and repository-hygiene checks,
then commit this checkpoint independently from later prototype implementation.

**Next**: Implement the repair state machine, fixed Task-086 adapter boundary,
and negative tests without live mutation. Ask the project lead to confirm the
isolated runtime target before any Docker/Podman or trust-changing validation.

### 2026-08-06 - Reboot Persistence And Manual Non-Mutating Validation

**Objective**: Complete the remaining user-observed launcher and provider
sequence after a Windows reboot while keeping every TLS repair and mutation
gate closed.

**Context**: The exact-source `4327fb6` package had passed pristine
verification and fresh Docker CPU setup, but the user restarted Windows before
the repeated launcher refresh, preview, and provider-key observations could be
completed. The reboot created an additional opportunity to verify that the
same isolated runtime and persistent assets recover without repeating setup.
The historical `7a7aecc` AMSI and `31c41ec366c2` Docker-probe timeout results
remain unchanged in their original entries.

**Decision**: Reopen the exact packaged launcher against the already isolated
port-5008 project and record only sanitized UI outcomes. Treat the reboot and
manual sequence as unsigned development-workstation functional evidence, not
as a substitute for an organization-approved signed production-shaped build
under representative managed-endpoint policies. Do not run the suggested
Task-086 repair command during this proof.

**Execution**:

- After Windows restarted and Docker Desktop came up, Compose project
  `towerscout-task087-full-4327fb6` auto-resumed healthy on
  `127.0.0.1:5008`. Assets remained `ok` with zero missing and zero corrupt,
  CPU remained selected, and the exact pinned image digest
  `sha256:86c54bd723ff970f70f0883397a1f2f804db796507a461a5718aeab57258afe8`
  persisted.
- Reopened the exact packaged launcher. Docker reported running and reachable
  initially and after all three user-initiated Refresh clicks, resolving the
  repeated status-probe symptom seen in the historical `31c41ec366c2` run for
  this corrected build.
- Displayed the Google Maps/Docker TLS repair preview. It identified the exact
  package, Docker CPU profile, and port 5008, and correctly stated that it was
  preview-only: it did not inspect certificates, change trust, stop or restart
  the container, or run the dormant helper.
- The user entered the Google API key only in the browser Setup Wizard and
  reported the expected sanitized `tls_ca_untrusted` classification plus the
  Task-086 suggestion
  `.\scripts\repair-provider-tls.cmd -Provider google -Engine docker -Gpu off`.
  No provider key, raw provider response, or certificate detail was captured
  or recorded.
- At this host's display scaling, the launcher's normal window clipped its
  bottom controls; maximizing the window exposed them. Record this as a
  non-blocking UI follow-up before producing the signed build.

**Validation**: PASS for the bounded unsigned manual sequence: reboot recovery,
runtime persistence, three repeatable Docker status refreshes, preview-only
behavior, and sanitized provider-error classification all matched the intended
non-mutating contract. No certificate inspection by the preview operation,
trust change, TLS repair, launcher-initiated container stop/restart, helper
execution, or other launcher mutation was performed. Task-086 remains the
supported fallback. This result does not make the artifact an RC or release
and does not satisfy the signed representative managed-endpoint gate.

**Next**: Address or explicitly accept the non-blocking display-scaling issue,
then obtain an organization-approved signed production-shaped build and
validate it under the actual representative managed-endpoint policies with all
existing TLS-mutation gates off. Keep Draft PR #67 unmerged and make the
proceed/conditional/stop decision by August 14 only after that gate is
recorded.

### 2026-08-05 - Exact-Source Full-Package Fresh Docker Validation

**Objective**: Rebuild the helper-decoupled application and launcher as a
traceable full-runnable validation package, then exercise its pristine
first-run Docker CPU path without weakening endpoint policy or enabling TLS
mutation.

**Context**: Run 1 from exact source `7a7aecc` reached healthy
`setup_required` readiness and opened the unsigned launcher, but ordinary
setup/stop imported the dormant helper and AMSI blocked that script. The
helper-decoupled `31c41ec366c2` package subsequently reached the Setup Wizard
and reproduced the known Google Maps managed-network TLS validation result.
Its first launcher view showed the expected status and TLS repair preview, but
later reopen/refresh attempts repeatedly timed out during the Docker status
probe even while Docker was independently reachable. Those results remain
historical failed/partial runs; neither run performed TLS repair.

**Decision**: Correct the fixed Docker child-process probe for a windowed
Windows executable, bind the launcher build and package to exact source, and
repeat setup through a new Compose project and port. Keep the launcher
non-mutating, retain Task-086 as the supported repair fallback, and treat this
unsigned run only as functional evidence.

**Execution**:

- Committed the Windows status-probe and full-package stabilization as
  `18082cf`, then committed exact launcher build-provenance and atomic package
  controls as `4327fb6` (full source
  `4327fb6288f4f8c83202f548a2ba7cb2dcf9bab6`).
- Built and inspected the exact launcher. Its executable SHA-256 is
  `e1abd49b2c7e4e1c8de86aa4dd06bd8572520349ecea8fbaba6e75e52c10c868`;
  the complete launcher-tree SHA-256 is
  `fc4a150647822c950480dddc2f65bfc9ae5e1616c6513dd3b0532052e25b7380`.
- Assembled
  `towerscout-Task-087-validation-4327fb6288f4.zip`; its SHA-256 is
  `8c8e5a69c702836bf842d63c6407621e124a9cc2dae170ab46dbc9259ab7f673`.
  The package excludes dormant host-helper artifacts, keeps the Task-086
  repair scripts, and leaves all launcher TLS mutation closed.
- In a fresh download/extraction area, verified the control ZIP sidecar, the
  `1,012`-record internal checksum inventory, and the shared asset ZIP at
  SHA-256
  `00599cc4fe9f2bdb4708c669d7c3d9a8a570a0c3b547bc5c317026196c7bacbb`.
- Passed verify-only preflight, then created the isolated Docker Compose
  project `towerscout-task087-full-4327fb6` on port 5008. Setup created eight
  named volumes, imported and verified assets, started a healthy container,
  and reported `setup_required`, assets OK, one engine, CPU selected, and the
  exact pinned image digest
  `sha256:86c54bd723ff970f70f0883397a1f2f804db796507a461a5718aeab57258afe8`.
- Opened the exact packaged launcher for the remaining user-observed GUI
  checks. No trust repair, container repair/restart, provider-key capture, or
  other TLS mutation was performed.

**Validation**: Pristine sidecars and package inventory passed; verify-only and
fresh Docker CPU setup exited successfully. The focused launcher/release tests
passed 36 tests, and static quality checks passed. The broader selected run
passed 183 of 202 tests; its 19 failures were the already documented historical
dormant-helper direct-execution tests blocked by AMSI, with no bypass attempted.
This establishes a functioning helper-free application package and preserves
the earlier `7a7aecc` AMSI and `31c41ec366c2` timeout findings as history. It
does not establish signed managed-endpoint approval.

**Next**: Obtain the project lead's manual result for repeated launcher status
refreshes, the preview-only Google/Azure connection-repair view, and the
provider-key validation observation. If that bounded unsigned proof passes,
obtain an organization-approved signed production-shaped build and validate it
under representative managed-endpoint policies before any proceed decision,
merge, release candidate, or release.

### 2026-08-05 - Full-Package Endpoint Finding And Helper Decoupling

**Objective**: Exercise the validation launcher in a realistic end-user control
package, identify endpoint-policy failures, and remove the dormant helper from
ordinary release execution without weakening endpoint protections.

**Context**: The project lead authorized an unsigned functional test on the
development workstation. A full control package from exact source `7a7aecc`
was placed in a clean download/extraction area with a verified release asset
bundle, isolated Compose project, alternate port, and fresh named volumes.

**Decision**: Treat the AMSI block against the dormant PowerShell host helper
as a release-path defect, not as a reason to add exclusions or bypass endpoint
policy. Keep helper source and historical tests temporarily for review, but
remove it from ordinary launch/stop execution, `.env.example`, and the release
package, including its Compose activation variables. Preserve the Task-086
user-run TLS repair scripts.

**Execution**:

- Confirmed the application reached healthy `setup_required` readiness after
  verified asset import, with zero missing or corrupt assets.
- Confirmed the unsigned Tkinter launcher ran visibly, detected both engines,
  selected the intended Docker profile, and reported the expected first-run
  state without a Defender or Code Integrity block.
- Confirmed ordinary setup failed when `launch.ps1` dot-sourced
  `TowerScoutHostHelper.ps1`; `stop.ps1` contained the same unconditional
  dependency. No exclusion, execution-policy bypass, or endpoint-policy change
  was used.
- Removed host-helper imports and session/profile calls from normal launch and
  stop, removed helper artifacts from release assembly, removed the obsolete
  package `.env` review flag and Compose activation variables, and updated the
  package guide and tests.

**Validation**: PowerShell parse checks, both `.agent_work` validators, and
`git diff --check` pass. The bounded release, manifest, route, license,
container-publish, config, sanitization, bootstrap, runtime-hardening,
decoupling, and launcher selection passes all 158 tests. Exact-source
commit/build and the clean-install rerun remain pending.

**Next**: Complete bounded tests, commit the source checkpoint, rebuild the full
validation package, repeat clean extraction/setup without endpoint bypasses,
and pause at the visible Setup Wizard for project-lead provider-key entry.

### 2026-08-05 - Separate Validation-Package Process Added

**Objective**: Prevent the Task-087 launcher policy test from being confused
with, or assembled as, a normal TowerScout release package.

**Context**: The existing `scripts/package-release.ps1` creates the full
end-user control package and includes dormant Task-087 helper files. Reusing it
for this proof would widen the validation artifact beyond the authorized
non-mutating launcher slice.

**Decision**: Keep the release-package generator unchanged. Assemble the
Task-087 artifact through a separate exact-source process that contains only
the launcher build, a no-services package-discovery sentinel, non-secret
identity defaults, validation/source manifests, notices, and hashes. Exclude
the application stack, launch/runtime scripts, repair helpers, live `.env`,
provider keys, certificates, and model/data assets.

**Execution**:

- Added `launcher/package_validation.py` with a clean-worktree requirement,
  full-commit source identity, bounded validation name, launcher static
  inspection, Tcl/Tk license check, forbidden-file scan, per-file hashes, ZIP,
  and ZIP SHA-256 sidecar.
- Added focused tests for source traceability, closed authorization flags,
  absent control/helper content, and complete checksum coverage.
- Documented that the resulting artifact is not an RC, release, merge signal,
  or unsigned managed-endpoint executable.

**Validation**: The focused launcher suite passes all 16 tests, launcher and
assembler compilation passes, and `git diff --check` passes. The actual ZIP is
intentionally built only after these changes become a clean, immutable PR
source checkpoint; its generated manifest and PR evidence record that result
without changing the source commit afterward.

**Next**: Commit and push the assembler checkpoint, build and statically
inspect the validation-only artifact from that exact clean commit, then record
its sanitized identity and hashes on Draft PR #67. Do not execute or publish
the unsigned artifact.

### 2026-08-05 - Draft PR Repository Checkpoint Published

**Objective**: Establish an immutable, reviewable source identity before
building the validation-only launcher artifact.

**Context**: Documentation was reconciled and the isolated branch passed its
bounded validation. The project lead authorized the recommended repository
checkpoint while keeping every merge, release, mutation, and cdcai gate closed.

**Decision**: Publish the four intentional Task-087 commits to the existing
short-lived feature branch and open a Draft PR against `main`. Treat the final
PR head after this status-only follow-up as the source identity for the
validation-only build.

**Execution**:

- Pushed `feature/task-087-windows-launcher-prototype` to the fork.
- Opened Draft PR #67, `feat(task-087): add validation-only Windows launcher
  proof`, against `main`.
- Kept PR #64 open and on hold; no tag, GitHub Release, merge, cdcai change,
  executable publication, or runtime mutation occurred.

**Validation**: GitHub reports PR #67 open as a Draft against `main`. Required
CI and the Task-087 production-controller workflow started at the initial PR
head; their final result remains pending at this checkpoint.

**Next**: Push this status-only documentation commit, use the resulting final
PR head as the exact source for `Task-087-validation-<short-SHA>`, and keep the
PR unmerged through signing and representative managed-endpoint validation.

### 2026-08-05 - Validation-Only Repository Checkpoint Prepared

**Objective**: Make the launcher experiment reversible at the GitHub boundary
and remove task-document ambiguity before creating or executing a validation
package.

**Context**: The preview-only launcher and static package proof were ready, but
the controlling documentation did not yet define validation-artifact identity
or failed-experiment branch handling. Primary agent guidance still described
Task-087 as awaiting implementation restart, two active status notes still requested approval
after ADR-018 had accepted the pivot, and the historical helper proof could be
confused with the unmerged launcher proof.

**Decision**: Keep launcher code off `main` until the signed managed-endpoint
gate passes. Publish a Draft PR, build only
`Task-087-validation-<short-SHA>` from its exact commit, and create no tag,
GitHub Release, candidate identity, or cdcai change. If validation stops, close
the code PR unmerged and record the final decision from a clean docs-only
branch based on current `main`.

**Execution**:

- Aligned the primary agent guide, current task tracker, backlog, requirements,
  design, roadmap, handoff navigation, ADR-018, Task-087, completion history,
  and review evidence with the validation-only boundary.
- Clarified that the merged proof is the dormant-helper Gate 3 proof and that
  the Python/Tkinter launcher remains isolated and unmerged.
- Marked the earlier helper plan as historical and archived both superseded
  August 4 review requests under `context/archive/2026-08/` with repaired links.
- Removed two unrelated broken leadership-snapshot links from this isolated
  branch only; the separate dirty primary worktree was not changed.

**Validation**: The quick hygiene check, canonical agent-work validator,
`git diff --check`, authoritative semantic-staleness scan, and changed-document
relative-link check passed. The focused launcher suite passed all 14 tests, the
current license/manifest/package/publish selection passed all 14 tests, and
launcher compilation passed. Black, flake8, mypy, and Bandit were not rerun in
this repository checkpoint because neither installed Python interpreter
currently exposes those optional tools; their prior passing review results are
preserved below, and launcher source did not change during this documentation
reconciliation.

**Next**: Create intentional documentation, implementation, test, and evidence
commits; push the isolated branch; open a Draft PR against `main`; then use its
exact final commit as the validation-only package source identity.

### 2026-08-05 - Review-Ready Polish And Evidence Audit

**Objective**: Prepare the non-mutating launcher slice for technical review
without committing, publishing, signing unofficially, or widening the approved
security boundary.

**Context**: The first implementation and static package proof passed, but the
branch still needed a complete diff review, formatter cleanup, dependency and
license inventory, exact-source rebuild, and a compact reviewer handoff.

**Decision**: Keep the synchronous, visible, preview-only architecture. Apply
mechanical Black formatting, explicitly disable environment proxies for the
fixed loopback readiness read, pin the complete observed PyInstaller build
toolchain, and record prototype provenance without treating it as a release
SBOM or legal approval. Do not refactor advisory complexity during the
time-boxed proof unless review identifies it as blocking.

**Execution**:

- Reviewed the complete isolated-branch source, test, packaging, and planning
  change set against verified `origin/main` at `4b93caf` and the approved
  August 5 pivot. No unrelated workspace change was imported beyond the
  authorized Task-087 planning set.
- Ran Black 25.12.0 mechanically under installed Python 3.13 because Black
  intentionally refuses the host's Python 3.12.5 AST-safety check. No behavior
  change was introduced by formatting.
- Changed the readiness opener to use an empty proxy map plus redirect
  rejection so the fixed `127.0.0.1` request cannot inherit environment proxy
  routing. Added assertions for both controls.
- Pinned PyInstaller and all observed transitive build dependencies and added
  `launcher/DEPENDENCY-PROVENANCE.md` with build/runtime inventory and explicit
  SBOM, notice, signing, and legal-review gates.
- Added the task-local reviewer packet under
  `.agent_work/tasks/active/TASK-087/REVIEW-EVIDENCE-2026-08-05.md`.

**Validation**:

- PASS: 14 focused launcher tests.
- PASS: all 9 existing compliance/manifest/publish tests. Eight passed in the
  managed sandbox; the one pytest `tmp_path` case passed unchanged outside the
  sandbox after the sandbox denied temporary-directory enumeration.
- PASS: Black check for all launcher and focused-test Python files, Python
  compilation, blocking flake8 syntax/undefined-name gate, mypy for seven
  source files, Bandit, exact build-pin comparison, agent-work validation, and
  `git diff --check`.
- ADVISORY: the CI-profile flake8 review retains three C901 complexity warnings
  in discovery functions plus Black's expected E203 slice-spacing conflict.
  These are visible prototype maintainability debt, not merge-blocking findings.
- PASS: exact-source PyInstaller rebuild and static package inspection. The
  output is a 943-file / 26,426,570-byte Windows AMD64 GUI package with four
  launcher modules, UPX absent, the generated Tcl/Tk license present, no
  prohibited script/secret filename, and Authenticode status `NotSigned`.
- NOT RUN: unsigned executable launch, GUI smoke, helper self-test, provider
  TLS/certificate work, Stop/restart, trust mutation, or managed-endpoint test.

**Review Finding**: No blocking functional or source-security defect was found
within the approved non-mutating boundary. Distribution remains blocked on an
approved signing owner/path, file-level SBOM and hashes, final third-party
notice integration, legal/owner review, and signed representative endpoint
validation.

**Next**: Obtain technical/security review of the task-local packet. If the
slice is accepted, create intentional commit checkpoints and publish a review
branch only with project-lead authorization; do not begin Task-096 Stop or TLS
mutation under this review-ready checkpoint.

### 2026-08-05 - Non-Mutating Windows Launcher Slice Implemented

**Objective**: Implement the first visible, release-shaped Task-087 launcher
slice without enabling helper activation, host mutation, trust changes, or
unsigned managed-endpoint execution.

**Context**: ADR-018 authorized a time-boxed launcher feasibility proof from
the merged dormant-helper baseline. The working workspace contained unrelated
user changes, so implementation required an isolated branch from verified
`origin/main` at `4b93caf` plus a faithful port of the August 5 Task-087
planning set.

**Decision**: Use Python 3.12/Tkinter with PyInstaller 6.15.0 in a windowed
one-directory package with UPX disabled. The host has the maintained
Python/pytest/Tkinter path but no .NET SDK. The launcher uses only synchronous,
fixed Docker/Podman read-only probes, a bounded loopback readiness read, a
package-scoped Windows session mutex, and an in-process operation guard. It
accepts no
command text or executable path and invokes no PowerShell, shell, dormant
helper, listener, detached worker, or mutation path.

**Execution**:

- Added the visible Tkinter application, package/runtime discovery, sanitized
  public state models, single-instance/duplicate-operation coordination, and
  Google/Azure TLS repair preview.
- Added a pinned PyInstaller build input, windowed one-directory spec, CMD
  build entry point, static PE/package inspector, technology/security/signing
  notes, and focused tests.
- Built the package in an isolated build environment. Static inspection
  confirmed a Windows AMD64 GUI executable, UPX absent, all four launcher
  modules bundled, 943 packaged files / 26,426,570 bytes, and no packaged
  helper, PowerShell/CMD/BAT, environment, key, or certificate files.
- Performed sanitized read-only host discovery after the project lead
  confirmed both engines were running. Docker and Podman were both reachable.
  The source prototype has no configured engine, so explicit fixed-enum engine
  selection is required; no TowerScout instance was reachable at its default
  package port.
- Did not inspect or copy source from the external Windows helpers repository;
  reuse/license/provenance approval therefore remains a future gate if reuse
  is proposed.

**Validation**:

- PASS: Python compilation for launcher source and build inspector.
- PASS: 14 focused pytest cases covering allowlisted package fields, fixed
  runtime commands, raw-output redaction, malformed success output, package
  identity mismatch, exact-engine selection, preview behavior, duplicate
  operation/process blocking, readiness sanitization, package inspection, and
  forbidden mutation/shell/helper source contracts.
- PASS: blocking flake8 syntax/undefined-name gate (zero findings).
- PASS: mypy for seven launcher/build-inspection source files.
- PASS: Bandit for launcher/build-inspection source after documenting the two
  fixed, shell-free subprocess allowlist boundaries.
- PASS: PyInstaller build and package inspection; no missing launcher import,
  no forbidden packaged filename, AMD64 GUI subsystem confirmed, and UPX marker
  absent.
- PASS: sanitized live read-only Docker/Podman detection with both engines
  reachable; the first sandboxed check was correctly classified as runtime
  isolation and repeated outside that boundary with suppressed raw output.
- NOT RUN: Black, because the installed formatter refuses Python 3.12.5 due
  its upstream AST-safety guard. Flake8, compilation, tests, and mypy passed.
- NOT RUN: unsigned executable launch, GUI smoke, managed-endpoint policy
  validation, provider TLS connectivity, certificate discovery, helper
  self-test, TLS mutation, Stop, restart, or trust-store validation.

**Signing/Deployment State**: The built executable reports `NotSigned` and was
not executed. The required signer is the organization-approved Windows
Artifact Signing or equivalent service. The signing owner/custodian remains
unresolved. At minimum `TowerScoutLauncher.exe` must be signed and timestamped;
the approved owner must define policy for bundled third-party DLL/PYD
verification or re-signing. A controlled Windows build, dependency/hash
provenance, malware/policy scan, signing integration, post-signature
verification, checksums, manifest/SBOM integration, and representative managed
endpoint validation remain required before candidate inclusion.

**Boundary Confirmation**: No listener, browser-issued host operation,
dormant-helper import/start/self-test, hidden worker, PowerShell child,
execution-policy bypass, runtime/container mutation, TLS/certificate action,
Windows trust-store change, administrator action, provider key handling,
release publication, cdcai change, PR #64 action, or `v0.1.2` asset change
occurred.

**Recommendation**: CONTINUE WITH CONDITIONS. Review the non-mutating slice
and resolve signing/deployment ownership. Do not merge, ship, execute the
unsigned artifact on the managed endpoint, or implement Stop/TLS mutation
until this slice and its tests are reviewed. If approved, Task-096 Stop remains
the preferred first separately authorized mutation.

**Next**: Run canonical repository/task hygiene, obtain reviewer feedback on
the source/package proof, and coordinate an organization-approved signed build
for representative managed-endpoint testing before the August 14 disposition.

### 2026-08-05 - Reversible Windows Launcher Prototype Authorized

**Objective**: Authorize a small, reversible implementation checkpoint that
tests the proposed visible launcher pathway without treating an unsigned
functional prototype as release validation.

**Context**: The dormant Task-087 PowerShell helper and its browser-to-loopback
control plane raised Defender/AMSI and supportability concerns. Architecture
review favored a visible launcher that owns fixed TowerScout operations without
an extra listener, browser authority, hidden worker, or execution-policy
bypass. The project lead approved building the prototype now, retaining the
Task-086 manual fallback, and deciding whether to continue by August 14.

**Decision**: Apply the August 5 override and ADR-018. Keep PR #64 and all
activation gates on hold, build only on a reversible prototype path, and run
signing/deployment coordination in parallel. Candidate inclusion remains
blocked until the production-shaped signed artifact passes representative
managed-endpoint validation.

**Execution**: Updated the current sprint, backlog dependency, requirements,
technical design, canonical roadmap, and Task-087 record. No launcher code,
runtime, browser, container, certificate store, Defender setting, release
asset, or external repository was changed.

**Validation**: Both the quick agent-work hygiene check and canonical
`.agent_work` validator passed. `git diff --check` also passed.

**Next**: Start a new prototype session from the dated override and ADR-018,
select one maintainable implementation technology, and build the non-mutating
visible launcher slice before requesting any managed-endpoint execution.

### 2026-07-06 - Gate 3 Browser Start Contract Defined

**Objective**: Define the non-mutating browser-to-helper start contract before
any live Setup Wizard helper request is enabled.

**Context**: Reviewer feedback accepted the `12de100` authorization-edge slice
and recommended one more Gate 3 checkpoint before wiring a live helper call:
prove the browser contract sends only provider enum, fixed confirmation, and a
scoped operation authorization; prove duplicate/reload/active-operation states
do not launch another repair; and keep token/runtime/control fields redacted.

**Decision**: Keep `PROVIDER_TLS_REPAIR_BROWSER_MUTATION_ENABLED = false` and
do not add any live `fetch` path for provider TLS repair. Add a sanitized
start-contract preview and active-operation status memory so tests can prove
the allowed request shape and operation-busy behavior without mutating host
state. Keep helper-owned runtime values such as engine, GPU mode, port,
restart mode, script path, Podman provider fields, and durable helper tokens
out of the allowed browser request body.

**Execution**: Added Setup Wizard helpers for `POST
/operations/provider-tls-repair` contract inspection, sanitized
operation-status retention, active-operation blocking, and token-redacted
public operation summaries. Extended frontend contract tests for helper
unavailable states, expired/malformed authorization, duplicate clicks while the
mutation gate is closed, active `operation_busy` status after a simulated
reload/status restore, DOM/notification/console redaction, and forbidden
runtime/control fields. Rebuilt the generated frontend bundle.

**Validation**:

- PASS: `node tests\frontend\test_setup_wizard_validation_contract.js`
- PASS: `node tests\frontend\test_global_contract.js`
- PASS: `node tests\frontend\test_debug_logging_contract.js`
- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_frontend_provider_tls.py tests\unit\test_config.py tests\unit\test_provider_http.py -q -p no:cacheprovider`
- PASS:
  `python .agents\skills\towerscout-frontend-bundle-guard\scripts\check_bundle_source_consistency.py .`
- PASS: `python .agent_work\scripts\validate_agent_work.py`
- PASS:
  `python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`
- PASS: `git diff --check`

**Next**: Push this start-contract checkpoint to PR #46 for reviewer feedback
before enabling any browser-triggered helper mutation.

### 2026-07-06 - Gate 3 Repair UI Authorization Gate Added

**Objective**: Add the next Gate 3 Setup Wizard repair UI contract without
enabling browser-triggered host mutation.

**Context**: Reviewer feedback accepted the PR #46 process-tree cleanup
hardening and recommended proceeding to the next visible repair UI /
host-mutation design slice, while keeping `provider_tls_repair=true`, default
browser-triggered repair, Podman remediation, and tester-facing package
inclusion blocked.

**Decision**: Render a Setup Wizard TLS repair review panel only when the
retained provider validation failure is a repairable TLS trust category and
helper availability is explicitly true. Keep the repair button disabled unless
a future short-lived operation authorization is present and the explicit browser
mutation gate is opened. Redact operation tokens from public validation-state
accessors and rendered DOM text.

**Execution**: Added the Setup Wizard repair view-model, confirmation checkbox,
disabled repair button, command fallback text, and browser-mutation gate. Added
contract tests proving invalid keys, unauthorized/quota/provider HTTP failures,
generic network failures, helper-unavailable TLS failures, unsupported runtime,
and Podman provider states do not render the host repair action. Added a
short-lived authorization test proving the token is not exposed through the
public state accessor or DOM text and no helper operation request is made while
the browser-mutation gate is closed. Rebuilt the generated frontend bundle.

**Validation**:

- PASS: `node tests\frontend\test_setup_wizard_validation_contract.js`
- PASS: `node tests\frontend\test_global_contract.js`
- PASS: `node tests\frontend\test_debug_logging_contract.js`
- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_frontend_provider_tls.py tests\unit\test_config.py tests\unit\test_provider_http.py -q -p no:cacheprovider`
- PASS:
  `python .agents\skills\towerscout-frontend-bundle-guard\scripts\check_bundle_source_consistency.py .`

**Next**: Run final `.agent_work` and diff hygiene checks, then push this
gated UI/authorization slice to PR #46 for reviewer feedback before adding any
real browser-to-helper operation start.

### 2026-07-06 - Gate 3 Review Wording And Authorization Edges

**Objective**: Incorporate reviewer feedback on the gated Setup Wizard repair
panel before continuing toward a real browser-to-helper operation start.

**Context**: Reviewer feedback accepted the `1a304d8` gated UI/authorization
slice and confirmed it is acceptable to continue Gate 3 proof work. The review
called out one wording correction: the branch now contains a visible disabled
repair panel/button, so PR/task wording should describe "no enabled/actionable
repair button" rather than "no visible repair button." The review also named
expired and malformed operation authorization handling as coverage needed
before real mutation.

**Decision**: Keep the current branch non-mutating. Treat the visible panel as a
disabled review/fallback panel only, with no actionable repair button, no
browser-triggered helper start, no `provider_tls_repair=true` capability flip,
no Podman remediation, and no tester-facing package inclusion.

**Execution**: Clarified the Gate 3 wording in this task log and extended the
Setup Wizard contract tests for expired, malformed, wrong-type, and missing
token operation authorization inputs. These inputs must leave the panel
disabled, report authorization unavailable, avoid helper operation requests, and
keep operation tokens out of public/DOM surfaces.

**Validation**:

- PASS: `node tests\frontend\test_setup_wizard_validation_contract.js`
- PASS: `node tests\frontend\test_global_contract.js`
- PASS: `node tests\frontend\test_debug_logging_contract.js`
- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_frontend_provider_tls.py tests\unit\test_config.py tests\unit\test_provider_http.py -q -p no:cacheprovider`
- PASS:
  `python .agents\skills\towerscout-frontend-bundle-guard\scripts\check_bundle_source_consistency.py .`
- PASS: `python .agent_work\scripts\validate_agent_work.py`

**Next**: Push the wording and authorization-edge coverage to PR #46, then ask
the Reviewer whether the branch is ready for the next focused start-contract
design checkpoint.

### 2026-07-06 - PR #46 Process-Tree Cleanup Path Hardened

**Objective**: Address the reviewer follow-up that the timeout cleanup path
should not resolve `taskkill.exe` through `PATH`.

**Context**: The PR #45 bot follow-up added process-tree cleanup for controlled
wrapper timeouts. Reviewer feedback on PR #46 correctly noted that invoking
`taskkill.exe` by name leaves the helper dependent on `PATH` resolution during
the cleanup path.

**Decision**: Resolve the Windows system `taskkill.exe` from
`[System.Environment]::SystemDirectory` before use, mirroring the fixed-system
`cmd.exe` resolution already used for wrapper execution. Keep product UI
exposure, `provider_tls_repair=true`, browser-triggered host mutation, Podman
remediation, and tester-facing package inclusion blocked.

**Execution**: Added a fixed-path `taskkill.exe` resolver to
`scripts\lib\TowerScoutHostHelper.ps1` and updated timeout process-tree cleanup
to call that resolved executable. Extended the Task-087 static contract test to
assert the resolver is present and direct `PATH`-based `taskkill.exe`
invocation is absent.

**Validation**:

- PASS: PowerShell parser checks for `scripts\lib\TowerScoutHostHelper.ps1`
  and `scripts\host-helper.ps1`
- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_task_087_host_helper.py -q -p no:cacheprovider`
- PASS:
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\host-helper.ps1 -SelfTest`

**Next**: Run full hygiene checks, push the hardening update to PR #46, then
request reviewer confirmation before visible host mutation/UI work.

### 2026-07-06 - PR #45 Bot Follow-Up Hardening

**Objective**: Address post-merge bot findings from PR #45 before requesting
review of the Gate 3 product-integration branch.

**Context**: The bot identified three P2 helper-control issues in the merged
Gate 1 / Gate 2 implementation: wrapper timeouts killed only the `cmd.exe`
parent process, the helper start-step timeout matched the launcher's readiness
timeout without headroom, and synthetic public states such as `operation_busy`
or `operation_expired` could inherit stale classification / terminal /
next-action values from the stored operation lock.

**Decision**: Treat these as helper safety fixes that should land before the
Reviewer evaluates Gate 3 product integration. Keep product UI exposure,
`provider_tls_repair=true`, browser-triggered host mutation, Podman remediation,
and tester-facing package inclusion blocked.

**Execution**: Added process-tree timeout cleanup for controlled wrapper
execution, using Windows `taskkill.exe /T /F` and a cleanup wait before bounded
stdout/stderr draining. Added 60 seconds of helper headroom over the launcher's
180-second readiness timeout, so `start.bat` can return its own exit code 2 and
map to `readiness_timeout`. Updated public operation-status conversion so
synthetic override states recompute classification, terminal, and next action
from the override state policy instead of copying stale lock values.

**Validation**:

- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_task_087_host_helper.py -q -p no:cacheprovider`
- PASS: PowerShell parser checks for `scripts\lib\TowerScoutHostHelper.ps1`
  and `scripts\host-helper.ps1`
- PASS:
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\host-helper.ps1 -SelfTest`
- PASS: `node tests\frontend\test_setup_wizard_validation_contract.js`
- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_config.py tests\unit\test_frontend_provider_tls.py tests\unit\test_provider_http.py tests\unit\test_flask_routes.py -q -p no:cacheprovider`
- PASS: `node tests\frontend\test_global_contract.js`
- PASS: `node tests\frontend\test_debug_logging_contract.js`
- PASS:
  `python .agents\skills\towerscout-frontend-bundle-guard\scripts\check_bundle_source_consistency.py .`
- PASS: `python .agent_work\scripts\validate_agent_work.py`
- PASS:
  `python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`
- PASS: `git diff --check`

**Next**: Ask the Reviewer to review both the bot-follow-up helper hardening
and the Gate 3 state-retention slice before adding visible repair UI.

### 2026-07-06 - Gate 3 Product Integration Proof Started

**Objective**: Start product integration proof without enabling a browser-side
host repair action.

**Context**: PR #45 merged the Gate 1 / Gate 2 helper transport, security, and
internal Docker CPU/off live-wrapper proof. The reviewer accepted that as the
helper proof baseline, but product UI exposure, `provider_tls_repair=true`,
Podman remediation, browser-triggered default mutation, and tester-facing
package inclusion remained blocked.

**Decision**: Make the first Gate 3 slice non-mutating and test-led. Preserve
structured provider validation details end-to-end and keep helper availability
reported as unavailable until a later slice wires an approved helper
availability check and repair-button renderer. Do not render a repair button
or call the host helper from the browser in this slice.

**Execution**: Added provider validation metadata for `repairable` and
`helper_available`, with repairable limited to the existing TLS repair
categories and helper availability defaulting to `false`. Updated Setup Wizard
to retain the last structured validation result and failure per provider,
including `provider`, `category`, `repairable`, `support_action`,
`repair_command`, and `helper_available`. Added a repair-display predicate that
requires both a repairable TLS failure and helper availability, but did not add
visible UI or a mutating operation call. Rebuilt the generated frontend bundle.

**Validation**:

- PASS: `node tests\frontend\test_setup_wizard_validation_contract.js`
- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_config.py tests\unit\test_frontend_provider_tls.py tests\unit\test_provider_http.py tests\unit\test_flask_routes.py -q -p no:cacheprovider`
- PASS: `node tests\frontend\test_global_contract.js`
- PASS: `node tests\frontend\test_debug_logging_contract.js`
- PASS:
  `python .agents\skills\towerscout-frontend-bundle-guard\scripts\check_bundle_source_consistency.py .`
- PASS: `python .agent_work\scripts\validate_agent_work.py`
- PASS:
  `python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`
- PASS: `git diff --check`

**Next**: Request reviewer feedback on whether this Gate 3 state-retention
contract is sufficient before adding a visible helper-unavailable fallback or
repair-button renderer.

### 2026-07-06 - Patched Live Wrapper Rerun Passed

**Objective**: Rerun the approved internal Docker CPU/off provider TLS repair
validation against patched PR head `c55814b`.

**Context**: The previous live run was `PARTIAL` because ordinary stop cleanup
cleared helper operation metadata before the controlled runner could persist
stop status and continue to start. The `7177cc1` fix preserved ordinary stop
cleanup while allowing helper-controlled stop to defer session invalidation.
The source-checkout Docker image prerequisite was prepared before rerun.

**Decision**: Execute the internal helper-controlled repair, stop, start
sequence only after fresh release-owner approval. Keep product UI,
`provider_tls_repair=true`, browser-triggered default mutation, Podman
remediation, and tester-facing packaging blocked.

**Execution**: Ran the approved internal live Docker CPU/off validation for
`google` on port `5000`. The helper-controlled operation returned terminal
state `ready`, current step `start`, and classification `terminal_success`.
Post-run checks confirmed the app was reachable on port `5000` and the Docker
service was running / healthy with `towerscout:local`.

**Validation**:

- PASS: helper-controlled operation returned `ready`.
- PASS: readiness returned on port `5000`.
- PASS: Docker service state was running / healthy.
- PASS: no fallback command was needed.
- PASS: sanitized evidence recorded in
  `.agent_work/tasks/active/TASK-087/live-wrapper-validation-2026-07-06.md`.

**Next**: Ask the reviewer to assess the patched live-run evidence before
starting any Gate 3 product integration design or user-facing enablement.

### 2026-07-06 - Docker Rerun Prerequisite Prepared

**Objective**: Prepare the Docker runtime prerequisite needed before requesting
a patched Task-087 live-wrapper rerun.

**Context**: Reviewer feedback accepted the `7177cc1` stop-cleanup fix for
internal rerun, but called out that the previous fallback start could not prove
readiness because the source-checkout runtime expected `towerscout:local` and
that image was not available.

**Decision**: Prepare the local source-checkout image without rerunning the
mutating helper validation. Keep product UI, `provider_tls_repair=true`,
browser-triggered default mutation, Podman remediation, and tester-facing
packaging blocked.

**Execution**: Performed targeted Docker cleanup through the package stop path,
confirmed the source checkout resolves to `towerscout:local`, built the local
Docker image, and confirmed this checkout's Compose project remained stopped /
clear afterward. No broad Docker prune or unrelated image/container cleanup was
performed.

**Validation**:

- PASS: `docker image inspect towerscout:local`
- PASS: `docker compose -f compose.yaml config --images`
- PASS: `docker compose -f compose.yaml ps --all`
- PASS: `git status --short --branch`

**Next**: Request fresh explicit approval before rerunning the mutating Docker
CPU/off live validation against patched head `7177cc1`.

### 2026-07-06 - Live Wrapper Partial Run And Stop Cleanup Fix

**Objective**: Run the approved internal Docker CPU/off live-wrapper validation
and close the helper-controlled stop cleanup gap it exposed.

**Context**: The release owner approved the internal `google` provider
validation on port `5000`, including `repair-provider-tls.cmd -Apply`,
`stop.cmd`, and `start.bat`. Product UI exposure, `provider_tls_repair=true`,
browser-triggered default mutation, Podman remediation, and tester-facing
packaging remained blocked.

**Decision**: Treat the run as `PARTIAL` rather than retrying automatically.
The controlled runner reached the stop step, but normal stop cleanup cleared
the active helper session metadata before the helper could persist the stop
result and continue to the start step. Preserve ordinary user/support stop
cleanup, but mark helper-controlled stop subprocesses so `stop.ps1` defers
session invalidation only for the active controlled operation.

**Execution**: Updated `scripts\stop.ps1` to skip helper-session invalidation
only when `TOWERSCOUT_HOST_HELPER_CONTROLLED_OPERATION=1` is present. Updated
the controlled command resolver/process runner to attach that fixed environment
marker only to the allowlisted stop wrapper. Added focused unit coverage that
asserts the marker reaches the controlled stop wrapper and that normal stop
cleanup remains present. Updated
`.agent_work/tasks/active/TASK-087/live-wrapper-validation-2026-07-06.md` with
the sanitized partial-run outcome.

**Validation**:

- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_task_087_host_helper.py -q -p no:cacheprovider`
- PASS: PowerShell parser checks for `scripts\stop.ps1` and
  `scripts\lib\TowerScoutHostHelper.ps1`
- PASS: `python .agent_work\scripts\validate_agent_work.py`
- PASS:
  `python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`
- PASS: `git diff --check`

**Next**: Commit and push the fix, then ask for fresh explicit approval before
rerunning the mutating Docker CPU/off live validation against the patched
branch.

### 2026-07-06 - Live Wrapper Evidence Note Prepared

**Objective**: Prepare the run-specific evidence note requested before the
first internal live-wrapper validation window.

**Context**: The reviewer cleared `0132b13` for internal Docker CPU/off
live-wrapper validation only, while keeping product UI,
`provider_tls_repair=true`, browser-triggered default mutation, Podman
remediation, and tester-facing guided repair packaging blocked.

**Decision**: Create a task-local proof note under the owning Task-087 support
folder rather than recording run-specific evidence in `.agent_work/context/`.
Keep the note support-safe and concrete enough to use before execution.

**Execution**: Added
`.agent_work/tasks/active/TASK-087/live-wrapper-validation-2026-07-06.md` with
planned PR head, Docker CPU/off runtime profile, provider, port, wrapper
sequence, timeout budget, fallback commands, pre-run checklist, sanitized
evidence fields, abort conditions, and post-run gate.

**Validation**:

- PASS: `python .agent_work\scripts\validate_agent_work.py`
- PASS:
  `python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`
- PASS: `git diff --check`

**Next**: Request explicit approval before running any live command that repairs
TLS trust or stops/restarts the Docker runtime.

### 2026-07-02 - Internal Live Wrapper Validation Runbook Added

**Objective**: Incorporate the reviewer's `e0bb8b5` feedback before running any
live repair/stop/start sequence.

**Context**: The reviewer accepted the non-mutating real-wrapper contract proof
as sufficient to proceed to explicit internal live-wrapper validation. They did
not identify a code blocker, but required a short validation runbook before
running the mutating sequence.

**Decision**: Add the runbook as a tracked Task-087 gate before live execution.
Keep product UI exposure, `provider_tls_repair=true`, browser-triggered default
mutation, Podman remediation, and tester-facing guided repair packaging blocked
until live evidence is reviewed.

**Execution**: Added an internal live wrapper validation runbook covering the
selected Docker profile, provider, app port, expected repair/stop/start
sequence, timeout budget, rollback/manual fallback commands, pre-run checks,
sanitized evidence fields, abort conditions, and post-run review requirements.

**Validation**:

- PASS: `python .agent_work\scripts\validate_agent_work.py`
- PASS:
  `python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`
- PASS: `git diff --check`
- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_task_087_host_helper.py -q -p no:cacheprovider`

**Next**: Commit and push the runbook checkpoint, then schedule the internal
live Docker validation window before any Gate 3 product integration work.

### 2026-07-02 - Non-Mutating Real Wrapper Contract Proof Added

**Objective**: Continue from the reviewer recommendation toward internal
real-wrapper validation without running the mutating repair/stop/start sequence
by default.

**Context**: The reviewer accepted the controlled runner for internal
validation, with user-facing enablement still blocked. The prior
pre-default-mutation follow-ups were addressed in `186224d`. The remaining
milestone is real-wrapper validation, but the real sequence includes
`repair-provider-tls.cmd -Apply`, `stop.cmd`, and `start.bat`, so live execution
must be handled as a deliberate validation window rather than an incidental
unit-test side effect.

**Decision**: Add a non-mutating real-wrapper contract proof first. The proof
resolves the actual package-local wrappers from the current checkout, validates
the fixed command contract, and returns only support-safe metadata with
`executed=false`. Product UI exposure, `provider_tls_repair=true`, default
browser-triggered mutation, live repair execution, and Podman remediation remain
blocked.

**Execution**:

- Added `Test-TowerScoutHostHelperRealWrapperContract` to resolve the real
  Docker first-slice wrappers and validate fixed step order, argument counts,
  timeouts, `cmd.exe`, fixed interpreter flags, and working directory without
  executing any wrapper.
- Added a sanitized self-test scenario,
  `provider_tls_repair_real_wrapper_contract`, that reports
  `real_wrapper_contract_validated` and `executed=false` without command paths,
  wrapper names, helper tokens, local paths, certificate details, or raw output.
- Added focused pytest coverage proving the contract result is non-mutating,
  Docker/off/port-specific, ordered as repair/stop/start, and support-safe.

**Gate**: Gate 2 controlled-runner to internal real-wrapper validation handoff,
still pre-product-UI and pre-default-mutation.

**Result**: PASS for the non-mutating real-wrapper contract proof. Actual
wrapper execution remains pending explicit internal validation with the selected
Docker package/runtime state.

**Validation**:

- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_task_087_host_helper.py -q -p no:cacheprovider`
- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_config.py tests\unit\test_error_sanitization.py -q -p no:cacheprovider`
- PASS:
  `python .agents\skills\towerscout-secret-and-provider-key-safety\scripts\scan_for_sensitive_terms.py scripts\lib`
- PASS: `python .agent_work\scripts\validate_agent_work.py`
- PASS:
  `python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`
- PASS: `git diff --check`

**Next**: Request reviewer feedback on the non-mutating real-wrapper contract
proof. If accepted, schedule an explicit internal live-wrapper validation window
for Docker CPU/CUDA where repair, stop, start, readiness polling, and reconnect
state can be observed without enabling product UI or Podman remediation.

### 2026-07-02 - Controlled Runner Review Hardening Tests Added

**Objective**: Close the reviewer follow-ups from `5a73075` before any
user-facing enablement or real-wrapper default mutation.

**Context**: The reviewer accepted the internal controlled-runner checkpoint but
requested explicit coverage for package roots containing CMD metacharacters,
browser attempts to pass `execution_enabled`, and tampered command-wrapper
script names for all three controlled steps.

**Decision**: Add targeted tests only unless they expose a real runner gap. Keep
product UI exposure, `provider_tls_repair=true`, browser-triggered default
mutation, and Podman remediation blocked.

**Execution**:

- Extended the controlled-runner test to execute a harmless temp wrapper from a
  package-root path containing spaces, `&`, and parentheses.
- Added a direct operation-POST test proving browser input with
  `execution_enabled=true` is rejected as an unexpected field.
- Added tampered script-name rejection checks for the repair, stop, and start
  wrapper slots.

**Gate**: Gate 2 controlled-runner hardening, still pre-product-UI and
pre-default-mutation.

**Result**: PASS. The new hardening tests passed without production helper-code
changes, so the existing controlled runner already handled the reviewed path
safety and script-name tampering cases.

**Validation**:

- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_task_087_host_helper.py -q -p no:cacheprovider`
- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_config.py tests\unit\test_error_sanitization.py -q -p no:cacheprovider`
- PASS:
  `python .agents\skills\towerscout-secret-and-provider-key-safety\scripts\scan_for_sensitive_terms.py scripts\lib`
- PASS: `python .agent_work\scripts\validate_agent_work.py`
- PASS:
  `python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`
- PASS: `git diff --check`

**Next**: Request reviewer feedback on the hardening-test follow-up, then proceed
to internal real-wrapper controlled validation only if the reviewer agrees the
Gate 2 controlled-runner boundary is sufficient.

### 2026-07-02 - Controlled Runner Execution Slice Added

**Objective**: Implement the first controlled execution-design slice behind the
existing host-helper operation plan while keeping product UI exposure,
`provider_tls_repair=true`, Podman remediation, and default mutating execution
blocked.

**Context**: The reviewer accepted `bb0ef3b` as an acceptable controlled
execution design scope and requested one follow-up before merge: explicitly
account for the Windows `.cmd`/`.bat` interpreter boundary. The next slice was
allowed only as command-runner control implementation, not user-facing repair
enablement.

**Decision**: Keep execution disabled by default and add a gated controlled
runner that can be invoked directly by tests. The runner validates the accepted
operation plan, exact wrapper names, fixed wrapper arguments, package-root path
containment, fixed `cmd.exe` interpreter selection, fixed interpreter flags,
per-step timeouts, and support-safe public status before any command can run.

**Execution**:

- Updated `scripts/lib/TowerScoutHostHelper.ps1` with support-safe state
  classification, persisted operation status metadata, explicit step timeouts,
  package-local command resolution, fixed Windows command-interpreter handling,
  structured argument validation, subprocess timeout cleanup, and a gated
  controlled execution path.
- Updated `tests/unit/test_task_087_host_helper.py` to prove the runner remains
  gated, rejects mutated command arguments, uses fixed `cmd.exe`, executes only
  harmless temp wrappers during tests, handles a package root with spaces,
  maps timeout to `operation_timeout`, expires timeout locks on poll, and keeps
  fake raw stdout/stderr/local path/certificate details out of public status.
- Updated this Task-087 document to record the `.cmd`/`.bat` interpreter-boundary
  requirement and test gate.

**Observed Status Codes / Labels**:

- `planned`
- `tls_repair_completed`
- `runtime_stopped`
- `ready`
- `operation_timeout`
- `operation_expired`

**Gate**: Gate 2 controlled execution implementation, still pre-product-UI and
pre-default-mutation.

**Result**: PASS for the controlled runner slice. The implementation can run the
allowlisted command sequence only when explicitly invoked with execution enabled
from internal code/tests; the browser operation endpoint still uses the default
planning-only path and capabilities continue to report `provider_tls_repair=false`.

**Validation**:

- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_task_087_host_helper.py -q -p no:cacheprovider`
- PASS:
  `.\.venv\Scripts\python.exe -m pytest tests\unit\test_config.py tests\unit\test_error_sanitization.py -q -p no:cacheprovider`
- PASS: `python .agent_work\scripts\validate_agent_work.py`
- PASS:
  `python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`
- PASS: `git diff --check`
- PASS:
  `python .agents\skills\towerscout-secret-and-provider-key-safety\scripts\scan_for_sensitive_terms.py scripts\lib`

**Next**: Request reviewer feedback on the controlled runner implementation
before exposing any product UI path, setting `provider_tls_repair=true`, enabling
default browser-triggered mutation, or adding Podman remediation.

### 2026-07-02 - Mutating Execution Design Review Scope Added

**Objective**: Record the handoff criteria for the first mutating repair/restart
execution design review without enabling script execution, product UI exposure,
or Podman remediation.

**Context**: The reviewer accepted `84d6e49` as sufficient for the
operation-control checkpoint and recommended moving to a narrowly scoped
execution-design review. The accepted boundary remains Docker CPU/CUDA only.
`provider_tls_repair=true`, product UI entry points, and Podman Compose provider
remediation remain blocked until later checkpoints explicitly approve them.

**Decision**: Add a design-only controlled runner contract, explicit script-exit
to public-state mapping, timeout/retry semantics, and required execution-runner
tests. The browser may only authorize the internally generated operation plan;
it must not influence script path, command path, engine, GPU mode, app port,
provider argument order, `-Apply`, `-NoBrowser`, timeout values, or working
directory.

**Execution**: Updated the restart orchestration section with the first
controlled execution design review target. The section requires package-local
allowlisted wrappers, package-root path containment, structured argument arrays,
support-safe public status, timeout handling, idempotent same-authorization
behavior, `operation_busy` for different active authorization, and terminal state
classification before any execution code is enabled.

**Observed Status Codes / Labels**:

- `tls_repair_completed`
- `tls_repair_selection_required`
- `tls_repair_failed`
- `runtime_stopped`
- `runtime_stop_failed`
- `ready`
- `readiness_timeout`
- `runtime_start_failed`
- `readiness_failed`
- `operation_timeout`

**Gate**: Gate 2 Security Proof to controlled execution-design handoff.

**Result**: Documentation-only PASS. The task now states the expected mutating
execution design review scope, but no mutating command runner, product UI
entry point, Podman remediation path, or `provider_tls_repair=true` exposure has
been implemented.

**Validation**:

- PASS:
  `python .agent_work\scripts\validate_agent_work.py`
- PASS:
  `python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`
- PASS: `git diff --check`

**Next**: Ask the reviewer to verify the execution design scope before
implementation proceeds. The next implementation slice should still be reviewed
as execution-design work first, not product UI enablement.

### 2026-07-02 - Operation-Control Hardening Follow-Up

**Objective**: Address reviewer follow-ups that should be complete before the
first mutating repair/restart execution design is reviewed.

**Context**: The reviewer accepted `1342f0b` as a non-mutating checkpoint but
recommended endpoint-specific CORS/method handling, byte-exact or explicitly
ASCII-only POST body handling, full script-exit mapping tests, and deterministic
terminal/retry/cleanup semantics before moving toward execution.

**Decision**: Keep the helper non-mutating and narrow the request surface now.
Use byte-level request parsing with explicit ASCII-only request bodies for this
JSON schema, because accepted provider/confirmation/authorization fields are
ASCII by contract. Return CORS allowed methods based on the resolved endpoint:
`GET, OPTIONS` for health/runtime/status endpoints and `POST, OPTIONS` only for
`/operations/provider-tls-repair`.

**Execution**: Replaced the helper request-body read path with raw byte reads
through the header/body boundary, ASCII validation, and exact `Content-Length`
body reads. Added endpoint-level allowed-method resolution, preflight method
validation, and endpoint-specific CORS response headers. Extended the helper
self-test with minimal preflight coverage for health, provider-operation POST,
operation-status GET, and wrong-method rejection. Extended the focused pytest
PowerShell probe to cover every script-exit mapping row.

**Gate**: Gate 2 Security Proof, non-mutating hardening before execution design
**Observed States**: `cors_preflight_ok`, `rejected_method`, `planned`,
`operation_busy`, `tls_repair_completed`, `tls_repair_selection_required`,
`tls_repair_failed`, `runtime_stopped`, `runtime_stop_failed`, `ready`,
`runtime_start_failed`, `readiness_timeout`, `readiness_failed`,
`operation_timeout`
**Result**: PASS for the hardening follow-up. Product UI, mutating
repair/restart execution, Podman remediation, and `provider_tls_repair=true`
remain blocked.
**Redaction Check**: No helper tokens, operation authorizations, local paths,
command paths, provider keys, certificate details, or raw subprocess output are
returned in public helper self-test output.

**Validation**: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File
scripts\host-helper.ps1 -SelfTest` passed. `.venv\Scripts\python.exe -m pytest
tests\unit\test_task_087_host_helper.py -q -p no:cacheprovider` passed with 4
tests.

**Next**: Run full repo/task hygiene checks, push PR #45, update the PR body to
match the implemented operation-control slice, and ask for reviewer feedback
before preparing the first mutating execution design.

### 2026-07-02 - Reviewer Operation-Control Checkpoint Reviewed

**Objective**: Record reviewer feedback for PR #45 at `1342f0b` before moving
from the bounded non-mutating operation-control slice toward execution design.

**Context**: The reviewer accepted `1342f0b` as an acceptable Gate 1/Gate 2
checkpoint. The slice now includes bounded `POST /operations/provider-tls-repair`
request parsing, required `operation_authorization`, same-authorization
idempotency, different-authorization `operation_busy`, sanitized
`GET /operations/{operation_id}` status polling, `execution_enabled=false`, and
script-exit-to-public-state mapping. Product UI, mutating repair/restart
execution, and Podman remediation remain blocked.

**Decision**: Treat the checkpoint as accepted, but require another
non-mutating hardening pass before any first mutating repair/restart execution
slice. The required follow-ups are endpoint-specific CORS/method responses,
byte-exact or explicitly ASCII-only POST body handling, script-exit mapping test
coverage, deterministic terminal/retry/cleanup semantics, and an updated PR body
that no longer describes the implemented operation-control slice as future work.

**Execution**: Verified the reviewer feedback against the branch state and PR
metadata. The PR body still described bounded POST parsing, short-lived
operation authorization, sanitized status, cleanup, and script-exit mapping as
the next intended slice even though `1342f0b` implements that work.

**Gate**: Gate 2 Security Proof, reviewer checkpoint before execution design
**Observed States**: `planned`, `operation_busy`, `rejected_unexpected_field`,
`rejected_operation_authorization`, `execution_enabled=false`
**Result**: PASS for the non-mutating operation-control checkpoint. Mutating
execution remains blocked until the follow-ups above are complete and reviewed.

**Validation**: Review-only checkpoint. No code changed for this entry.

**Next**: Implement the non-mutating hardening follow-up, validate, push to PR
#45, and update the PR body before requesting the next reviewer pass.

### 2026-07-02 - Bounded Operation Request Control Slice

**Objective**: Add the next non-mutating host-helper operation controls before
any TLS repair, restart, or Podman remediation execution is exposed.

**Context**: The reviewer approved continuing beyond the Gate 1/Gate 2
checkpoint into bounded POST parsing, short-lived operation authorization,
sanitized async status, timeout cleanup, and script-exit mapping tables while
keeping product UI, mutating scripts, and Podman installer remediation blocked.

**Decision**: Allow only one browser-posted operation endpoint,
`POST /operations/provider-tls-repair`, with a small JSON body, fixed field
allowlist, required `operation_authorization`, and public status polling through
`GET /operations/{operation_id}`. Same authorization returns the existing
operation, different authorization returns `operation_busy`, and public status
continues to report `execution_enabled=false` until the mutating repair slice is
explicitly authorized.

**Execution**: Added bounded POST body parsing, content-type and content-length
checks, `operation_authorization` validation, operation-status polling,
same-authorization idempotency, existing-operation busy handling, timeout/expired
status cleanup, and script-exit-to-public-state mapping. Kept
`provider_tls_repair=false`, left `repair-provider-tls.cmd`, `stop.cmd`, and
`start.bat` unexecuted, and kept Podman remediation out of the browser API.

**Gate**: Gate 2 Security Proof, non-mutating operation-control slice
**Observed States**: `planned`, `operation_busy`, `rejected_unexpected_field`,
`rejected_operation_authorization`, `tls_repair_completed`,
`readiness_timeout`, `operation_timeout`
**Result**: PASS for bounded request/control-plane behavior. Product UI,
mutating TLS repair/restart execution, and Podman provider installation remain
blocked.
**Redaction Check**: Public operation responses omit helper tokens, operation
authorizations, command paths, local paths, certificate details, provider keys,
and raw subprocess output. Rejected invalid providers still collapse to
`provider=unknown`.

**Validation**: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File
scripts\host-helper.ps1 -SelfTest` passed. `.venv\Scripts\python.exe -m pytest
tests\unit\test_task_087_host_helper.py -q -p no:cacheprovider` passed with 4
tests, including a direct PowerShell probe for plan/status/idempotency/busy
behavior plus unexpected-field and invalid-authorization rejection. Endpoint
protection rejected an earlier large PowerShell self-test
fixture, so the integrated self-test remains focused on stable transport proof
and the expanded operation API assertions live in the Python test module.

**Next**: Run repository hygiene checks, push the PR #45 update, and request
reviewer feedback before deciding whether to begin the first mutating
repair/restart execution slice.

### 2026-07-02 - Rejected Provider Reflection Hardening

**Objective**: Address the PR #45 reviewer finding that rejected provider
status should not reflect caller-controlled invalid provider text before any
browser-exposed operation endpoint exists.

**Context**: The reviewer accepted `95ea6fb` as a Gate 1/Gate 2 checkpoint and
recommended continuing into the next non-mutating operation-control slice. The
one must-fix before browser-accessible POST exposure was that invalid provider
input such as `google;Start-Process` was rejected but could still appear in the
rejected operation's public status.

**Decision**: Treat invalid-provider reflection as a pre-POST blocker. Rejected
operation plans may report an approved provider enum when one was supplied, but
non-allowlisted provider text must collapse to `unknown` in all public rejected
operation status.

**Execution**: Updated the rejected operation-plan helper to sanitize provider
status centrally before building either the internal rejected plan or public
operation status. Extended the helper self-test and focused pytest coverage to
prove `google;Start-Process` returns `rejected_unknown_provider` with
`provider=unknown` and the caller-controlled text is absent from public self-test
output.

**Gate**: Gate 2 Security Proof, rejected-input redaction hardening
**Observed States**: `rejected_unknown_provider`, `provider=unknown`
**Result**: PASS. The helper still has no mutating repair/restart endpoint,
`provider_tls_repair` remains unavailable, and product UI remains blocked.
**Redaction Check**: Invalid caller provider text, command paths, helper tokens,
local paths, certificate details, provider keys, raw subprocess output, and
operation credentials are not returned in public self-test output.

**Validation**: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File
scripts\host-helper.ps1 -SelfTest` passed. `.venv\Scripts\python.exe -m pytest
tests\unit\test_task_087_host_helper.py -q -p no:cacheprovider` passed with 2
tests.

**Next**: Update the PR description to reflect the visible helper proof,
non-mutating Docker operation boundary, and rejected-provider reflection fix,
then continue only into bounded non-mutating operation-control work.

### 2026-07-02 - Docker TLS Operation Boundary Slice

**Objective**: Add the first non-mutating provider TLS repair operation
contract before exposing any repair/restart endpoint.

**Context**: The visible helper window is now locally viable, and the next
reviewer-approved direction is to move toward a support-guided Docker CPU/CUDA
repair MVP without product UI or Podman installer exposure. The remaining risk
is browser-controlled host mutation, so the helper needs an allowlisted
operation boundary before it can run the `TASK-086` repair path.

**Decision**: Add a Docker-only provider TLS repair operation plan and
package-local operation lock, but keep `provider_tls_repair` capability
advertised as unavailable and do not add a mutating POST endpoint yet. The plan
accepts only `provider=google|azure`, the fixed confirmation value
`repair_tls_and_restart`, and the captured runtime profile. It derives repair,
stop, and restart commands internally, rejects Podman for the first slice, and
returns only sanitized public states.

**Execution**: Extended `scripts\lib\TowerScoutHostHelper.ps1` with operation
planning, fixed confirmation validation, Docker-only runtime gating, one active
operation lock per helper session, nonce fingerprinting without storing raw
operation credentials, and stop-path cleanup for active operation lock files.
The helper self-test now proves the Docker plan is accepted, Podman is blocked,
bad confirmation is rejected, non-allowlisted providers are rejected, duplicate
starts return `operation_busy`, and public operation status does not expose
command paths, helper tokens, local paths, certificate details, or raw
subprocess output.

**Phase 1 Evidence - 2026-07-02 - Docker Operation Boundary**

**Gate**: Gate 2 Security Proof, non-mutating operation-contract slice
**Environment**: Windows source/package-like script context, Docker CPU profile
shape, public-safe validation labels only
**Objective**: Validate allowlisted provider TLS operation planning, Docker-only
first-slice gating, fixed confirmation enforcement, single-operation locking,
and public-status redaction before adding repair/restart execution.
**Command Category**: operation plan / allowlist rejection / confirmation
rejection / duplicate-operation lock / helper self-test
**Inputs**: `provider=google`, `engine=docker`, `gpu=off`,
`confirmation=repair_tls_and_restart`, plus negative Podman, confirmation, and
provider inputs
**Observed States**: `planned`, `unsupported_runtime`,
`rejected_confirmation`, `rejected_unknown_provider`, `operation_busy`
**Result**: PASS for non-mutating operation boundary proof. Product UI,
mutating endpoints, actual TLS repair execution, restart orchestration, and
Podman provider remediation remain blocked.
**Redaction Check**: No helper token, helper listener port, local path, provider
key, certificate detail, raw subprocess output, command path, thumbprint, or
operation credential was returned in public self-test output.

**Validation**: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File
scripts\host-helper.ps1 -SelfTest` passed. `.venv\Scripts\python.exe -m pytest
tests\unit\test_task_087_host_helper.py -q -p no:cacheprovider` passed with 2
tests. The unqualified system `python -m pytest ...` failed before test
execution because that interpreter does not have `pytest` installed; the
project virtualenv was used for validation.

**Next**: Add bounded POST-body parsing, short-lived operation authorization,
asynchronous sanitized operation status, execution timeout/cleanup, and
script-exit mapping before enabling the helper to run `repair-provider-tls.cmd`
or restart TowerScout.

### 2026-07-02 - Visible Helper Lifecycle Proof

**Objective**: Validate the reviewer-approved visible helper-window lifecycle
candidate before adding any mutating repair/restart endpoint.

**Context**: The PR #45 follow-up reviewer accepted the Gate 1 hardening and
recommended validating `scripts\host-helper-visible.cmd` next. The visible
helper model is intended to avoid the hidden detached PowerShell pattern that
triggered endpoint protection/AMSI while still proving that a helper can survive
the launching wrapper process and be invalidated by the package stop path.

**Decision**: Treat the visible helper window as a viable Gate 1 lifecycle proof
candidate based on local validation, but keep product UI, TLS repair operation
endpoints, restart orchestration, and Podman remediation blocked until the team
confirms the visible-window UX and endpoint-policy behavior are acceptable for
the target managed Windows environment.

**Execution**: Created a temporary sanitized validation harness under
`.agent_work\tmp\` and ran it outside the sandbox boundary so the visible helper
PowerShell window could open. The harness cleared stale helper sessions, launched
`scripts\host-helper-visible.cmd`, waited for package-local session metadata,
used the token internally without printing it, called the loopback `/health`
endpoint, invalidated the helper through `scripts\host-helper.ps1 -Stop`,
verified session/token files were removed, and verified the helper endpoint was
no longer reachable after stop cleanup.

**Phase 1 Evidence - 2026-07-02 - Visible Helper Lifecycle**

**Gate**: Gate 1 Helper Transport Proof / Gate 2 Security Proof
**Environment**: Windows source/package-like script context, Docker CPU profile
shape, public-safe validation labels only
**Objective**: Validate visible helper launch, wrapper-process return,
loopback health reachability, package-local session/token creation, stop-path
invalidation, and post-stop listener cleanup.
**Command Category**: visible helper start / health check / origin-token check /
stop cleanup / lifecycle validation
**Inputs**: `engine=docker`, `gpu=off`, `package_flavor=self-test-visible`,
sanitized health request, stop invalidation request
**Observed States**: `started`, `returned`, `created`, `ready`, `cleared`,
`reachable_after_stop=false`
**Result**: PASS for local visible-helper lifecycle proof; target managed
endpoint UX/policy confirmation still required before product integration.
**Redaction Check**: No helper token, helper listener port, local path, provider
key, certificate detail, raw subprocess output, `.env` value, or support log was
recorded.
**Follow-Up**: User confirmed in-session that the visible helper window was
observable during the slower manual check and no endpoint-protection alert,
warning, quarantine, or suspicious-process notification appeared. Continue to
the first support-guided Docker CPU/CUDA repair MVP design, while keeping
product UI and mutating endpoints blocked until operation locking,
authorization, timeout/cleanup, and sanitized progress are implemented.

**Validation**: The temporary visible-helper harness returned `result=passed`,
`visible_window_launch=started`, `wrapper_process=returned`,
`session_metadata=created`, `token_file=created_then_removed`,
`health_check=ready`, `stop_invalidation=cleared`, and
`reachable_after_stop=false`. A follow-up session-directory check found no
remaining helper session/token files.

**Next**: Remove the temporary harness, rerun task/document validators, commit
the evidence update, and then decide whether to proceed into the Docker-only
repair operation slice or pause for reviewer/user confirmation on the visible
window UX.

### 2026-07-02 - Reviewer Gate 1 Hardening Follow-Up

**Objective**: Incorporate the PR #45 Gate 1 reviewer feedback that can be
addressed before repair/restart operation work begins.

**Context**: The reviewer accepted the loopback `TcpListener` transport proof
but recommended blocking product UI and mutating operations until the helper
lifecycle model is redesigned without the hidden detached PowerShell pattern
that triggered endpoint protection. The reviewer also identified low-risk
hardening: narrow CORS methods to the implemented API, add HTTP request
hardening before future POST operations, avoid hardcoded package flavor in
launch profiles, and preserve package artifact hygiene.

**Decision**: Accept the low-risk hardening now and keep lifecycle work in Gate
1. Use a transparent visible helper command as the next lifecycle proof
candidate instead of reintroducing hidden detached PowerShell. Do not wire this
visible helper command into product UI or automatic launcher behavior yet; it is
for reviewer/manual endpoint-policy validation before selecting the final
helper lifecycle model.

**Execution**: Tightened helper CORS from `GET, POST, OPTIONS` to `GET,
OPTIONS`, added basic helper request timeouts plus request-line/header-count/
header-byte limits, extended the helper self-test to assert the GET-only CORS
policy, changed launcher profile capture to use the real package PyTorch flavor
when available, added `scripts\host-helper-visible.cmd` as an explicit visible
helper-window entry point, and updated `scripts\package-release.ps1` to include
the helper scripts/library so release package generation does not copy a
`launch.ps1` that dot-sources a missing helper library.

**Phase 1 Evidence - 2026-07-02 - Reviewer Hardening Follow-Up**

**Gate**: Gate 1 Helper Transport Proof / Gate 2 Security Proof
**Environment**: Windows source/package-like script context, Docker CPU profile
shape, public-safe self-test labels only
**Objective**: Validate GET-only CORS policy, bounded request parsing, helper
artifact package inclusion, and the next transparent lifecycle proof candidate.
**Command Category**: health check / origin-token check / allowlist rejection /
stop cleanup / release-package hygiene / lifecycle design
**Inputs**: `engine=docker`, `gpu=off`, sanitized self-test runtime profile,
valid token scenario, wrong token scenario, wrong origin scenario, unknown
endpoint scenario, CORS preflight scenario, invalidated-session scenario
**Observed States**: `ready`, `rejected_token`, `rejected_origin`,
`rejected_unknown_endpoint`, `cors_preflight_ok`, `session_invalidated`
**Result**: PARTIAL
**Redaction Check**: No helper tokens, helper listener ports, local paths,
provider keys, certificate details, raw subprocess output, `.env` values, or
support logs were recorded.
**Follow-Up**: Manually validate the visible helper-window entry point on the
target Windows endpoint-policy environment, then either accept that lifecycle
model for the first product slice or replace it with a native/supervised helper
before adding repair/restart operations.

**Validation**: PowerShell parser checks passed for
`scripts\lib\TowerScoutHostHelper.ps1`, `scripts\launch.ps1`, and
`scripts\package-release.ps1`. `powershell.exe -NoProfile -ExecutionPolicy
Bypass -File scripts\host-helper.ps1 -SelfTest` passed with the existing loopback
security scenarios and the new GET-only CORS assertion.

**Next**: Run full `.agent_work` and diff validation, then decide whether to
ask the reviewer to manually test the visible helper lifecycle proof before
continuing into any mutating helper operation.

### 2026-07-02 - Launch Profile Capture And Endpoint Protection Finding

**Objective**: Continue Gate 1 by double-checking the initial helper proof,
adding shared launcher runtime-profile capture, and testing whether a detached
PowerShell helper path is viable.

**Context**: The first helper proof validated loopback binding, origin/token
checks, endpoint allowlisting, sanitized responses, and basic session
invalidation. The next Gate 1 question was whether the PowerShell helper could
move toward launcher-exit survival without weakening the security model or
leaving stale helper sessions behind.

**Decision**: Keep support-safe launch-profile capture and invalidated-session
handling, but do not keep the hidden detached PowerShell process attempt. During
double-check validation, the local endpoint protection/AMSI path blocked the
helper library when the detached helper implementation embedded a hidden
PowerShell child-process launch. That is a valid Gate 1 feasibility finding, so
the AV-triggering detached code was removed before committing. Detached
lifecycle remains open and should be redesigned rather than forced through a
pattern endpoint protection rejects.

**Execution**: Added `Save-TowerScoutHostHelperLaunchProfile` and called it from
`scripts\launch.ps1` after the effective engine and port are known, so
setup/bootstrap/start/launch paths refresh a shared package-local runtime
profile through the launcher. The profile records only support-safe metadata:
engine, GPU mode, app port/base URL, package flavor, helper version, timestamp,
and package-root identity hash. Added helper-session ID validation, package-local
token-file cleanup, helper-port refresh in session metadata, and listener-loop
session checks so invalidated sessions return `session_invalidated` and the
listener can exit once the session is cleared. Added an `invalidated_session`
self-test scenario.

**Phase 1 Evidence - 2026-07-02 - Launch Profile And Invalidation Handling**

**Gate**: Gate 1 Helper Transport Proof / Gate 2 Security Proof
**Environment**: Windows source/package-like script context, Docker CPU profile
shape, public-safe self-test labels only
**Objective**: Validate launcher runtime-profile capture, token/session cleanup,
invalidated-session response handling, and endpoint-protection feasibility for
the proposed detached PowerShell lifecycle.
**Command Category**: runtime profile capture / helper start / origin-token
check / stop cleanup / endpoint protection feasibility
**Inputs**: `engine=docker`, `gpu=off`, sanitized self-test runtime profile,
launch-profile metadata, session cleanup metadata
**Observed States**: `profile_captured`, `ready`, `rejected_token`,
`rejected_origin`, `rejected_unknown_endpoint`, `cors_preflight_ok`,
`session_invalidated`, `blocked_by_endpoint_protection`
**Result**: PARTIAL
**Redaction Check**: No helper tokens, helper listener ports, local paths,
provider keys, certificate details, raw subprocess output, `.env` values, or
support logs were recorded.
**Follow-Up**: Redesign helper launch/lifecycle without the rejected hidden
PowerShell child-process pattern. Candidate follow-ups include a safer
package-local supervisor pattern, a small native helper proof, or another
endpoint-policy-approved process model before product UI integration.

**Validation**: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File
scripts\host-helper.ps1 -SelfTest`, `powershell.exe -NoProfile -ExecutionPolicy
Bypass -File scripts\host-helper.ps1 -Stop`, focused launch-profile and
session/token cleanup checks, `python .agent_work\scripts\validate_agent_work.py`,
and `git diff --check` passed after removing the AV-triggering detached process
attempt.

**Next**: Continue Gate 1 with lifecycle design alternatives that can survive
launcher exit without triggering endpoint protection, then prove package-local
script invocation only after the lifecycle model is accepted.

### 2026-07-02 - Helper Session Invalidation Scaffold Added

**Objective**: Add the first package-local helper session invalidation path so
`scripts\stop.ps1` can invalidate helper metadata before stopping the selected
container runtime.

**Context**: Gate 1 requires the helper to self-terminate or be invalidated
when the package runtime stops whenever practical. The initial loopback proof
did not write durable token material, but it also did not give the stop path
any helper-session state to clear.

**Decision**: Add ignored package-local helper session metadata under
`.towerscout-runtime\host-helper\` and keep token material out of the metadata.
Use support-safe package-root identity hashing rather than recording full local
paths in helper session JSON. Treat this as invalidation scaffolding only; full
helper detachment, heartbeat, process termination, and container-exit detection
remain later Gate 1 work.

**Execution**: Added session metadata save/clear helpers, a `scripts\host-helper.ps1
-Stop` invalidation mode, `.towerscout-runtime/` git ignore coverage, and
`scripts\stop.ps1` cleanup before Compose shutdown. Active helper request
handling now returns a sanitized `session_invalidated` state if its session
metadata has been cleared.

**Phase 1 Evidence - 2026-07-02 - Session Invalidation**

**Gate**: Gate 1 Helper Transport Proof / Gate 2 Security Proof
**Environment**: Windows source/package-like script context, Docker CPU profile
shape, public-safe self-test labels only
**Objective**: Validate helper session metadata can be saved without token
material and invalidated by the stop-style cleanup path.
**Command Category**: stop cleanup / session invalidation
**Inputs**: `engine=docker`, `gpu=off`, sanitized self-test runtime profile
**Observed States**: `active`, `invalidated`, `session_invalidated`
**Result**: PASS
**Redaction Check**: No helper tokens, helper listener ports, local paths,
provider keys, certificate details, raw subprocess output, `.env` values, or
support logs were recorded.
**Follow-Up**: Add detached helper start, launcher profile refresh, heartbeat
or TTL, and process termination/cleanup proof before product UI integration.

**Validation**: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File
scripts\host-helper.ps1 -SelfTest`, `powershell.exe -NoProfile -ExecutionPolicy
Bypass -File scripts\host-helper.ps1 -Stop`, a focused PowerShell
save/clear/active-state check, and `git diff --check` passed.

**Next**: Continue Gate 1 with detached helper lifecycle and trusted
launcher-generated runtime profile refresh across setup/bootstrap/start/launch.

### 2026-07-02 - Gate 1 Loopback Helper Proof Started

**Objective**: Add the first package-local host helper proof for Gate 1/Gate 2
transport primitives before any product UI or restart orchestration work.

**Context**: Task-087 requires a browser-reachable host helper that binds only
to loopback, avoids administrator URL ACL setup, accepts TowerScout localhost
origins only, requires a per-run token, and returns sanitized states. The first
implementation slice is intentionally limited to transport/security proof; it
does not expose a repair button, run TLS repair, run the Podman provider
installer, or restart TowerScout.

**Decision**: Use a PowerShell `TcpListener` proof instead of `HttpListener` for
the first helper transport because `TcpListener` binds directly to
`127.0.0.1` and avoids Windows URL ACL registration. Add a self-test mode so
the listener, origin check, token check, endpoint allowlist, and CORS preflight
handling can be validated without leaving a background helper process running.

**Execution**: Added `scripts\lib\TowerScoutHostHelper.ps1`,
`scripts\host-helper.ps1`, and `scripts\host-helper.cmd`. The helper proof
creates an internal runtime profile, generates an in-memory token, exposes
sanitized `GET /health` and `GET /runtime-profile` responses, rejects unknown
endpoints, rejects bad origins, rejects missing/wrong tokens, and supports
browser CORS preflight for the allowlisted endpoints.

**Phase 1 Evidence - 2026-07-02 - Loopback Self-Test**

**Gate**: Gate 1 Helper Transport Proof / Gate 2 Security Proof
**Environment**: Windows source/package-like script context, Docker CPU profile
shape, public-safe self-test labels only
**Objective**: Validate loopback listener feasibility, TowerScout localhost
origin enforcement, token enforcement, endpoint allowlist rejection, and
sanitized helper responses.
**Command Category**: helper start / health check / origin-token check /
allowlist rejection
**Inputs**: `engine=docker`, `gpu=off`, sanitized self-test runtime profile,
valid token scenario, wrong token scenario, wrong origin scenario, unknown
endpoint scenario
**Observed States**: `ready`, `rejected_token`, `rejected_origin`,
`rejected_unknown_endpoint`, `cors_preflight_ok`
**Result**: PASS
**Redaction Check**: No tokens, helper listener ports, local paths, provider
keys, certificate details, raw subprocess output, `.env` values, or support
logs were recorded.
**Follow-Up**: Add lifecycle/runtime-profile file handling, stop cleanup, and
allowlisted script-invocation proof before product UI integration.

**Validation**: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File
scripts\host-helper.ps1 -SelfTest` passed. `git diff --check` passed.

**Next**: Extend the proof toward runtime-profile persistence, helper
lifecycle/stop cleanup, and allowlisted script invocation while keeping product
UI integration blocked behind Gates 1 and 2.

### 2026-07-02 - Reviewer Minor Follow-Up Added

**Objective**: Incorporate the reviewer's non-blocking follow-up suggestions
before merging the Sprint 6 closeout / Task-087 planning PR.

**Context**: The reviewer approved the updated Task-087 direction and suggested
three implementation-support additions: a sanitized Phase 1 evidence template,
explicit `scripts\stop.cmd` helper-session cleanup, and release-owner sign-off
before any product UI exposes the Podman Compose provider installer operation.

**Decision**: Accept all three suggestions as documentation refinements because
they reduce implementation ambiguity without changing the approved first-slice
scope. Keep the first user-facing slice limited to Docker CPU/CUDA TLS repair
and restart while allowing sanitized Podman preflight status only.

**Execution**: Added the Phase 1 evidence template, explicit stop-path helper
termination/invalidation requirements, and release-owner sign-off language for
any future Podman installer UI exposure.

**Validation**: `python .agent_work\scripts\validate_agent_work.py`,
`python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`,
and `git diff --check -- .agent_work\tasks\active\TASK-087-host-side-tls-repair-control-plane.md`
passed.

**Next**: Push the final Task-087 planning update to PR #44 for merge
readiness, then start implementation from a fresh post-merge Task-087 branch.

### 2026-07-02 - Reviewer Boundary And Security Follow-Up Added

**Objective**: Incorporate reviewer feedback on Task-087's first-slice scope,
helper lifecycle, token delivery, operation locking, restart request shape,
runtime-profile generation, and frontend validation-state handling.

**Context**: The reviewer approved the gated helper direction but recommended
holding Podman Compose provider remediation out of the first user-facing slice
until the Docker CPU/CUDA helper proof validates the transport, security model,
and reconnect UX. Local code review confirmed that current setup validation
already carries structured TLS categories, but Setup Wizard state collapses
provider validation to booleans, launcher scripts exit after readiness, and
Podman provider scripts print local paths/version/installer details that must
not be streamed to browser-visible helper output.

**Decision**: Keep Podman Compose provider remediation in Task-087 as a valid
later slice, but define Docker CPU/CUDA provider TLS repair and restart as the
first implementation target. Add explicit design requirements for detached or
heartbeat-based helper lifecycle, short-lived operation authorization instead
of frontend exposure to durable helper tokens, one active host operation per
package instance, fixed `repair_tls_and_restart` confirmation semantics, shared
runtime-profile generation across setup/bootstrap/start/launch paths, and
structured provider failure retention in Setup Wizard.

**Execution**: Added a canonical-source note for the active PR branch, a first
implementation slice boundary, Gate 1 and Gate 2 additions, helper API operation
lifecycle rules, backend/frontend responsibilities, security/privacy
requirements, test-plan coverage, phase-plan updates, and acceptance criteria.

**Validation**: `python .agent_work\scripts\validate_agent_work.py`,
`python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`,
and `git diff --check -- .agent_work\tasks\active\TASK-087-host-side-tls-repair-control-plane.md`
passed.

**Next**: Run `.agent_work` validators and `git diff --check`, then ask the
reviewer to re-review the active PR branch plan before implementation begins.

### 2026-07-02 - Podman Compose Provider Remediation Scope Added

**Objective**: Incorporate the proposed Podman Compose provider check and
installer path into the Task-087 design before reviewer feedback.

**Context**: The package already validates Podman Compose provider selection and
includes `scripts\install-podman-compose-provider.cmd -Apply` for connected
support/setup use. The new host helper framework could reduce Podman support
friction, but the provider installer changes `.env`, creates a package-local
provider environment, and may require network/Python access. It should not be
hidden inside TLS repair.

**Decision**: Treat Podman Compose provider remediation as an optional,
separately confirmed runtime-preflight operation within the Task-087 helper
framework. Keep provider TLS repair and Podman provider installation separate,
derive all runtime context from the trusted launcher profile, and reject all
browser-supplied installer arguments.

**Execution**: Updated the Task-087 problem statement, gates, helper API,
runtime profile, restart orchestration, security requirements, test plan,
acceptance criteria, open questions, and risks to include the optional Podman
Compose provider remediation path.

**Validation**: `python .agent_work\scripts\validate_agent_work.py`,
`python .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`,
and `git diff --check -- .agent_work\tasks\active\TASK-087-host-side-tls-repair-control-plane.md`
passed.

**Next**: Ask the reviewer to assess whether Podman Compose provider
remediation should be included in the first Task-087 implementation slice or
held behind the Docker CPU/CUDA helper proof.

### 2026-07-02 - Selected For Sprint 7

**Objective**: Promote Task-087 from post-RC7.1 follow-up planning into the active Sprint 7 lane.

**Context**: Sprint 6 closed with RC7.1 validated for tester-facing use and `TASK-086` established as the command-based managed-network TLS repair baseline. The team selected the host-side TLS repair control plane as the next active sprint focus.

**Decision**: Keep Task-086 as the validated fallback while starting Task-087 with the gated helper transport proof. Product UI integration remains blocked until the helper transport and security gates pass.

**Execution**: Updated task status and Sprint target during Sprint 6 closeout. Kept this task file in `.agent_work/tasks/active/` while completed Sprint 6 task files moved to `.agent_work/tasks/completed/`.

**Validation**: Closeout validation will run after tracker updates and file moves.

**Next**: Start Gate 1 with a package-local helper transport proof that validates loopback binding, token/origin checks, helper lifetime, and script invocation behavior on the target Windows environment.

### 2026-06-29 - Initial Plan Created

**Objective**: Capture the proposed one-click managed-network TLS repair path as
a scoped follow-on to `TASK-086`.

**Decision**: Plan around a trusted package-local Windows host helper with a
narrow loopback API, per-launch token, explicit user confirmation, and strict
reuse of the validated `repair-provider-tls.cmd` plus stop/start flow. Keep the
manual command path as the support baseline and do not make this a default
RC7.1 baseline requirement unless user-testing evidence requires it.

**Next**: Review the plan with the team, decide whether `TASK-087` is selected
for active implementation before or after RC7.1, then run a helper transport
proof of concept before product UI work begins.

### 2026-06-29 - Reviewer Feedback Incorporated

**Objective**: Tighten the Task-087 plan before implementation by incorporating
reviewer feedback on helper security, transport feasibility, structured error
handling, runtime-profile correctness, packaging drift, and release gating.

**Context**: The reviewer agreed the guided repair button can materially reduce
managed-network setup friction, but highlighted that Task-087 introduces a new
browser-to-host trust boundary. The existing `TASK-086` command path remains the
validated repair baseline and should not be replaced until the host helper is
proven.

**Decision**: Keep Task-087 as a follow-on support UX improvement and require
four Go/No-Go gates before user-facing package inclusion: helper transport
proof, security proof, product integration proof, and managed-network package
validation. Prefer direct browser-to-loopback-helper calls for the first slice
only if the proof of concept validates CORS, origin, token, and
private-network behavior in the target Windows environment.

**Execution**:
- Added explicit Go/No-Go gates.
- Added runtime-profile identity and stale/wrong-package/multi-instance
  rejection requirements.
- Added a direct browser-to-loopback helper preference with backend brokering as
  a fallback if the proof of concept fails.
- Required sanitized operation states instead of raw subprocess output because
  the manual repair scripts can print support-sensitive certificate details.
- Added token non-leakage requirements for readiness, status, logs, support
  bundles, browser console output, DOM attributes, and task evidence.
- Required helper-unavailable to remain a normal command-fallback path.
- Added CPU/CUDA package inclusion and generated-artifact exclusion checks as
  Gate 4 requirements.

**Validation**: `python .agent_work\scripts\validate_agent_work.py` passed
after the Task-087 plan and current-task index updates.

**Next**: Validate task tracker hygiene, then decide whether to keep Task-087 as
post-RC7.1 follow-up or authorize only the Phase 1 helper transport proof of
concept while RC7.1 materials proceed from the validated Task-086 baseline.
