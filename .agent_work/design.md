# TowerScout Current Technical Design

**Last Updated**: August 19, 2026
**Scope**: Unsigned fix-first preview iteration, four-profile runtime
qualification, October production signing, and cdcai handoff
**Archived Pre-Rebaseline Design**:
[`2026-07-23-pre-rebaseline-design.md`](./context/archive/2026-07/2026-07-23-pre-rebaseline-design.md)

## Current Architecture

TowerScout is a Flask web application packaged as an OCI-compatible local
application for Windows 11 AMD64. The normal user path is a GitHub Release
control package plus a digest-pinned GHCR image and a shared checksummed Model &
Data Package.

The application includes:

- Flask routes, filesystem-backed sessions, setup/settings, provider
  validation, detection, progress/cancel, export, restore, and readiness.
- Google Maps and Azure Maps frontend/backend provider paths.
- YOLOv5 primary detection plus EfficientNet secondary classification.
- Named volumes for configuration, model/data assets, logs, sessions, uploads,
  cache, and working data.
- Windows launch/setup/status/log/stop/import/TLS support scripts.
- Docker- and Podman-compatible Compose execution.

## Release And Repository Topology

### During Preview And Candidate Development

- `J-Schulein/TowerScout` hosts the immutable `v0.1.2` pilot.
- The same fork publishes immutable unsigned `v0.1.3-preview.N` GitHub
  prereleases for normal-user package refinement.
- `v0.1.3-rc.N` is reserved for signed production-shaped candidates produced
  through Task-100 after the package is satisfactory.
- `cdcai/TowerScout` remains unchanged.

### During Task-087 Validation

- `feature/task-087-windows-launcher-prototype` remains a short-lived branch
  reconciled with verified `main` commit `3932abf` and reviewed through Draft
  PR #67. Rebased implementation checkpoint `1908670` preserves the accepted
  launcher/runtime tree while retaining the Sprint 09 and Task-099 history.
- Validation artifacts are built only from an exact commit and use
  `Task-087-validation-<short-SHA>` rather than either the
  `v0.1.3-preview.N` or `v0.1.3-rc.N` release line.
- The historical source-bound functional package was assembled from clean commit
  `4327fb6288f4f8c83202f548a2ba7cb2dcf9bab6`, after launcher/runtime fixes in
  `18082cf` and provenance hardening in `4327fb6`. It is evidence for that
  historical source only; a new full-runnable package must use the accepted
  post-reconciliation PR head.
- No validation artifact receives a tag or GitHub Release. Executable transfer
  uses only the organization-approved internal signing/endpoint-validation
  channel; repository evidence contains hashes, source identity, sanitized
  results, and no secrets or local certificate detail.
- `main`, the frozen `v0.1.2` release, and `cdcai/TowerScout` remain unchanged
  throughout the checkpoint.
- The August 19 Proceed decision makes the Draft PR eligible for normal
  technical/security review, merge, and separate preview-package integration.
  Existing validation artifacts remain nonpublishable and do not themselves
  authorize merge or release.

### During Unsigned Preview Iteration

The release-package integration path is separate from the Task-087 validation
assembler:

1. Build from an exact accepted commit and fresh digest-pinned image.
2. Include the launcher and intended normal-user entry points in the real
   control-package layout.
3. Generate current manifests, checksums, source/SBOM/notices, release notes,
   and unsigned/unmanaged-test-machine guidance.
4. Publish immutable `v0.1.3-preview.N` only as a fork-side GitHub prerelease;
   never mark it `Latest` or treat it as a signed RC.
5. Test the actual download/extract/setup/use path on an approved clean
   unmanaged Windows machine without security-disablement instructions.
6. Repeat under a new preview identity until the ADR-019 satisfactory-package
   gate is recorded.

Task-100 then builds and signs the stable production-shaped package under a
`v0.1.3-rc.N` identity in October, regenerates package metadata/checksums after
signing, verifies the extracted signatures, and runs representative managed-
endpoint qualification. Those exact bytes are published/frozen only after the
Task-100 gates pass.

### At Final Adoption

- Task-100's signed-candidate and managed-endpoint gate has passed.
- The cdcai owner and project lead select the official tag and display title.
- The official image, package, manifests, checksums, and documentation are
  built consistently for that identity.
- The official release is published from cdcai only after qualification and
  explicit adoption approval.
- The fork remains available as pilot and provenance history.

## Runtime Profiles

The final supported matrix contains four profiles:

| Engine | Compute | Required qualification |
| --- | --- | --- |
| Docker | CPU | Normal CPU package setup, readiness, provider, detection, persistence, and stop |
| Docker | GPU | CUDA package plus selected-engine NVIDIA validation and CUDA readiness |
| Podman | CPU | Running Podman machine plus approved non-Docker-Desktop Compose provider |
| Podman | GPU | Podman WSL2 machine, NVIDIA host support, CDI, approved Compose provider, and CUDA readiness |

The profiles are equally supported once their documented prerequisites are met.
This final-candidate target does not retroactively change the narrower support
wording of the frozen `v0.1.2` pilot.

## Provider TLS Design Boundary

ADR-018 provisionally replaces the earlier browser-to-loopback-helper
implementation direction with a time-boxed, reversible Windows launcher proof.
The older helper design and evidence remain preserved in the Task-087 record,
but they do not authorize helper activation during this checkpoint.

The candidate flow is:

1. Setup/Settings classifies a repairable Google or Azure certificate trust
   failure.
2. The browser directs the user to a visible TowerScout launcher; it does not
   issue a host operation.
3. The package-local launcher identifies the exact package, engine, runtime
   profile, and target, then presents a fixed operation and confirmation.
4. The first proof is non-mutating status and TLS repair preview. It uses no
   listener, dormant helper import, hidden worker, execution-policy bypass,
   arbitrary command input, administrator-only setup, or Windows trust-store
   mutation.
5. After the non-mutating proof passed, the project lead authorized one
   isolated native Google/Docker TLS transaction. It passed candidate staging,
   verification, backup/recovery controls, same-profile restart, and named-
   volume preservation; the combined packaged UI flow remains unvalidated.
6. Unsigned preview iteration proceeds through the normal release-package path
   after applicable technical/security review. Production signing and
   representative managed-endpoint validation occur under Task-100 in October
   after the package is satisfactory and before signed-candidate acceptance.
7. The command-based Task-086 repair remains available throughout the proof
   and becomes the supported disposition if the launcher fails.

All existing browser/helper activation gates remain off, and PR #64 stays on
hold. The August 19 Proceed decision applies to the separate launcher and
preview-package path; it does not reactivate the dormant helper.

The first authorized unsigned full-package run confirmed that the launcher and
application do not need the dormant helper, but also exposed an unconditional
helper import in ordinary PowerShell launch and stop. The validation design now
requires normal launch/stop and Compose configuration to contain no helper
activation dependency, and requires the end-user package to omit the helper
scripts, state library, worker, and support page. Dormant source remains only as
historical review material while the branch is unmerged.

The rebuilt validation path has two deliberately separate package kinds:

- `launcher-policy` is the small, non-runnable artifact for static launcher and
  endpoint-policy review.
- `full-runnable` overlays the same inspected launcher on the normal
  digest-pinned control package for explicitly authorized functional testing.

Both assemblers stage the package directory, ZIP, and adjacent checksum before
publishing them as one artifact set, and roll back any partially published set
if publication fails. Launcher build provenance binds a clean
40-character source commit to the exact build-requirements hash, executable
hash, and deterministic complete launcher-tree hash. Assembly rechecks that
provenance and, for `full-runnable`, the base release identity, source ref,
pinned image digest, asset identity, and existing content checksums. A policy
artifact must never be represented as runnable, and neither package kind is a
release candidate.

Runtime discovery is also a fixed, non-mutating contract. The launcher resolves
only its allowlisted Docker or Podman executable and arguments, invokes the
child with `shell=False`, disconnected standard input, captured output, and a
five-second timeout. On Windows it sets `CREATE_NO_WINDOW` so a windowed
PyInstaller parent does not stall while attaching a console for the runtime CLI
child. Timeout and failure messages are sanitized; no caller-supplied command,
shell text, environment dump, or raw runtime response is displayed.

The source-bound `full-runnable` package passed a fresh isolated Docker CPU
setup on August 5. Its control/asset sidecars and all 1,012 internal checksum
records matched; verify-only preflight passed; asset staging/import completed
with hash verification; and the unique port-5008 project created fresh volumes
and reached healthy `setup_required` readiness with assets `ok`, one inference
engine, CPU selected, and the exact pinned image digest.

The August 6 manual preview checkpoint also passed. After a Windows reboot,
the isolated Docker project automatically resumed with its persisted state, and
the exact packaged launcher reported Docker running and reachable through three
consecutive refreshes. Its preview displayed the expected fixed identity:
`TowerScout Task-087-validation-4327fb6288f4 (cpu)`, Docker, GPU off, port 5008,
and Google Maps. The preview explicitly performed no certificate inspection,
trust change, container stop/restart, or dormant-helper execution. A provider
key entered only in the Setup Wizard produced the sanitized expected
`tls_ca_untrusted` category and Task-086 guidance for
`.\scripts\repair-provider-tls.cmd -Provider google -Engine docker -Gpu off`.
No key, raw provider response, or certificate detail was captured. A later,
separately authorized source-adapter run performed one isolated Google/Docker
repair and retained all eight named volumes; that result does not substitute
for exact-source packaged UI, Azure, recovery-injection, or Podman validation.

At this host's display scaling, the normal-size launcher window clipped its
bottom controls; maximizing the window exposed them. This was a non-blocking UI
follow-up for the later source. All results described in this historical
checkpoint remain authorized unsigned development-workstation evidence only:
the artifact is not a preview, release candidate, or release, and no cdcai
mutation is authorized by that evidence. Later exact-source package results are
recorded in Task-087. The current gates are technical/security review, a newly
integrated normal-user preview package, clean unmanaged-machine feedback, and
later Task-100 signing/representative managed-endpoint qualification. The
current historical evidence is
[`FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md`](./tasks/active/TASK-087/FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md);
the earlier review packet is retained as historical static-review evidence.

Prototype technology selection, August 5: use Python 3.12 with Tkinter and a
conservative PyInstaller one-directory package (`windowed`, `UPX` disabled).
This reuses TowerScout's maintained Python/pytest toolchain and the available
Windows Tk runtime. The validation host has .NET desktop runtimes but no .NET
SDK, so .NET would add an unproven build and maintenance lane during the
time-boxed checkpoint. Revisit the selection if endpoint/deployment policy
requires .NET or rejects Python/PyInstaller applications.

Podman-machine image-pull/build TLS is outside this application-provider flow
and belongs to Task-097.

## Exit/Stop Design Boundary

If the Task-087 launcher proof passes, Task-096 will reuse the launcher's
fixed-target confirmation, runtime validation, sanitized state, and recovery
pattern without exposing Docker or Podman sockets to the application container.
If the proof fails, Task-096 must be re-planned around the current user-run stop
path or another separately approved mechanism.

Expected sequence:

1. User selects Exit/Stop TowerScout in the visible launcher.
2. The launcher explains that TowerScout will stop while saved data remains.
3. User confirms.
4. The launcher validates the exact package and captured runtime profile.
5. The package-local stop path runs for Docker or Podman.
6. The container is removed without deleting named volumes.
7. The launcher shows a final status or manual fallback when it cannot
   complete.

Exact endpoint and lifecycle details remain Task-096 design work.

## Podman Qualification Boundary

Task-097 owns:

- CPU and GPU/CDI qualification.
- Docker-Desktop-free Compose-provider selection and installer fallback.
- Setup, launch, stop, status, logs, asset import, persistence, provider TLS,
  and Exit/Stop checks.
- Managed-network image-pull and source-build TLS investigation.
- A pass/fix/documented-limitation decision before final freeze.

Task-097 must not silently expand the product UI to install Compose providers
or modify Podman-machine trust.

## Dependency Security Boundary

Task-090 and Task-098 completed the 62-alert Trivy baseline classification,
approved remediation, and affected-runtime qualification. PR #51 merged as
`e499b50`. That July 27 closeout remains historical and complete.

GitHub disclosed four additional Dependabot advisories on August 4-5, followed
by reviewed npm advisory `GHSA-5p4m-2wfm-xmqj` entering the blocking audit on
August 7. Task-099 is the separate, narrow release-gate follow-up; it does not
reopen Task-098 or expand into the qualified ML runtime.

The current security boundary is:

1. Loopback publication and content-sniffed custom-image validation protect
   the normal local runtime.
2. Release-model hashes are enforced by default; model upload remains disabled
   by default and requires both an administrator key and approved SHA-256 hash
   when enabled.
3. The selected `torch==2.6.0` / `torchvision==0.21.0` pair is qualified for
   the Task-098 CPU/CUDA boundary.
4. The July 27 closeout left eight medium/low torch advisories visible and
   non-reachable on supported paths. A future upgrade must move torch and
   torchvision together and repeat CPU/CUDA, model-load, output-parity, and
   performance validation.
5. Task-099 updated runtime `aiohttp` from `3.14.2` to `3.14.3` for alert
   `#74` and development-only transitive `ip-address` from `10.2.0` to
   `10.3.1` for alerts `#72`, `#73`, and `#75`.
6. Task-099 also updated development-only transitive `js-yaml` from `4.3.0`
   to `4.3.1` for `GHSA-5p4m-2wfm-xmqj`; the repository inventory had not
   assigned that new audit finding an alert number at the August 7 check.
7. PR #68 merged the narrow fixes as `f460445`; PR #69 merged the root graph
   refresh as `0133b50`. Graph run `31510493332` removed stale
   `aiohttp==3.14.2`, alert `#74` closed without dismissal, and the repository
   returned on August 11 to the eight documented medium/low torch residuals
   with no open critical/high alert at that closeout.
8. All-severity SARIF reporting remains advisory, while new or reintroduced
   critical/high dependency findings are blocking unless covered by a narrow,
   unexpired exception. The Task-099 discovery confirms that ratchet is
   operating as designed.
9. GitHub opened alert `#76` on August 12 for high-severity
   `extract-zip==2.0.1` in the development-only path
   `puppeteer@24.19.0 -> @puppeteer/browsers@2.10.8 -> extract-zip@2.0.1`.
   The dependency is not copied into the product runtime image or end-user ZIP,
   but the browser-install test path can execute it and the blocking npm audit
   fails. No patched `extract-zip` release is currently listed.
10. Backlog Task-101 owns supported-path reachability and a validated
    remediation or authorized residual-high disposition. PR #67 review may
    continue, but merge, preview publication, optional architecture work, and
    candidate acceptance remain behind that gate.

## Task Dependency Flow

```text
TASK-095 Phase A rebaseline
        |
        v
TASK-090 bounded security investigation [COMPLETE]
        |
        v
TASK-098 dependency-security remediation/disposition gate [COMPLETE]
        |
        +---------------------------+
        |                           |
        v                           v
TASK-087 universal provider   TASK-099 August advisory
TLS repair [IN PROGRESS]      follow-up [COMPLETE]
        |                           |
        |                           v
        |                     TASK-101 extract-zip
        |                     gate [BACKLOG]
        v                           |
TASK-096 user Exit/Stop             |
        |                           |
        +---------------------------+
        |
        v
TASK-097 Podman CPU/GPU qualification
        |
        +--> TASK-058 only if schedule and risk gates pass
        |          |
        |          +--> TASK-059 only if remaining margin is safe
        |
        v
TASK-091 pre-sign harness + TASK-092/093 docs and recovery
        |
        +--> TASK-094 only if pilot/support evidence justifies it
        |
        v
Satisfactory unsigned preview package
        |
        v
TASK-100 production signing + representative managed-endpoint qualification
        |
        v
Signed candidate freeze -> owner qualification -> TASK-089 adoption/handoff
```

Task-095 Phase B spans the remaining work to keep governance, backlog, and
handoff material current. Task-098 is separately scoped from Task-090 so the
investigation cannot hide dependency upgrades, CPU/CUDA compatibility work, or
four-profile regression effort. Task-099 preserved the same governance
principle for post-closeout disclosures and cleared its scoped dependency-
security gate on August 11. Task-087 continues under its own remaining
qualification gates. Task-101 is the new blocking high-severity dependency
follow-up and does not reopen the dated Task-099 record. Task-100 remains
backlog work until October and the ADR-019 satisfactory-package entry decision.

## Validation Strategy

Automated validation covers unit, route, frontend contract, packaging, and
security checks where practical. Manual evidence remains required for:

- Windows package behavior
- Docker and Podman runtime behavior
- CPU/GPU execution
- managed-network provider TLS
- live-provider browser behavior
- asset-backed package smoke
- owner-operated release and recovery rehearsal

No runtime-dependent validation should begin until the user has been told which
runtime is needed and has confirmed Docker Desktop and/or Podman is running.

## Safety Boundaries

- Do not mount Docker or Podman control sockets into the application container.
- Do not accept browser-supplied command text or executable paths.
- Do not record provider keys, helper tokens, local certificate details, raw
  browser traces, private AOIs, or unsanitized logs in repository evidence.
- Do not delete named volumes during normal stop, upgrade, or container
  replacement.
- Do not mutate `v0.1.2` or publish `v0.1.3` final prematurely.
- Do not relabel Task-087 validation artifacts as previews, mark an unsigned
  preview `Latest`, or give unsigned bytes a `v0.1.3-rc.N` identity.
- Do not test unsigned previews on managed endpoints or instruct testers to
  disable Windows security controls.
- Do not change cdcai before explicit owner authorization.
