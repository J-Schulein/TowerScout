# TowerScout Windows Launcher Prototype

This directory contains the Task-087 visible Windows launcher prototype. The
current UI reports TowerScout/package status, probes Docker and Podman with
fixed read-only commands, identifies the selected package/runtime profile,
displays a non-mutating TLS repair plan for Google Maps or Azure Maps, and can
start the controlled native repair only after exact-target preparation and a
typed `REPAIR TLS AND RESTART` confirmation.

## Technology decision

Python 3.12 with Tkinter was selected over .NET for this time-boxed proof.
TowerScout already uses Python and pytest, Tkinter is available on the
validation host, and the application can be packaged as a conservative
one-directory PyInstaller build. The host has .NET desktop runtimes but no
.NET SDK, so a .NET implementation would first add a new toolchain and
maintenance lane. This decision should be revisited if organizational policy
requires .NET or rejects Python/PyInstaller applications.

## Security boundary

The prototype:

- creates no listener and accepts no browser operation;
- imports and starts none of the dormant Task-087 helper files;
- launches no PowerShell and uses no execution-policy bypass;
- uses no shell command strings, detached workers, runtime sockets, admin
  rights, or Windows trust-store writes;
- uses only fixed Docker/Podman arguments, exact targets, bounded timeouts, and
  sanitized results for status and controlled repair;
- creates those fixed CLI children with `CREATE_NO_WINDOW` on Windows so the
  windowed PyInstaller parent does not depend on console attachment;
- keeps raw runtime output, executable paths, local package paths, provider
  keys, certificate details, and exception text out of the UI and evidence;
- uses a package-scoped Windows session mutex plus an in-process operation
  guard to prevent duplicate launcher operations.

The existing Task-086 command-based repair remains unchanged and available.

## Controlled-repair implementation

`towerscout_launcher/repair.py` implements the bounded native continuation:

- exact package, provider, engine, GPU mode, port, Compose project, image, and
  digest binding;
- prepared, confirmed, applying, restarting, succeeded, rejected, and
  recovery-required states;
- exact confirmation before mutation;
- private in-memory certificate material with redacted representations;
- native Windows TLS-chain classification for the fixed Google/Azure hosts;
- rejection of missing or ambiguous trust-chain candidates;
- exact Compose-label/container, image, digest, runtime, GPU, and loopback-port
  validation immediately before mutation;
- private staging with prior certificate/bundle and `.env` backup;
- provider verification through the staged combined CA bundle before `.env`
  changes;
- atomic `.env` update that preserves unrelated settings and line endings;
- same-project Compose recreation without `-v` or `--volumes`, followed by
  provider, runtime, digest, and readiness verification;
- bounded rollback and force-recreation with the restored environment after a
  staging, restart, or readiness failure;
- explicit rejection of missing, ambiguous, or Docker Desktop-backed Podman
  Compose providers; and
- a coordinator mutation gate that is off by default; the visible prototype
  explicitly enables it behind the typed-confirmation flow.

The first direct Task-086 script-adapter proof was rejected on the development
workstation because ordinary no-bypass PowerShell script execution is blocked
by effective policy. The launcher does not add `-ExecutionPolicy Bypass`, use
the `.cmd` wrappers, or work around that policy. The native Docker transaction
passed failure-injection tests and one developer-invoked isolated live run on
project `towerscout-task087-full-4327fb6`: the container returned healthy
`setup_required`, both CA environment settings persisted, and all eight named
volumes remained present. This used current source code, not a newly built or
signed launcher executable.

Podman remains fail-closed on this workstation because `podman compose` does
not currently have an approved non-Docker-Desktop provider. Task-087 will not
install or silently substitute that separate dependency.

The integrated UI was built from clean source `0901cc5b8a2e` and packaged as
an exact-source launcher-policy artifact. Its ZIP sidecar, inventory, internal
hashes, source ref, and capability/authorization fields passed direct archive
verification, and the executable opened responsively against the non-runnable
sentinel. The package truthfully records native TLS mutation capability while
keeping `execution_authorized=false`; its missing release image identity makes
repair fail closed.

A clean full-runnable package remains blocked locally because the normal
package generator is PowerShell and ordinary no-bypass script execution is
blocked by effective policy. Do not bypass that policy or pair the new launcher
with an older-source base. Exact-source full-package UI repair, Docker/Azure,
approved Podman-provider, recovered CI, signing, and representative
managed-endpoint testing remain open.

## Source validation

Run from the repository root:

```powershell
python -m pytest tests/unit/test_windows_launcher.py -q -p no:cacheprovider
python -m compileall -q launcher/towerscout_launcher `
  launcher/inspect_build.py launcher/build_provenance.py `
  launcher/package_validation.py
```

Do not run an unsigned launcher executable on a managed endpoint as an
endpoint-security experiment.

## Production-shaped build

Create a clean build environment, install the pinned build dependency, and run:

```powershell
python -m pip install -r launcher/requirements-build.txt
launcher/build.cmd
python launcher/inspect_build.py dist/TowerScoutLauncher
```

The spec intentionally uses a windowed one-directory build with `upx=False`.
`build.cmd` runs the structural inspection after PyInstaller and refuses to
write provenance unless the repository is at a clean, full Git commit. It
writes `BUILD-PROVENANCE.v1.json` beside the executable with the source ref,
the pinned build-requirements SHA-256, the executable SHA-256, and a
deterministic path/content hash of the complete launcher tree excluding that
provenance file. The built directory must be placed as a package-local
`launcher` directory so the executable can verify the adjacent package root.
The existing release package generator remains unchanged.

## Launcher-policy validation-only package assembly

After committing the accepted source and building the launcher from that clean
commit, assemble the separate policy-validation artifact with:

```powershell
python launcher/package_validation.py `
  --package-kind launcher-policy `
  --launcher-build-dir dist/TowerScoutLauncher `
  --output-dir dist/task-087-validation
```

The assembler refuses a dirty Git worktree and rejects a launcher whose
recorded source ref, build requirements, executable, or complete build-tree
hash does not match the requested commit and current source tree. It records
the full commit in both `SOURCE.txt` and `validation-manifest.v1.json`. It
creates `Task-087-validation-<12-character-SHA>.zip`, a SHA-256 sidecar, and
per-file checksums. The directory, ZIP, and sidecar are fully staged before
any final artifact is published. The package contains the one-directory
launcher, a non-runnable Compose discovery sentinel, non-secret identity
defaults, and explicit validation-only notices. It intentionally excludes the
TowerScout application stack, runtime launch scripts, Task-087 helper scripts,
live `.env` files, provider keys, certificates, and model/data assets.

The validation manifest records this shape as `launcher-policy`. It is
not interchangeable with the runnable full-package validation shape below,
even though both use the same exact-source logical identity.

## Full-package functional-validation assembly

The explicitly authorized development-workstation test uses the normal
digest-pinned TowerScout control package as its runnable base. Generate that
base from the same clean commit with `scripts/package-release.ps1 -NoZip`,
then compose it with the inspected launcher:

```powershell
python launcher/package_validation.py `
  --package-kind full-runnable `
  --base-package-dir dist/<base-output>/towerscout-Task-087-validation-<12-character-SHA> `
  --launcher-build-dir dist/TowerScoutLauncher `
  --output-dir dist/<full-validation-output> `
  --engine docker `
  --gpu off `
  --port 5008 `
  --compose-project towerscout-task087-full-<12-character-SHA>
```

The full assembler verifies the base package identity, exact source ref,
existing content hashes, and the launcher's exact-source build provenance
before making a copy. It adds the inspected launcher, an isolated non-secret
runtime profile, launcher provenance, and explicit
`full-runnable` validation metadata; updates the generated ZIP
fields; and recomputes every package hash, ZIP, and ZIP sidecar. It rejects
symbolic links, a live `.env`, credential/certificate files, and every dormant
host-helper artifact. The Task-086 user-run provider TLS repair scripts remain
present as the supported fallback.

Neither artifact is an RC or end-user package. Do not tag it, publish it as a
GitHub Release, distribute it through cdcai, or merge based on its existence.
Unsigned functional execution requires separate project-lead authorization
and is limited to the development-workstation test recorded in Task-087. An
approved signing owner must sign and timestamp the launcher before
representative managed-endpoint policy testing.

The prototype build-tool and bundled-runtime inventory is documented in
[`DEPENDENCY-PROVENANCE.md`](./DEPENDENCY-PROVENANCE.md). It is review evidence,
not a release SBOM or legal approval.

## Signing and managed-endpoint gate

The intended path is the organization-approved Windows Artifact Signing or
equivalent code-signing service. Signing ownership is currently unresolved.
Before managed-endpoint testing or candidate inclusion:

1. Record the signing owner, certificate custody, timestamp service, and
   revocation/rotation procedure.
2. Build from the accepted source ref in a controlled Windows build job.
3. Sign and timestamp `TowerScoutLauncher.exe` before the release ZIP/checksum
   is finalized. Record the approved policy for provenance checking or
   re-signing the bundled third-party DLL/PYD files; the prototype produces no
   other project-owned native binary.
4. Verify required signatures after packaging and record the signed-file
   inventory without local paths or certificate subjects/thumbprints.
5. Run the production-shaped signed artifact under representative managed
   Defender, AMSI, ASR, and application-control policy without exclusions or
   bypasses.

Required CI work remains: a Windows build job, dependency/hash provenance,
malware/policy scanning, approved signing integration, post-signature
verification, artifact checksums, and release-manifest/SBOM integration.
