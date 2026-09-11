# Task-087 Full-Package Functional Validation Evidence

**Validation Window**: August 5-6, 2026

**Branch**: `feature/task-087-windows-launcher-prototype`

**Initial Source Commit**: `7a7aecc7470d7ae27bbacaadb9d0116e70845e9f`

**Latest Exact Source Commit**:
`4327fb6288f4f8c83202f548a2ba7cb2dcf9bab6`

**Disposition**: PASS for the authorized unsigned development-workstation
functional proof, with the known managed-network Google TLS condition and one
display-scaling usability follow-up recorded below. The initial `7a7aecc`
endpoint-policy failure and `31c41ec` launcher timeout remain preserved as
historical runs. The exact-source `4327fb6` full-runnable package passed
pristine-package, fresh Docker first-run, reboot persistence, repeated launcher
refresh, preview-only, and provider-error-classification validation. This is
not a release candidate, distribution approval, or signed managed-endpoint
qualification.

## Boundary

The project lead authorized unsigned functional execution on the development
workstation. The validation used an isolated Compose project, alternate
loopback port, clean extraction directory, fresh named volumes, and the pinned
pilot image/asset identities. The frozen release, existing TowerScout instance,
`main`, and cdcai were not changed.

No Defender exclusion, AMSI bypass, execution-policy bypass, administrator-only
workaround, provider key, certificate detail, raw network trace, or
unsanitized log is recorded here.

## Initial `7a7aecc` Artifact Evidence

- Control ZIP SHA-256:
  `e4b8f3d3de5f2ff5a570d55cf1e3e50c3ab1a75a1af1cb84ef49c9c1d165ca92`
- Asset bundle SHA-256:
  `00599cc4fe9f2bdb4708c669d7c3d9a8a570a0c3b547bc5c317026196c7bacbb`
- Control and asset sidecars passed filename and hash verification.
- Extracted package content checksums passed with no unsafe ZIP paths.
- The package contained no live `.env`; first-run setup created its isolated
  configuration from `.env.example`.

## Initial `7a7aecc` Functional Results

| Check | Result |
| --- | --- |
| Docker and Podman runtime discovery | PASS |
| Isolated asset import with hash verification | PASS |
| Application health endpoint | PASS |
| Readiness state | PASS - `setup_required` |
| Asset status | PASS - `ok`, zero missing/corrupt |
| ML runtime status | PASS - `ok`, CPU selected |
| Unsigned launcher execution | PASS |
| Launcher package/runtime/readiness profile | PASS |
| Defender/Code Integrity block against launcher | NONE OBSERVED |
| Normal setup command completion | FAIL - AMSI blocked dormant helper import |
| Package stop command qualification | FAIL - same dormant helper dependency |

The application container remained healthy after asset import. The compiled
launcher opened visibly and reported that TowerScout was reachable and required
setup. The endpoint failure occurred when ordinary PowerShell launch/stop code
unconditionally loaded `scripts/lib/TowerScoutHostHelper.ps1`, even though the
launcher proof does not require that helper.

## Decision And Remediation At `7a7aecc`

- Do not bypass the endpoint control.
- Remove the dormant helper from normal `launch.ps1` and `stop.ps1` execution.
- Exclude all host-helper scripts and its support page from the end-user
  release package.
- Keep the Task-086 guided user-run TLS repair scripts available.
- Retain dormant helper source temporarily as historical/review material only.
- Rebuild from a new exact committed source identity and repeat this test.

## Cleanup

Only the isolated validation launcher, container, and network were stopped.
Validation named volumes were preserved for evidence/recovery. The existing
TowerScout instance remained healthy and unchanged.

## Chronological Follow-Up Evidence

### Helper-Free `31c41ec` Validation

Commit `31c41ec366c2` removed the dormant host helper from the ordinary
end-user launch and stop paths and excluded the helper artifacts from the
validation package while retaining the reviewed Task-086 guided repair
scripts. The rebuilt package completed normal setup and reached the
`setup_required` application flow. A user-entered Google Maps key reached the
known managed-network TLS validation condition; no key, provider response,
certificate detail, or unsanitized log was retained.

The launcher's first opening reported the runtimes correctly. After the
launcher was closed and reopened, its fixed Docker status probe repeatedly
timed out after five seconds even though Docker Desktop and the application
container remained healthy. The behavior persisted after Windows and Docker
restarts, establishing a repeatable launcher subprocess problem rather than a
port conflict or unavailable Docker daemon.

### Windows Subprocess Diagnosis And `18082cf` Fix

A bounded A/B diagnostic held the fixed read-only Docker probe constant and
changed only the Windows child-process creation mode. Adding
`CREATE_NO_WINDOW` made the probe complete successfully; environment and DLL
sanitation were not required. Commit `18082cf` applied that Windows-only flag
to launcher runtime discovery, retained `shell=False`, fixed arguments,
captured output, a null standard input, and the five-second limit, and added a
sanitized timeout result. It did not add runtime, trust, certificate, helper,
or TLS mutation.

Regression coverage verifies Windows and non-Windows creation flags, the full
subprocess contract, and sanitized timeout handling. The final focused and
adjacent validation run passed 36 tests. A broader selected run produced 183
passes and 19 failures; all 19 failures were the pre-existing direct-execution
tests for `TowerScoutHostHelper.ps1` blocked by endpoint AMSI policy. No bypass
was attempted, and six selected static/decoupling/helper-boundary tests passed.
Compilation, the blocking flake8 gate, Black 25.12.0 under Python 3.13, mypy,
Bandit, and `git diff --check` also passed.

### Exact `4327fb6` Build And Full-Runnable Package

The windowed one-directory launcher was rebuilt from the clean exact commit
`4327fb6288f4f8c83202f548a2ba7cb2dcf9bab6` with PyInstaller 6.15.0 and
Python 3.12.5. Build provenance bound the executable and complete launcher
tree to that source:

- launcher executable SHA-256:
  `e1abd49b2c7e4e1c8de86aa4dd06bd8572520349ecea8fbaba6e75e52c10c868`
- launcher tree SHA-256:
  `fc4a150647822c950480dddc2f65bfc9ae5e1616c6513dd3b0532052e25b7380`
- build-requirements SHA-256:
  `1a846c3559bcb0f2673b0d7860ab007bc5d1144b9c886065bee431bcc1aba078`
- launcher tree inventory: 944 files totaling 26,427,236 bytes
- Authenticode status: `NotSigned`

The exact-source full-runnable package identity is
`towerscout-Task-087-validation-4327fb6288f4`. It targets Docker, CPU, loopback
port 5008, and the isolated Compose project
`towerscout-task087-full-4327fb6`. The pinned image is
`ghcr.io/j-schulein/towerscout:v0.1.2-cpu` at digest
`sha256:86c54bd723ff970f70f0883397a1f2f804db796507a461a5718aeab57258afe8`.
The package was explicitly marked `full-runnable`, validation-only, and not a
release candidate; host-helper and launcher TLS-mutation capabilities remained
false.

- control ZIP SHA-256:
  `8c8e5a69c702836bf842d63c6407621e124a9cc2dae170ab46dbc9259ab7f673`
- asset ZIP SHA-256:
  `00599cc4fe9f2bdb4708c669d7c3d9a8a570a0c3b547bc5c317026196c7bacbb`
- ZIP inventory: 1,013 entries, including `SHA256SUMS`
- extracted checksum inventory: 1,012 records and 1,012 recorded files, with
  zero missing, extra, mismatched, or reparse-point entries
- manifest, provenance, and runtime consistency checks: 22 of 22 passed
- forbidden-artifact and populated sensitive-value scan: zero findings

The control and asset ZIPs were copied into a pristine simulated download
directory. Both adjacent sidecars passed, and the extracted package's exact
inventory passed before any setup-created file existed.

### Fresh Docker First Run From `4327fb6`

Read-only `-VerifyOnly` preflight passed for the Docker CLI, daemon, Compose,
free port 5008, and locally available pinned image without changing runtime
state. The actual fresh setup then exited successfully: it created `.env` only
after the pristine-package check, staged and hash-verified the assets, created
the unique Compose project and eight new named volumes, imported assets with
no missing, corrupt, or optional-missing items, and restarted the isolated
stack.

The resulting container was healthy on `127.0.0.1:5008`. Sanitized status
fields reported readiness/config state `setup_required`, asset status `ok`,
one inference engine, selected device `CPU`, device policy `cpu`, PyTorch
flavor `cpu`, and the exact pinned image digest above. The setup did not invoke
TLS repair or the dormant host helper. Existing TowerScout stacks and their
volumes were not changed.

The exact packaged launcher process opened visibly. At this host's current
Windows display scaling, its normal-size window clipped the lower controls;
maximizing the window exposed both buttons. This did not block the bounded
functional proof, but it is an open usability item to correct or explicitly
disposition before a production-shaped signed build.

### Reboot Persistence And Manual Checks - August 6

Windows was restarted before the manual launcher sequence. After Docker
Desktop returned, the unique Compose project had automatically resumed its
same container on `127.0.0.1:5008`. Independent sanitized checks reported:

- container health `ok`
- readiness/config state `setup_required`
- asset status `ok`, with zero missing and zero corrupt assets
- selected device and PyTorch flavor `cpu`
- the exact pinned image digest
- neither Google nor Azure configured before the key-validation attempt

The control ZIP and launcher executable still matched their recorded hashes
after the reboot. The exact launcher reopened and again displayed the correct
`4327fb6288f4` package, Docker/CPU/port-5008 profile, reachable application,
and `setup_required` state.

The project lead then completed the remaining human-observed checks:

1. **PASS** - Docker remained reported as running and reachable after all
   three manual **Refresh status** operations.
2. **PASS** - The Google Maps/Docker TLS repair preview identified the exact
   package and CPU/port-5008 profile and explicitly stated that it did not
   inspect certificates, change trust, stop or restart a container, or run the
   dormant helper.
3. **PASS WITH EXPECTED MANAGED-NETWORK CONDITION** - A Google Maps key was
   entered only in the Setup Wizard. Validation returned the sanitized
   category `tls_ca_untrusted` and directed the user to the existing Task-086
   command:
   `.\scripts\repair-provider-tls.cmd -Provider google -Engine docker -Gpu off`.
   No key, raw provider response, certificate detail, browser/provider
   screenshot, or unsanitized log was collected or retained in evidence.

This result confirms that the launcher/runtime subprocess correction is stable
across refresh and reboot, the preview remains non-mutating, and the application
classifies the known managed-network Google TLS failure safely. It does not
prove that a TLS repair succeeds, because no repair was authorized or run.

No signing, managed-endpoint policy acceptance, release publication, merge,
TLS repair, certificate inspection, trust change, helper activation, or cdcai
change is established by this functional validation.
