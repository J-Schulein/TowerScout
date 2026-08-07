# Task-087 Non-Mutating Launcher Review Evidence

**Date**: August 5, 2026
**Branch**: `feature/task-087-windows-launcher-prototype`
**Base**: verified `origin/main` at `4b93caf`
**Draft PR**: [#67](https://github.com/J-Schulein/TowerScout/pull/67)
**Disposition**: Ready for technical review; not approved for merge, release,
unsigned execution, or mutation

> **Historical checkpoint / supersession note:** This packet preserves the
> pre-execution static-review status, including every `NOT RUN` statement and
> the original static artifact facts. It is superseded **only for later
> functional-validation status** by
> [FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md](FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md),
> which records the project-lead-authorized unsigned development-workstation
> sequence through exact commit `4327fb6`. That later evidence does not make
> the package a release candidate, approve distribution or merge, satisfy the
> signing/managed-endpoint gates, or authorize TLS/helper mutation.

## Executive Summary

The branch implements the ADR-018 non-mutating Windows launcher slice in
Python 3.12/Tkinter with a windowed PyInstaller one-directory package. It shows
package, runtime, and readiness state and creates a fixed Google/Azure TLS
repair preview. It does not bind a listener, activate the dormant helper, run
PowerShell, accept command text or executable paths, mutate container/runtime
state, inspect certificates, or change trust.

Review found one substantive hardening item: the fixed loopback readiness read
could otherwise inherit environment proxy configuration. The opener now uses
an empty proxy map and rejects redirects, with focused regression assertions.
No other blocking source or functional finding was identified inside the
approved preview-only boundary.

## Review Scope

- `launcher/towerscout_launcher/`: visible UI, public state models, package and
  runtime discovery, readiness, duplicate-operation coordination, entry point
- `launcher/TowerScoutLauncher.spec`, `build.cmd`, `inspect_build.py`, and
  `package_validation.py`: conservative build, static inspection, and a
  separate exact-source validation-only assembler
- `launcher/requirements-build.txt` and `DEPENDENCY-PROVENANCE.md`: exact
  observed build pins and prototype provenance inventory
- `tests/unit/test_windows_launcher.py`: fixed-command, redaction, identity,
  duplicate-operation, readiness, preview, packaging, and forbidden-source
  contracts
- Task-087 requirements, design, decision, current/backlog state, pivot review,
  roadmap, and implementation record

No external helper source was inspected or copied. No Dockerfile, Compose,
release-package generator, provider key, frozen `v0.1.2` asset, cdcai state, or
PR #64 activation path changed.

## Validation Matrix

| Check | Result |
| --- | --- |
| Focused launcher pytest | PASS - 16 tests |
| Existing license/manifest/package/publish pytest | PASS - 14 tests at repository checkpoint |
| Python compilation | PASS |
| Blocking flake8 syntax/undefined-name gate | PASS |
| Black 25.12.0 | PASS under installed Python 3.13 |
| mypy | PASS - 7 source files |
| Bandit | PASS |
| Exact build pins versus isolated build environment | PASS |
| PyInstaller 6.15.0 exact-source build | PASS |
| Static package inspector | PASS |
| Validation-only assembler controls | PASS - source, boundary, and hash tests |
| Agent-work validators and `git diff --check` | PASS |
| Unsigned executable or GUI smoke | NOT RUN by policy |

CI-profile flake8 still reports three advisory discovery-function complexity
warnings and Black's known E203 spacing disagreement. They are recorded as
prototype maintainability debt and do not affect the repository's blocking
syntax/undefined-name gate.

## Static Artifact Evidence

- Windows 11 AMD64 GUI, one-directory shape
- UPX disabled and no UPX marker
- 943 files totaling 26,426,570 bytes
- four expected TowerScout launcher modules present
- generated Tcl/Tk license present
- no packaged `.ps1`, `.cmd`, `.bat`, `.pem`, `.key`, or `.env` file
- Authenticode status `NotSigned`

The artifact was inspected only. It was not executed.

The validation-only assembler deliberately does not call the existing release
package generator. It emits a no-services Compose discovery sentinel and
excludes the application stack, runtime launch scripts, dormant helper,
credentials, certificates, and model/data assets. Its actual ZIP identity and
hashes are recorded out-of-tree and on Draft PR #67 after assembly from the
final clean source checkpoint so the evidence does not change that source.

## Live Read-Only Evidence

After the project lead confirmed both engines were running, the exact source
reported Docker and Podman as installed, running, and reachable through fixed
read-only JSON probes. Because both were reachable and the source template has
no engine hint, the launcher required an explicit fixed-enum engine choice.
TowerScout itself was not reachable at the source template's default package
port. Raw runtime output and executable/local paths were not recorded.

## Open Gates And Reviewer Questions

Blocking before distribution or managed-endpoint execution:

1. Assign the organization-approved signing owner and service, certificate
   custody, timestamp, revocation, and third-party DLL/PYD policy.
2. Generate file-level hashes and an SBOM from a controlled accepted-source
   build; integrate Python, Tcl/Tk, PyInstaller, hooks, and DLL notices with the
   release compliance set.
3. Obtain owner/legal review of redistribution and notice wording. This packet
   is not legal approval.
4. Sign and verify the production-shaped artifact, then run GUI and policy
   tests on a representative managed endpoint without exclusions or bypasses.
5. Decide whether the three advisory discovery-function complexity findings
   should be reduced before acceptance or tracked as bounded prototype debt.

Task-086 remains the supported fallback. Task-096 Stop and all TLS/certificate,
restart, and trust mutation remain separately gated.

## Validation-Only Repository Boundary

- Publish this bounded source only as a Draft PR against `main`.
- Build the validation artifact only from the exact accepted commit and name it
  `Task-087-validation-<short-SHA>`.
- Do not create a tag, GitHub Release, `v0.1.3-rc.N` identity, public asset, or
  cdcai change for the validation artifact.
- Keep the Draft PR unmerged while signing and managed-endpoint evidence is
  incomplete.
- On Stop, close the code PR unmerged and preserve the decision/evidence through
  a documentation-only PR from current `main`; no launcher-code revert is
  required.

## Suggested Commit Checkpoints

1. `docs(task-087): record launcher feasibility pivot`
2. `feat(task-087): add non-mutating Windows launcher`
3. `test(task-087): validate launcher and package boundaries`
4. `docs(task-087): add prototype provenance and review evidence`

No commit, push, PR publication, merge, signing, or release action is included
in this review-preparation step.

## Suggested PR Summary

> Implements the ADR-018 preview-only Windows launcher proof with fixed
> Docker/Podman status checks, package/readiness identity, duplicate-operation
> controls, and Google/Azure repair preview. The branch adds conservative
> windowed PyInstaller packaging, focused safety tests, exact build pins, and
> review/provenance evidence while keeping every helper, mutation, signing,
> managed-endpoint, release, and cdcai gate closed.
