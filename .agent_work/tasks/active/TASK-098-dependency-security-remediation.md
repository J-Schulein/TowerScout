# TASK-098: Dependency Security Remediation And Release Gate

**Status**: IN_PROGRESS / SLICES A-C COMPLETE; SLICE D/G READY
**Priority**: HIGH
**Type**: C (Security Remediation / Runtime Qualification)
**Estimated Effort**: Mandatory slices 4-8 days; full coordinated hardening
6-11 days, plus required GPU/runtime host availability
**Selected For Planning**: July 23, 2026

## Objective

Implement and qualify the dependency, local-runtime, custom-image, and model
trust remediations approved from Task-090. Close every release-blocking
critical/high finding before Task-087 resumes, or obtain the explicit,
time-bounded project-lead/cdcai-owner residual-risk decision required by
`SEC-001`.

This file preserves Task-098 as a separately governed implementation and
validation task. Creating the task record does not authorize dependency or
runtime changes.

## Task-090 Inputs

- [Task-090 control record](./TASK-090-runtime-custom-image-dependency-security.md)
- [62-alert disposition](./TASK-090/alert-disposition.md)
- [Proposed remediation scope and release gate](./TASK-090/remediation-scope.md)
- [July 23 readiness assessment](../../context/analysis/GITHUB-CODE-SCANNING-READINESS-ASSESSMENT-2026-07-23.md)

Task-090 identified five release-blocking alerts, one required-hardening alert,
and an all-interface Compose port publication that conflicts with the
single-user local-runtime boundary. The exact target directions, estimates,
and work slices are preserved below as the approved implementation baseline.
Exact resolved versions and the final ML pair remain subject to the
compatibility evidence required by each slice.

## Approval Record

Complete this record when the scope decision is made. Approval authorizes only
the selected slices and candidate evaluation described here; it does not
pre-approve a residual risk or the final ML pair before compatibility evidence
exists.

| Decision field | Current value |
| --- | --- |
| Scope decision | APPROVED by the project lead on 2026-07-23, subject to the non-regression contract below |
| Approved mandatory slices | A-D and G |
| Approved coordinated-hardening slices | E and F, only when compatibility and non-regression gates pass |
| Fixed dependency targets | Target directions for A-C approved; exact resolved versions must be recorded |
| ML candidates and selection criteria | Approved as proposed; final pair/wheel flavor is selected during Slice D |
| Residual-risk path | None granted; use the decision packet below only if required |
| Project-lead approval/date | APPROVED in project chat, 2026-07-23, with explicit non-regression caveat |
| cdcai-owner boundary | Not required to start fork-side remediation; required for residual critical/high acceptance, changes to `cdcai/TowerScout`, or official cdcai adoption |

## Requirements

- WHILE Task-098 approval is pending, THE PROJECT SHALL NOT change dependency
  pins, dismiss alerts, start runtime qualification, modify the frozen
  `v0.1.2` release, or mutate `cdcai/TowerScout` under this task.
- WHEN the project lead approves the Task-098 scope, THE PROJECT SHALL
  implement only the approved remediation slices and record any later scope
  change before execution.
- WHEN the normal TowerScout package publishes its application port, THE
  PACKAGE SHALL bind the host port to loopback unless a separately approved
  deployment profile explicitly requires broader exposure.
- WHEN TowerScout accepts a custom image, THE SYSTEM SHALL verify that its
  content is an approved JPEG, PNG, or TIFF format before Pillow selects a
  decoder.
- WHEN Pillow, Waitress, or aiohttp is upgraded, THE PROJECT SHALL validate
  custom-image parsing, WSGI startup/readiness, and Google/Azure provider
  downloads against the approved target versions.
- WHEN PyTorch or torchvision is changed, THE PROJECT SHALL treat the package
  pair, CPU/CUDA wheel flavor, Docker image, release scripts, model loading,
  and CPU/GPU inference as one coordinated compatibility decision.
- WHEN release models are imported or loaded, THE SYSTEM SHALL enforce the
  approved checksum/trusted-model controls by default and keep model upload
  disabled by default.
- BEFORE the first Task-098 implementation change, THE PROJECT SHALL capture a
  reproducible functional, detection-output, startup, and performance baseline
  using the same trusted fixtures, models, host, and runtime profiles that will
  be used for comparison.
- AFTER each remediation slice, THE PROJECT SHALL run its focused tests and
  the shared production-critical workflow gate before stacking another slice.
- IF a candidate changes a user-visible workflow, detection/export result,
  supported runtime behavior, or exceeds the predeclared performance tolerance,
  THEN THE PROJECT SHALL stop, isolate or revert the slice, and investigate
  before continuing.
- IF a mandatory critical/high remediation cannot be qualified safely, THEN
  THE PROJECT SHALL stop later runtime work and obtain the written
  project-lead/cdcai-owner decision defined by Task-090.
- AFTER mandatory remediation is qualified, THE PROJECT SHALL reconcile the
  GitHub alert baseline, preserve all-severity SARIF reporting, and add the
  approved blocking CI control for new critical/high findings or unexpired,
  narrowly scoped exceptions.

## Approved Work Slices

The following baseline comes from Task-090 and is authorized by the approval
record above, subject to the non-regression contract and slice stop rules:

| Slice | Current baseline | Proposed target direction | Estimate | Gate |
| --- | --- | --- | ---: | --- |
| A: Local and input boundary | All-interface Compose publish; extension-only image validation | Bind the normal package to `127.0.0.1`; enforce JPEG/PNG/TIFF content signatures before Pillow; retain the 50 MiB cap and rate limit | 0.5-1 day | Mandatory |
| B: Narrow runtime patches | Pillow 12.2.0; Waitress 3.0.0 | Pillow 12.3.0; Waitress >=3.0.1 | 0.5-1 day | Mandatory |
| C: Provider client | aiohttp 3.9.3 | aiohttp 3.14.2; minimum alert fixes converge at 3.14.1 | 0.5-1 day | Mandatory |
| D: ML runtime | torch 2.2.1; torchvision 0.17.1; CPU/CUDA 12.1 package paths | Evaluate at least torch 2.6.0 + torchvision 0.21.0 and a currently supported pair; select one pair and its CPU/CUDA wheel flavors from compatibility evidence | 2-4 days plus GPU hosts | Mandatory or explicit residual-risk decision |
| E: Geospatial | Fiona 1.9.6/GDAL 3.6.4; GeoPandas 0.14.3 | Select stable Fiona >=1.10.1 and GeoPandas >=1.1.2 together | 1-2 days | Required hardening if compatibility passes |
| F: Config/web framework | python-dotenv 1.0.0; Flask 3.0.2 | python-dotenv 1.2.2; Flask 3.1.3 | 0.5-1 day | Required hardening if compatibility passes |
| G: Model trust | Runtime hash verification defaults off; model upload defaults off | Verify release-model hashes by default; preserve upload-off default; constrain any trusted-model override to loopback and trusted files | 0.5-1 day | Mandatory with the ML decision |

Approval must record the selected slices and fixed targets for Slices A-C.
For Slice D, approval records the candidate set and selection criteria; the
final torch/torchvision pair, CUDA flavor, and affected package-script changes
are recorded after the compatibility spike and before migration. Slices E-F
may be approved conditionally rather than forcing incompatible upgrades.

## Required Regression Matrix

| Surface | Required evidence |
| --- | --- |
| Static dependency resolution | Clean Python 3.11 and 3.12 installs; exact resolved versions; no incompatible wheel or unintended source-build fallback |
| Google provider | TLS-verified tile and metadata downloads; header parsing; redirect; retry/timeout; cancellation; sanitized errors |
| Azure provider | TLS-verified tile and attribution/metadata downloads; header parsing; redirect; retry/timeout; cancellation; sanitized errors |
| Custom image | Valid JPEG/PNG/TIFF; renamed EPS/JPEG2000/McIdas rejection before Pillow; malformed and oversized rejection; output drawing |
| Waitress | Startup/readiness; loopback-binding contract; request-size cap; malformed and disconnected-client regression where practical |
| EfficientNet | Known-checksum model loads with `weights_only=True`; representative-crop inference on CPU and CUDA |
| YOLO | Vendored full-object checkpoint loads only from a trusted, checksummed path; representative inference parity on CPU and CUDA |
| Model upload | Disabled by default; constrained trusted-local override only; filename/type/size validation; no non-loopback exposure |
| Geospatial | Packaged ZIP-code shapefile loads and returns representative geometry on Python 3.11 and 3.12 |
| Configuration/session | Setup/settings config read/write; secret persistence; filesystem-session routes; cache headers |
| Production-critical workflows | Setup/settings; estimate/detect/cancel; review/list/map; manual tower; CSV/KML/dataset export; restore; ZIP search; health/readiness |
| Performance | Same-host three-run warmed medians for startup, YOLO/EfficientNet inference, total local detection, and peak memory; investigate >10% degradation |
| Package/runtime | Rebuilt image plus Docker CPU, Docker GPU, Podman CPU, and Podman GPU before final-candidate qualification |

Unit, static, and compatibility-spike work does not require a running
container engine. Before rebuilt-image or four-profile validation, ask the
user to start the exact Docker Desktop and/or Podman profiles required.

## Non-Regression Contract

No engineering process can guarantee that an undiscovered regression is
impossible. Task-098 therefore uses prevention, early detection, rollback, and
final runtime qualification as independent safeguards. A security fix is not
accepted merely because the vulnerability scan clears.

### Baseline Before Change

Before changing a pin or runtime boundary:

1. Record the source commit, resolved dependencies, model and asset checksums,
   Python version, engine/profile, GPU/driver where applicable, and safe test
   fixture identity.
2. Run the blocking unit and affected integration suites on Python 3.11 and
   3.12.
3. Capture same-fixture Google and Azure estimate/detect/cancel results,
   detection/list/map counts, export/restore state, startup/readiness timing,
   YOLO/EfficientNet phase timing, total detection timing, and peak memory.
4. Use at least three warmed runs on the same host for local compute timing.
   Network timing is recorded but excluded from a strict percentage comparison
   because provider/network variance is not controlled.
5. Declare numeric detection-output tolerances before evaluating an ML
   candidate. Exact workflow state, counts, schemas, and manual/export/restore
   semantics remain mandatory; tolerances may not be widened after candidate
   results are known.

### Slice Isolation And Rollback

- Implement A, B, C, D/G, E, and F as independently reviewable changes with a
  known-good rollback point.
- Do not stack the next slice over a failing focused or shared regression gate.
- Keep confidence thresholds, tiling, NMS, coordinate precision, provider
  semantics, export schemas, and frontend behavior unchanged unless a
  separately approved change is required.
- A dependency upgrade that requires unrelated feature redesign is a stop
  condition, not an implicit expansion of Task-098.

### Blocking Comparison Gates

The following must pass before Task-098 sign-off:

- all existing blocking CI checks on Python 3.11 and 3.12
- new focused tests for image signatures/decoder rejection, loopback publish,
  Waitress request behavior, aiohttp provider behavior, model trust, and every
  upgraded optional package path
- the affected integration tests as a blocking Task-098 gate even while the
  repository's broad historical integration job remains advisory
- setup/settings, Google/Azure estimate/detect/cancel, detection review/list/map,
  custom-image success, manual tower, CSV/KML/dataset export, restore,
  ZIP-code search, session persistence/reset, health/readiness, and model-upload
  default-off workflows
- trusted-model YOLO and EfficientNet output parity on CPU and CUDA
- a rebuilt CPU image before merge, followed by Docker CPU, Docker GPU, Podman
  CPU, and Podman GPU package qualification before final sign-off

The current browser harness records durations but does not enforce a
performance budget. Task-098 therefore adds an explicit comparison:

- more than 10% degradation in the median of same-host warmed startup,
  YOLO/EfficientNet inference, total local detection time, or peak memory is a
  blocking investigation threshold
- any clear user-visible slowdown or timeout regression is blocking even when
  the measured change is below 10%
- a different threshold may be approved only before the candidate comparison,
  with a written reason; a measured regression is never silently accepted

### CI And Final-Qualification Boundary

Hosted CI can block deterministic unit, integration, dependency-resolution,
CPU image-build, and security checks. It cannot prove provider, Windows
launcher, Podman, or physical-GPU behavior. Those checks require sanitized
manual/runtime evidence and remain hard Task-098 completion gates rather than
being mislabeled as automated CI coverage.

## Residual Critical/High Decision Packet

Use this packet only if a mandatory upgrade cannot be qualified safely. It
does not constitute advance acceptance.

The owners must choose one:

1. Delay later runtime work and complete a compatible upgrade.
2. Accept a time-bounded residual risk through the final candidate.
3. Remove or disable the affected capability from the supported release.

Option 2 requires all of the following:

- exact unresolved alert IDs and vulnerable versions
- failed upgrade candidates and reproducible compatibility evidence
- proof that normal release model upload remains disabled
- loopback-only package binding
- release and individual model checksum enforcement enabled by default
- explicit trusted-model-only documentation
- expiration no later than the October 9 freeze unless renewed
- named owner and follow-up task
- written project-lead and cdcai-owner approval

## CI Ratchet

Keep the existing all-severity Trivy SARIF path advisory while Task-098 is
remediating the known baseline. After mandatory remediation:

1. Preserve all-severity SARIF generation/upload with `if: always()`.
2. Add a separate filesystem gate for `CRITICAL,HIGH` with `exit-code: 1`.
3. Do not use blanket `ignore-unfixed`; every direct critical/high finding
   still requires a reachability decision.
4. Represent any owner-approved residual finding with a narrow
   `.trivyignore.yaml` entry scoped to the vulnerability and package path,
   including a written statement and `expired_at`.
5. Pin the action and Trivy versions, record the baseline database/version,
   and add a scheduled scan.
6. Fail every new critical/high finding not covered by an unexpired approved
   exception.

Validate the exact pinned action behavior before making the new gate blocking.

## Acceptance Criteria

### Approval And Traceability

- [x] The Task-090 alert inventory and reachability classifications are final.
- [x] This task's proposed slices, targets, estimates, regression matrix,
  residual-decision packet, and CI ratchet align with Task-090.
- [x] The project lead approves the Task-098 implementation scope with the
  explicit non-regression caveat recorded above.
- [x] Fork-side implementation requires no separate cdcai-owner confirmation.
  Residual critical/high acceptance, changes to `cdcai/TowerScout`, and
  official cdcai adoption retain their explicit owner gates.
- [ ] Every Task-098 change maps to an approved alert, runtime boundary, or
  compensating control.

### Non-Regression Gate

- [x] A pre-change baseline records dependencies, fixtures, model/assets,
  output parity, workflow results, timings, and peak memory.
- [ ] Each slice passes focused tests and the shared workflow gate before the
  next slice begins.
- [ ] Dedicated maintained tests replace reliance on the skipped legacy
  validation and image-processing contracts for every touched path.
- [ ] Detection state/counts, review/map/list behavior, manual tower semantics,
  and export/restore schemas are unchanged; numeric ML tolerances were declared
  before candidate evaluation and pass.
- [ ] Same-host warmed median startup, inference, local detection time, and
  peak memory remain within the 10% investigation threshold unless a different
  threshold was approved before comparison.
- [ ] Live Google and Azure workflows and all four supported runtime profiles
  pass before sign-off.

### Mandatory Remediation

- [x] The normal release package binds TowerScout to loopback and a contract
  test prevents regression to an all-interface default.
- [x] Custom-image validation rejects content-sniffed EPS, JPEG2000, McIdas,
  malformed, and oversized inputs before vulnerable Pillow decoding; valid
  JPEG/PNG/TIFF behavior, the 50 MiB cap, and rate limiting remain intact.
- [x] Approved Pillow, Waitress, and aiohttp targets are pinned consistently
  and pass their focused image, WSGI, and provider regression suites.
- [ ] The approved torch/torchvision CPU/CUDA pair passes clean dependency
  resolution, trusted model loading, and representative YOLO/EfficientNet
  inference.
- [ ] Release-model checksum enforcement is enabled by default and model
  upload remains disabled by default; any enabled override is loopback-bound
  and restricted to trusted files.

### Compatibility And Runtime Qualification

- [ ] Clean Python 3.11 and 3.12 dependency installs resolve without
  incompatible wheels or unintended source-build fallback.
- [ ] Google and Azure provider downloads pass TLS-verified header parsing,
  redirect, timeout/retry, cancellation, and sanitized-error tests.
- [ ] ZIP-code shapefile behavior and setup/settings/session behavior pass for
  every approved geospatial or web-framework hardening change.
- [ ] A rebuilt image passes the dependency-focused Docker CPU, Docker GPU,
  Podman CPU, and Podman GPU validation required by the approved scope.
- [ ] Before each runtime stage, the user is asked to start the exact Docker
  Desktop and/or Podman profiles needed and confirms they are running.

### Release Gate And Handoff

- [ ] No release-blocking critical/high finding remains unresolved.
- [ ] Any residual critical/high finding has written project-lead/cdcai-owner
  acceptance, compensating controls, an expiration date, a named owner, and a
  follow-up disposition.
- [ ] GitHub code-scanning state is reconciled without treating raw alert
  count alone as proof of safety.
- [ ] The approved CI ratchet fails new critical/high findings unless covered
  by a narrow, unexpired exception.
- [ ] Requirements, design, task status, release notes, dependency notices,
  package manifests, and owner-maintenance guidance reflect the final result.
- [ ] Task-087 remains paused until this release gate is signed off.

## Dependencies

- Completed Task-090 evidence-backed classification.
- Project-lead approval of the implementation scope.
- Approved dependency target pairs and wheel/runtime strategy.
- Existing CPU/GPU test hosts and managed Windows Docker/Podman environments.
- Model and data assets with known checksums.
- GitHub code-scanning and Actions access for final reconciliation.

## Stop Rules

- Stop if a dependency target would require an unplanned package-format,
  supported-profile, model-format, or provider-behavior change.
- Stop if a clean CPU/CUDA wheel set cannot be produced for the approved
  Python and container baseline.
- Stop if model-load or inference parity cannot be demonstrated with trusted
  release assets.
- Stop and isolate or revert the current slice if a blocking test, production-
  critical workflow, output-parity comparison, or performance threshold fails.
- Stop if the only evidence for a touched validation or image path is an
  intentionally skipped legacy test; add a maintained focused test first.
- Stop before accepting or dismissing any residual critical/high alert without
  the required written owner decision.
- Stop before runtime validation until the user confirms the required runtime
  is running.
- Do not publish `v0.1.3` final or change `cdcai/TowerScout` as part of this
  task.

## Implementation Plan

1. Record the approved Task-090-to-Task-098 scope, exact targets, validation
   matrix, same-fixture functional/output/performance baseline, and rollback
   points; for ML, record the approved candidate set and selection criteria.
2. Add or update maintained focused regression tests before changing the
   behavior they protect.
3. Implement the loopback, custom-image, and model-trust boundaries with
   focused tests.
4. Apply and validate the narrow Pillow, Waitress, and aiohttp upgrades.
5. Complete the coordinated ML compatibility spike, record the selected
   torch/torchvision/wheel pair, and then perform the approved migration.
6. Apply approved geospatial and config/web-framework hardening only after
   clean compatibility proof.
7. Run blocking Python, provider, workflow, output-parity, performance, upload,
   WSGI, model, package, Docker, and Podman regression in staged gates.
8. Reconcile every affected alert, document residual decisions, and ratchet CI
   for new critical/high findings.
9. Obtain Task-098 sign-off before Task-087 resumes.

---

## Implementation Log

### 2026-07-23 - Planning Record Created

**Objective**: Preserve Task-098 as a visible, separately governed follow-on
to Task-090.

**Context**: Task-098 existed in the backlog, requirements, design, roadmap,
and Task-090 proposed scope, but did not yet have an individual task file. The
project lead requested a durable task record so mandatory remediation is not
lost after Task-090.

**Decision**: Create the Type-C task file in the current Sprint 08 task area
with a planned/pending-approval status. Carry forward Task-090's proposed
slices while making the approval and no-implementation boundary explicit.

**Execution**: Created this task control record and linked it to the Task-090
disposition and remediation-scope documents.

**Output**: A durable Task-098 plan that can be finalized without renumbering
or recreating the task.

**Validation**: Agent-work structure, references, and Markdown validation are
required after task-state alignment.

**Next**: Obtain project-lead/cdcai-owner approval, replace proposed target
directions with the approved matrix, and then mark Task-098 `IN_PROGRESS`.

---

### 2026-07-23 - Task-090 Scope Alignment Review

**Objective**: Confirm that the Task-098 task record is sufficiently complete
to begin once its implementation scope is approved.

**Context**: The initial Task-098 record preserved the intended slices and
release gate but summarized several execution-critical details from Task-090.
It also required a final ML pair before the compatibility spike intended to
select that pair.

**Decision**: Preserve the proposed target versions, estimates, full regression
matrix, residual-decision evidence, and CI ratchet directly in this task.
Approve an ML candidate set and selection criteria at the start gate, then
record the final pair after the spike and before migration.

**Execution**: Reconciled this task against Task-090's alert disposition and
proposed remediation scope, `SEC-001`, the dependency-security design
boundary, the current dependency pins, Compose exposure, PyTorch package
surfaces, and the current advisory Trivy workflow.

**Output**: The Task-098 record now has an approval form, traceable target
matrix, complete validation obligations, explicit residual-risk choices, and
an executable CI ratchet without granting implementation authority.

**Validation**: Agent-work structure, local Markdown links, and whitespace
validation passed after this update.

**Next**: Record the owner scope decision. If approved, mark Task-098
`IN_PROGRESS` and begin Slice A plus fixed-target compatibility checks; select
the final ML pair only after Slice D evidence exists.

---

### 2026-07-23 - Scope Approval With Non-Regression Caveat

**Objective**: Record the project lead's approval while ensuring dependency
security work cannot silently trade away application behavior or performance.

**Context**: The project lead approved the proposed scope and asked for
confirmation that regressions would be prevented or caught before later
discovery. Existing tests provide meaningful coverage, but the broad
integration job and image build are advisory in current CI, live provider
smokes require a managed runtime, and legacy validation/image-processing test
modules are intentionally skipped.

**Decision**: Accept the scope approval with a binding non-regression contract.
Require pre-change baselines, maintained focused tests, slice-level rollback
points, blocking affected integration checks, production-critical workflow and
output parity, a 10% same-host performance investigation threshold, and final
Google/Azure four-profile qualification.

**Execution**: Reviewed current CI, 33 unit-test files, seven integration-test
files, the browser detection harness, ML/model tests, upload/config/assets
tests, runtime/package tests, and performance instrumentation. Ran the
available non-runtime baseline described below.

**Output**: Project-lead scope approval is recorded. Task-098 is ready to begin
with the pre-change baseline and maintained-test gates; no separate cdcai-owner
confirmation is required for fork-side remediation.

**Validation**: Agent-work structure, local Markdown links, and whitespace
validation passed after this update.

**Next**: When Task-098 starts, capture clean Python 3.11/3.12 non-runtime
baselines and add maintained focused tests. Request the exact container
runtimes only when reaching container-dependent baseline or validation stages.

---

### 2026-07-24 - Execution Started And Baseline Gate Opened

**Objective**: Begin the approved Task-098 work without changing dependencies
or runtime behavior before the non-regression baseline is recorded.

**Context**: Task-090 and the Task-098 approval record were preserved in commit
`d336686`. Task-098 is being executed on the short-lived child branch
`fix/task-098-dependency-security` because it depends on that unmerged planning
checkpoint.

**Decision**: Move Task-098 to `IN_PROGRESS`, treat baseline capture as the
only active implementation phase, and defer dependency/runtime mutations until
the available Python 3.11/3.12, model, workflow, and performance evidence is
recorded.

**Execution**: Corrected stale pending-approval wording, opened the task-local
baseline record, and began environment and maintained-test discovery.

**Output**: Task state now matches execution reality, with a known planning
checkpoint and isolated implementation branch.

**Validation**: Agent-work validation and whitespace checks are required after
the task-state update. Baseline commands and results are recorded in
[`TASK-098/baseline.md`](./TASK-098/baseline.md).

**Next**: Complete the non-runtime baseline, identify unavailable external
runtime evidence explicitly, and only then begin Slice A.

---

### 2026-07-24 - Local Python 3.12 Baseline Completed

**Objective**: Capture the locally available clean-resolution, maintained-test,
trusted-model, deterministic-output, and same-host performance evidence.

**Context**: The host provides Python 3.12 and 3.13 but not the supported
Python 3.11 baseline required by the non-regression contract.

**Decision**: Complete and preserve the full local Python 3.12 baseline, record
the broad integration failures as pre-change drift, and stop before Slice A
until Docker Desktop CPU can provide the clean Python 3.11 environment.

**Execution**: Built an isolated Python 3.12 CPU environment in ignored task
scratch, reproduced the Docker dependency order, ran unit/integration and
frontend contracts, verified trusted asset hashes, and ran the maintained
three-sample CPU model/startup probe.

**Output**: Unit, ML-focused, frontend-contract, flake8, dependency, asset, and
deterministic CPU model baselines are recorded. The broad integration suite
has four pre-existing geocoding failures and is not represented as clean.

**Validation**: See [`TASK-098/baseline.md`](./TASK-098/baseline.md) for exact
versions, counts, hashes, timings, outputs, and unresolved external gates.

**Next**: Ask the user to start Docker Desktop for the exact Docker CPU /
Python 3.11 baseline. Do not begin Slice A until that gate is recorded.

---

### 2026-07-24 - Docker CPU Python 3.11 Baseline Completed

**Objective**: Close the required pre-change baseline gate without allowing
pre-existing Docker state to influence Task-098.

**Context**: Docker Desktop was available, while a healthy older TowerScout
container and several unrelated local images and volumes already existed.

**Decision**: Build a uniquely tagged CPU image from the recorded source
checkpoint with fresh base pulls and no build cache. Run tests with no Compose
project or published ports, mount repository source and trusted models
read-only, and place every writable path on disposable tmpfs.

**Execution**: Built the Python 3.11 image, verified its OCI source/flavor
labels, ran dependency checks, unit and broad integration suites, the focused
ML gate, and the maintained three-sample CPU model/performance probe. Removed
all Task-098 test containers and disposable storage while retaining the unique
baseline image for after-change comparison.

**Output**: Python 3.11 dependency resolution and `pip check` passed. Unit tests
reported 212 passed and 121 platform/feature skips. The broad integration suite
reproduced the same 20-pass, 2-skip, 4-failure geocoding drift recorded on
Python 3.12. The focused ML gate passed 8 tests, and deterministic YOLO and
EfficientNet outputs matched the host baseline.

**Validation**: The pre-existing RC7.1 container remained healthy on its
existing port. No Task-098 test container remains, no existing application
image was used, and the image/test identities, exact counts, timings, and
isolation controls are recorded in
[`TASK-098/baseline.md`](./TASK-098/baseline.md).

**Next**: Begin Slice A by adding maintained focused tests for loopback
publication and content-signature image rejection before changing behavior.

---

### 2026-07-24 - Slice A Local And Input Boundary Completed

**Objective**: Remove the normal package's all-interface publication and
prevent unsupported custom-image content from selecting vulnerable Pillow
decoders.

**Context**: Compose published `${TOWERSCOUT_PORT}` on every host interface,
and custom-image validation trusted an allowed filename extension before the
route saved the upload and called Pillow.

**Decision**: Add maintained regression tests before behavior changes. Bind the
normal Compose package explicitly to `127.0.0.1`. Allowlist JPEG, PNG, and TIFF
magic bytes before Pillow is called, require extension/content agreement, then
use Pillow's `verify()` only through the selected approved decoder to reject
malformed supported files.

**Execution**: Added `tests/unit/test_task_098_slice_a.py`; changed
`compose.yaml`; and extended `TowerScoutValidator.validate_image_file`.
Preserved the existing 50 MiB size gate, upload rate limit, sanitized filename,
valid-image detection path, and result drawing.

**Output**: The test-first gate initially reported 9 expected failures and 7
preservation passes. After implementation, the Slice A and current route
hardening set passed 23 tests. Docker Compose resolved the published mapping as
host `127.0.0.1`, port 5000, target 5000.

**Validation**:

- Python 3.12 full unit suite: PASS, 275 passed and 74 legacy skips.
- Python 3.11 Docker CPU full unit suite: PASS, 228 passed and 121
  Linux/platform-feature skips.
- Python 3.12 broad integration: unchanged baseline drift, 20 passed, 2
  skipped, and the same 4 geocoding failures.
- Setup Wizard and ProviderStateManager JavaScript contracts: PASS; the forced
  Azure failure output remained the expected negative-path assertion.
- Blocking Flake8 and targeted Bandit: PASS.
- Black under Python 3.11: PASS for the new maintained test file. The existing
  whole-file `ts_validation.py` formatting drift remains the repository's
  advisory baseline and was not expanded into an unrelated reformat.
- Docker isolation: no Task-098 container remains; the pre-existing RC7.1
  container remained healthy and was not changed.

**Next**: Create a Slice A commit checkpoint, then begin Slice B's narrow
Pillow/Waitress patch with clean-resolution and focused image/WSGI tests.

---

### 2026-07-24 - Slice B Pillow And Waitress Patch Completed

**Objective**: Apply the approved narrow Pillow and Waitress security patches
without changing supported image behavior, WSGI readiness, model output, or
runtime performance beyond the declared investigation threshold.

**Context**: The approved Slice B baseline pinned Pillow 12.2.0 and Waitress
3.0.0. Pillow 12.3.0 is the approved July 2026 security release, and Waitress
3.0.2 includes the 3.0.1 half-open/request-smuggling fixes plus the subsequent
trusted-proxy-header correction. Upstream references:
[Pillow 12.3.0 release notes](https://pillow.readthedocs.io/en/stable/releasenotes/12.3.0.html)
and [Waitress 3.0.2 project history](https://pypi.org/project/waitress/).

**Decision**: Pin Pillow 12.3.0 and Waitress 3.0.2 exactly. Keep the existing
torch 2.2.1+cpu / torchvision 0.17.1+cpu pair unchanged, align the YOLO runtime
minimum with the Pillow pin, and add a maintained loopback WSGI contract before
accepting the new versions.

**Execution**: Added `tests/unit/test_task_098_slice_b.py`; updated
`webapp/requirements.txt`, the Pillow minimum in `webapp/ts_yolov5.py`, and
the local-loader dependency fixture. The maintained Waitress contract covers
readiness, the request-body cap, malformed headers, a half-open client
disconnect followed by readiness recovery, and clean server shutdown.

**Output**: Clean Python 3.12 resolution selected Pillow 12.3.0 and Waitress
3.0.2 with no broken requirements. Runtime dependencies resolved from wheels
except the repository's pre-existing, source-only pure-Python
`efficientnet-pytorch==0.7.1`; this was an intentional known exception rather
than a new native source-build fallback. The disposable Python 3.11 container
upgraded only Pillow and Waitress over the isolated clean baseline layer and
retained the pinned CPU torch pair.

**Validation**:

- Focused Slice A/B, route, and YOLO loader gate: PASS, 31 tests on both
  Python 3.12 and containerized Python 3.11.
- Python 3.12 full unit suite: PASS, 277 passed and 74 legacy skips.
- Python 3.11 Docker CPU full unit suite: PASS, 230 passed and 121
  Linux/platform-feature skips.
- Broad integration on both versions: unchanged baseline drift, 20 passed, 2
  skipped, and the same 4 pre-existing geocoding failures.
- Setup Wizard and ProviderStateManager JavaScript contracts: PASS; the forced
  Azure failure output remained the expected negative-path assertion.
- Python 3.11 `pip check`, targeted Black, and blocking Flake8: PASS.
- Deterministic CPU model output: PASS; YOLO counts remained `[0, 0, 0]` and
  EfficientNet scores remained `[0.8266443, 0.8266443, 0.8266443]`.
- Same-host container comparison: startup and both inference medians improved;
  peak RSS changed from 1,385,152,512 to 1,459,650,560 bytes, a 5.38% increase
  below the 10% investigation threshold.
- Docker isolation: the disposable Slice B container was removed, the unique
  baseline image was retained for later comparison, and the pre-existing
  RC7.1 container was not reused or changed.

**Next**: Create a Slice B commit checkpoint, then begin Slice C's approved
aiohttp 3.14.2 provider-client patch with maintained Google/Azure download,
redirect, timeout/retry, cancellation, and sanitized-error tests.

---

### 2026-07-24 - Slice C aiohttp Provider Client Patch Completed

**Objective**: Remove the release-blocking aiohttp response-header parser
baseline while preserving Google/Azure download, retry, cancellation, TLS,
and sanitized-error behavior.

**Context**: TowerScout's live aiohttp surface is the fixed-host map-provider
client in `webapp/ts_maps.py`. The approved target is aiohttp 3.14.2, whose
official release history records the 3.14.1 cancellation/connector fixes and
the July 20, 2026 3.14.2 patch:
[aiohttp changelog](https://docs.aiohttp.org/en/stable/changes.html).

**Decision**: Pin aiohttp 3.14.2 exactly without changing provider application
code. Add maintained client tests that exercise the real aiohttp response
parser against a loopback fixture and retain the existing shared provider TLS
connector contract.

**Execution**: Added `tests/unit/test_task_098_slice_c.py` and updated the
aiohttp pin in `webapp/requirements.txt`. The new contracts cover Google and
Azure redirect-following and file writes, `Retry-After` parsing and retry,
timeout categorization, cancellation propagation, and credential redaction.
The test-first run on aiohttp 3.9.3 produced the single expected pin failure
while all six behavior-preservation tests passed.

**Output**: Python 3.12 and Python 3.11 selected the platform wheel for aiohttp
3.14.2, added `aiohappyeyeballs`, and passed `pip check`. No provider runtime
code, concurrency limit, timeout, retry count, TLS policy, URL construction,
or output file behavior changed.

**Validation**:

- Focused aiohttp/provider/TLS-runtime/Azure integration gate: PASS, 31 tests
  on both Python 3.12 and containerized Python 3.11.
- Python 3.12 full unit suite: PASS, 284 passed and 74 legacy skips.
- Python 3.11 Docker CPU full unit suite: PASS, 237 passed and 121
  Linux/platform-feature skips.
- Broad integration on both versions: unchanged baseline drift, 20 passed, 2
  skipped, and the same 4 pre-existing geocoding failures.
- Setup Wizard and ProviderStateManager JavaScript contracts: PASS; the forced
  Azure failure output remained the expected negative-path assertion.
- Targeted Black and blocking Flake8: PASS.
- Deterministic CPU model output: PASS; YOLO counts remained `[0, 0, 0]` and
  EfficientNet scores remained `[0.8266443, 0.8266443, 0.8266443]`.
- Same-host container comparison: startup and both inference medians improved;
  peak RSS changed from 1,385,152,512 to 1,457,643,520 bytes, a 5.23% increase
  below the 10% investigation threshold.
- Docker isolation: the disposable Slice C container was removed, the unique
  baseline image was retained, and the pre-existing RC7.1 container was not
  reused or changed.

**Next**: Create a Slice C commit checkpoint. Begin the Slice D/G coordinated
ML compatibility spike only after confirming the exact Docker GPU profile
needed for CPU/CUDA pair selection and model-trust qualification.

---

## Validation Results

**Execution Status**: IN_PROGRESS; PRE-CHANGE BASELINE AND SLICES A-C
COMPLETE; SLICE D/G READY

**Planning Readiness Confidence**: 94%. The alert inventory, reachability
evidence, proposed targets, work slices, regression obligations, stop rules,
residual-decision packet, and CI ratchet are traceable and internally
consistent. The remaining uncertainty is intentionally owned by the approval
decision and Slice D compatibility evidence, not missing task preparation.

**Documentation Validation**:

- `check_agent_work_quick.py`: PASS
- `.agent_work/scripts/validate_agent_work.py`: PASS
- Local Markdown links across Task-098 and its governing tracking sources:
  PASS
- `git diff --check`: PASS

**Current Baseline Review**:

- Python 3.12 affected-surface tests: 152 passed.
- Legacy validation and image-processing modules: 46 skipped by explicit
  repository-level markers; Task-098 must add maintained focused replacements
  for touched paths rather than count these skips as coverage.
- Setup Wizard validation contract: PASS.
- ProviderStateManager regression contract: PASS; its forced Azure failure
  messages are expected negative-path output and the command exited zero.
- Current CI reality: unit tests block; the broad integration job, container
  image build, and Trivy SARIF path are advisory; live Google/Azure browser
  smoke and four-profile package validation are external runtime gates.
- Live-provider smoke, after-change model output/performance comparison, and
  final Docker/Podman CPU/GPU qualification remain execution-time gates.

**Docker CPU Python 3.11 Baseline**:

- Fresh `--pull --no-cache` CPU image: PASS.
- Dependency resolution and `pip check`: PASS.
- Unit suite: PASS, 212 passed and 121 Linux/platform-feature skips.
- Broad integration: BASELINE DRIFT, 20 passed, 2 skipped, and the same 4
  pre-change geocoding failures seen on Python 3.12.
- ML-focused gate: PASS, 8 passed.
- Deterministic YOLO/EfficientNet output parity: PASS.
- Existing Docker state isolation: PASS; no pre-existing image, container,
  port, volume, or build-cache layer influenced the run.

Task-098 has changed only the approved Slice A runtime/input boundaries,
Slice B Pillow/Waitress pins, Slice C aiohttp pin, and their maintained
regression contracts. No release asset, GitHub alert state, or external
repository has been changed.
