# Current Tasks - Sprint 09

**Sprint Period**: August 8-August 21, 2026
**Last Updated**: September 9, 2026
**Focus**: Task-101 is complete. Task-087 held provider/runtime/endpoint
checkpoint `1547f2a` is independently reviewed and exact-head green: CI/CD run
`34370131662`, Task-087 run `34370131570`, and external Trivy passed all nine
applicable pull-request checks. A September 9 local source-only follow-up now
adds the outer transaction owner: the release manifest, both package policy
catalogs, Compose inputs, `.env`/template source, package root, and all Windows
process-environment directories are exact target/plan inputs held through the
fully acquired provider/runtime boundary. The dependency policy is now bundled
and build-inspected beside the runtime policy. The slice is unwired and ready
for checkpointing after independent review returned PASS with no findings.
Secure resolver/integration work, cross-session locks,
durable recovery, Windows-store CA selection, and ACL-preserving `.env`
replacement remain later Gate A work. Unsigned preview-package integration
remains later under ADR-019. Production signing remains Task-100 work in
October after the package is satisfactory.

**Current Release State**:

- Fork-side `v0.1.2` is the immutable pilot package.
- Iterative unsigned fork packages use immutable `v0.1.3-preview.N` GitHub
  prereleases and are never marked `Latest`.
- `v0.1.3-rc.N` is reserved for the signed production-shaped candidate created
  under Task-100.
- Dependabot alert `#76` closed as fixed, without dismissal, after PR #72
  squash-merged as `0cc189c`. PR #73's checkpoint then squash-merged as
  `9276084` and passed exact-main checks. PR #67 reconciliation head `946deaf`
  then passed CI/CD run `32383065903` and Task-087 run `32383065959` with all
  required jobs successful. Task-101 is complete. The lifecycle update
  `6e0f744` then passed CI/CD run `32385304086` and Task-087 run `32385304052`.
  Task-087 is active in Gate A IMPLEMENT under the project lead's August 21
  approval after the independent source review requested changes. PR #67 remains
  Draft. Reviewed source checkpoint `1970f76` and task-state checkpoint
  `636617b` passed exact-head CI/CD run `34244364493`, Task-087 run
  `34244364488`, and external Trivy; all nine applicable checks succeeded and
  the main-only build job skipped as designed for a pull request. This later
  docs-only handoff records that evidence without changing implementation bytes.
- Reviewed Windows-trust source checkpoint `2d37e66` and task-state checkpoint
  `ca2f284` passed exact-head CI/CD run `34257761291`, Task-087 run
  `34257761429`, and external Trivy; all nine applicable checks succeeded and
  the PR-only build job skipped as designed. A later docs-only handoff records
  that evidence without changing implementation or test bytes.
- Reviewed CPython-dependency source checkpoint `3909395` and task-state
  checkpoint `e01f1b7` passed exact-head CI/CD run `34275327043`, Task-087 run
  `34275327085`, and external Trivy; all nine applicable checks succeeded and
  the PR-only build job skipped as designed. This evidence closes the held
  checkpoint gate without changing implementation or test bytes.
- `cdcai/TowerScout` remains unchanged until final owner qualification and
  explicit adoption approval.
- October 30 is operational closeout; October 31 is the hard project end.

---

## Sprint 08 Closeout

Sprint 08 completed Tasks 090 and 098 within the July 23-August 7 period and
cleared the original dependency-security gate. Task-099 began during Sprint 08
but completed on August 11 after the declared period, so its completion belongs
to Sprint 09. Tasks 087, 089, and 095 carry forward.

Retrospective:
[`SPRINT-08-RETROSPECTIVE-ANALYSIS-2026-08-11.md`](./context/analysis/SPRINT-08-RETROSPECTIVE-ANALYSIS-2026-08-11.md)

---

## Sprint 09 Task State

### **TASK-095: Governance And AI-Ready Handoff Foundation**

**Status**: IN_PROGRESS - Phase A roadmap/workspace rebaseline is complete;
Phase B governance and final handoff maintenance continue through closeout
**Type**: C (Governance / Documentation / Handoff)
**Priority**: HIGH
**Estimated Effort**: Phase A 1-2 days; Phase B 2-4 distributed days
**Task File**:
`.agent_work/tasks/active/TASK-095-governance-ai-ready-handoff.md`

**Current Scope**:

- Keep task disposition, navigation, backlog, release evidence, and owner
  handoff sources current through October 30.
- Preserve one canonical fix-first roadmap and the immutable pilot/adoption
  boundary.
- Close sprint and task-state drift when live evidence changes the plan.

### **TASK-099: August Dependency Advisory Follow-Up**

**Status**: COMPLETED - PR #68 merged the narrow dependency fixes as
`f460445`; PR #69 merged the root-manifest refresh as `0133b50`. Dynamic graph
run `31510493332` replaced the stale snapshot, alert `#74` closed without
dismissal, the SBOM contains only `aiohttp==3.14.3`, and the August 11 closeout
inventory was exactly the eight documented torch residuals
**Completed**: August 11, 2026
**Type**: C (Security Remediation / Release Gate)
**Priority**: HIGH
**Task File**:
`.agent_work/tasks/active/TASK-099-august-dependency-advisory-follow-up.md`

**Release Boundary**: Task-099 cleared its scoped dependency-security gate on
August 11. Alert `#76` opened afterward and belongs to separately activated
Task-101 rather than rewriting Task-099. PR #72 restored the blocking frontend
gate, alert `#76` closed as fixed, and Task-101's downstream PR #67 exact-head
gate passed at `946deaf`. Task-099 remains the dated August 11 closeout;
reviewer input may continue.

### **TASK-101: extract-zip Advisory Assessment And Release-Gate Disposition**

**Status**: COMPLETED - PR #72/default-branch security gates and PR #73's
checkpoint passed; PR #67 reconciliation head `946deaf` then passed CI/CD run
`32383065903` and Task-087 run `32383065959`, and this lifecycle update records
Task-101 completion plus Task-087's explicit resume
**Completed**: August 20, 2026
**Type**: C (Security Remediation / CI And Release Gate)
**Priority**: HIGH
**Estimated Effort**: 1-2 days plus CI rerun timing
**Task File**:
`.agent_work/tasks/active/TASK-101-extract-zip-advisory-release-gate.md`

**Current Scope And Gates**:

- Preserve Task-099 as the dated August 11 closeout. Task-101 uniquely owns
  alert `#76`, the current npm lock graph, and restoration of the blocking
  frontend dependency-security gate.
- Treat the finding as a CI/developer-browser-install risk, not a shipped
  TowerScout runtime dependency. Do not claim exploitation or end-user runtime
  exposure without new evidence.
- Preserve the locally validated Node `>=22.12.0` / Puppeteer `25.8.0` path,
  whose locked browser tooling removes vulnerable `extract-zip`; do not use
  `npm audit fix --force`, weaken the high-severity gate, or dismiss the alert.
- Preserve the green final PR #72 evidence at `820b649`: CI/CD run
  `32308971393` and Task-087 run `32308971392`. Preserve the exact-main
  post-merge evidence at squash commit `0cc189c`: CI/CD run `32310281115` and
  Task-087 run `32310281051` passed, and alert `#76` closed as fixed without
  dismissal.
- Preserve PR #73's post-merge governance checkpoint at squash commit
  `9276084`: exact-main CI/CD run `32377736719` and Task-087 run `32377736797`
  passed. This merge semantically integrates that current `main` into PR #67
  while preserving ADR-019 and the branch's recorded evidence.
- Align the maintained Node baseline across CI, `package.json`, and the Docker
  frontend stage, and remove the redundant Puppeteer browser-download path
  from Task-087 workflows that already install a pinned browser separately.
- Keep the Docker frontend-stage build blocking on pull requests; the full
  runtime-image build remains the separately documented main-branch advisory
  check.
- Treat those narrowly scoped Task-101 security-workflow edits as gate work;
  those edits alone did not resume broader Task-087 implementation. Resumption
  occurs only through this explicit post-green lifecycle update.
- Require clean install/audit/lock-graph, frontend bundle/contracts, Task-087
  browser/Windows-helper, and Docker build validation before acceptance.
- Preserve the green PR #67 reconciliation evidence at `946deaf`: CI/CD run
  `32383065903` and Task-087 run `32383065959` passed with all required jobs
  successful.
- The lifecycle update marked Task-101 complete and explicitly resumed
  Task-087. Exact-head CI/CD run `32385304086` and Task-087 run `32385304052`
  passed at `6e0f744`; Task-101 has no remaining acceptance gate.

### **TASK-087: Host-Side TLS Repair Control Plane**

**Status**: IN_PROGRESS / IMPLEMENT - the exact-source `7ef879c`
full-runnable CPU packages passed Docker and approved-provider Podman
Google/Azure TLS repair plus controlled recovery. Follow-up head `3990bc0`
closed provider-installer dependency drift with a hash-approved offline
wheelhouse, and head `5737a58` enforced the selected Windows rootless-Podman
boundary without changing machine mode or volumes. PR #72 and alert `#76`
default-branch reconciliation passed, and PR #67 head `946deaf` passed CI/CD
run `32383065903` plus Task-087 run `32383065959`. Task-101 is complete, and
the lifecycle update resumed Task-087 while preserving the evidence and
ADR-019. That exact lifecycle head `6e0f744` passed CI/CD run `32385304086` and
Task-087 run `32385304052`. Independent technical/security review then
requested source changes. On August 21, the project lead explicitly approved
moving Task-087 to IMPLEMENT under the August 20 remediation design. Gate A
source implementation is now active while PR #67 remains Draft.
**Type**: B/C (Runtime Support / Setup UX / TLS Trust)
**Priority**: HIGH
**Remaining Estimate**: Rebaselined after review: approximately 6-10 focused
implementation days plus live Windows/Docker/Podman validation and re-review
timing; preview integration remains a later gate
**Task File**:
`.agent_work/tasks/active/TASK-087-host-side-tls-repair-control-plane.md`

**Current Scope And Gates**:

- Preserve the visible Python/Tkinter launcher and bounded native transaction
  on top of the current security and Sprint 09 tracking history.
- Preserve the Google/Azure functional evidence from accepted implementation
  head `7ef879c` and the provider-installer reproducibility evidence from
  follow-up head `3990bc0`; their applicable exact-head CI and CPU package gates
  are green.
- Preserve the passed exact-head Docker and approved-provider Podman
  Google/Azure/recovery results as unsigned development-workstation evidence.
- Keep the approved Podman Compose provider explicit. Head `3990bc0` replaces
  live dependency resolution with exact per-artifact URLs and SHA-256 pins,
  installs only from the verified local wheel cache with dependencies disabled,
  checks the environment and exact versions, and binds it only after approval.
  Fresh packaged installation and managed replacement passed; no unapproved
  provider or dependency was accepted.
- Treat rootless Podman CPU as the provisional Windows support boundary. The
  unchanged exact package reached native Windows localhost and retained that
  reachability across scoped restart in rootless mode. Rootful mode remained
  healthy only inside the Podman WSL distribution and did not expose Windows
  localhost, with Docker fully exited; user-mode networking did not fix it.
  Head `5737a58` now rejects rootful Windows Podman before Compose-provider
  discovery or container mutation, explains the separate rootful/rootless
  stores, and never switches the user's machine mode automatically.
- Record the NVIDIA result accurately: the workstation passed Docker GPU and
  Blackwell model execution, but the selected PyTorch 2.6/CUDA 12.6 release
  profile cannot execute compute capability 12.0. A non-release PyTorch
  2.7/CUDA 12.8 feasibility image passed the deterministic model harness.
  Keep dependency/profile selection and final Docker/Podman GPU package
  qualification in Task-097 rather than expanding the Task-087 release claim.
- Keep all existing `Task-087-validation-*` packages validation-only. Build a
  new normal-user package for any `v0.1.3-preview.N` publication; do not rename
  or upload an existing validation ZIP.
- Treat the August 20 external review as outside input rather than authority.
  Independent inspection agrees that runtime/endpoint/Compose/target binding,
  durable verified rollback, Windows-only trust selection, cross-session
  locking, Windows file safety, staged-byte provenance, build-toolchain
  integrity, and root `.env` backup handling require correction. Follow the
  task-local
  [`TECHNICAL-SECURITY-REMEDIATION-DESIGN-2026-08-20.md`](./tasks/active/TASK-087/TECHNICAL-SECURITY-REMEDIATION-DESIGN-2026-08-20.md).
- Gate A remains intentionally inert. Commits `7ad221d` and `e049e32` disable
  default mutation and add immutable target contracts, fixed read-only command
  plans, handle-bound file identity, canonical mutex names, and pure root
  selection. Commit `24d4015` adds the pinned runtime policy, same-handle
  Authenticode and PE product/version proof, and reviewed-record installation
  nomination. Commit `4150217` serializes every use/close of the retained file
  and combines the three evidence sources into a closeable, non-executable
  owner after final record/file revalidation. Documentation checkpoint
  `ab33864` records that source slice; all are pushed to PR #67.
- CI/CD run `32527400108` exposed one cross-platform defect in the earlier
  target/execution foundations: the completed Ubuntu/Python 3.11 leg reported
  62 fail-closed fixture errors after interpreting modeled `C:\...` values
  through host `Path`; the 3.12 leg had marked the same cases failed before
  matrix fail-fast cancelled it. Commit `0eebe7b` makes
  `FileIdentity.final_path` an exact `PureWindowsPath` contract, applies
  Windows semantics to all modeled path operations and command assertions,
  rejects wrong-flavor/relative inputs before rendering, and preserves ordinary
  drive paths plus handle-derived local `\\?\C:\...` final names. Focused tests
  pass 73/73; the inert Gate A set passes 537 tests with only the two prohibited
  native installed-file smokes deselected. Independent security, adversarial,
  and source-boundary reviews pass with no blockers. Exact-head CI/CD run
  `32530172080` passed both Ubuntu Python jobs and every required PR job;
  Task-087 run `32530172064` passed all three controller/Windows contract jobs.
  Local and tracking refs match at `0eebe7b` with zero divergence.
- Workstation-local handoff note: preserve stash
  `b9b36bf4741a5e7301de6a75672799b6ed91faec`, labeled
  `task-101-governance-transfer-2026-08-19`. Its tracked diff spans 12
  governance/Task-087 documentation paths, and it may also retain untracked
  local state. It is not part of the active branch or PR and must not be popped,
  dropped, or applied blindly; inspect it privately for sensitive content and
  reconcile it deliberately in a separate workspace-hygiene step.
- The final focused security/identity/Auth/combiner run passed 228 tests with
  only the two prohibited native installed-file smokes deselected; the policy,
  mutation-gate, and target-contract set passed 128. Independent security
  review found and closed one interruption-time pre-return handle-cleanup gap
  plus one inert-import test gap, then issued PASS with no open findings. No
  live discovery, process executor, app, or repair path imports the combiner;
  mutation remains disabled. Docker Compose and Podman command-based exact-
  version proof, provider reconstruction, ACL/mutex/journal/recovery, and
  `.env` transaction work remain open. The reviewed source slice is checkpointed
  at `4150217` and pushed to PR #67; this docs-only status reconciliation
  follows that checkpoint.
- The September 8 Gate A slice adds authenticated command-version proof
  for Docker Compose `5.3.1` and Podman CLI `6.0.2`, including exact fixed
  arguments/output parsing, minimal constructed environment, retained-handle
  identity/signer/hash/path binding, and a suspended Windows Job Object process
  boundary with streamed limits and verified tree termination. Independent
  review found and closed process-ownership/cleanup gaps and the missing native
  ctypes behavioral proof, then returned PASS with no open findings. Its focused
  63-test suite and the 611-test security/identity regression set pass with only
  two prohibited installed-file native smokes deselected; Black, blocking
  Flake8, isolated mypy, medium/high Bandit, compilation, diff checks, and both
  task-record validators pass. The reviewed source checkpoint is `1970f76`, and
  task-state checkpoint `636617b` passed exact-head CI/CD run `34244364493`,
  Task-087 run `34244364488`, and external Trivy. The slice remains unwired. No
  live Docker, Podman, Compose, launcher, or installed-binary smoke ran, and
  mutation remains disabled. Ancestor
  DACL/owner/reparse/cloud containment and application dependency/DLL load
  closure remain strict prerequisites before integration.
- Source checkpoint `2d37e66` implements the next inert Windows-trust
  prerequisite layer. It binds lexical and resolved directory chains through
  retained handles; validates local-fixed-directory identity, owner, DACL, ACE,
  and reparse/cloud policy; hydrates an explicitly allowed cloud leaf through a
  second identity-stable handle; binds every immediate application-directory
  file; authenticates PE images regardless of extension; and adds empty parent
  DLL-directory plus child image-load mitigations. Independent review closed
  unapproved-writer, unsupported-ACE, hydration, process/pipe/job, native out-
  parameter, and ownership-transfer gaps, then returned PASS with 109 scoped
  tests. Local validation passed 155 focused tests plus the separate native
  hardlink proof, and 689 broader tests plus that native proof. The layer is
  explicitly a prerequisite, not complete DLL closure: transitive
  dependencies, private assemblies, dynamic relative loads, and the product-
  specific Microsoft/CPython signer policy still block execution wiring. No
  Docker, Podman, launcher, repair, mutation, package, or publication action
  ran. Task-state checkpoint `ca2f284` then passed exact-head CI/CD run
  `34257761291`, Task-087 run `34257761429`, and external Trivy with all nine
  applicable checks successful; the PR-only build job skipped as designed.
- Source checkpoint `3909395` adopts the exact-artifact dependency policy:
  the official Python.org `pythoncore-3.12-64` CPython 3.12.10 archive and all
  47 PE files are hash-pinned; all 43 AMD64 files have exact static-dependency
  manifests; 39 require one of five exact signer certificates; and the eight
  upstream unsigned records are explicitly exact-hash-only. A bounded PE
  parser, held-handle random-access inspection, pure full-inventory/entrypoint
  validators, and exact dependency-signer Authenticode path are implemented.
  The official archive and matching installed tree produced zero inventory,
  hash, machine, dependency-manifest, or signer-policy mismatches. The launcher
  unit set passed 769 tests with the known native hardlink/temp-cleanup case
  deselected. Independent review found one Medium escaped-reader lifetime gap;
  the reader is now scope/thread-bound, invalidated before lock release, and
  covered after success, callback failure, owner close, and cross-thread use.
  Re-review returned PASS with no open findings. The broader suite was not
  green because of the documented
  Defender host-helper block, dirty-tree package assertion, and inaccessible
  shared pytest temp root. Native cache-only timestamp-chain validation failed
  closed on this workstation and is not treated as a pass. The checkpoint
  remains unwired. Exact-head CI/CD run `34275327043`, Task-087 run
  `34275327085`, and external Trivy subsequently passed for source `3909395`
  and task state `e01f1b7`; all nine applicable checks succeeded and the
  PR-only build job skipped as designed. A follow-up captures all 47
  policy-native files and every distinct parent-directory hierarchy, proves
  unsigned status from the held PE certificate-table structure rather than a
  generic trust failure, and retains/revalidates those handles before and
  after a synchronous child-operation boundary. Independent review found one
  Medium race where another thread could close a retained handle during the
  operation. The corrected owner now holds every underlying file lifetime lock
  through the operation and final revalidation, removes the public inspector
  capability, and covers cross-thread close blocking. Re-review found no
  remaining Critical, High, or Medium issue; one Low stale test count was
  corrected before checkpoint. Focused tests pass 32/32 and
  the post-remediation launcher regression set passes 830 tests when the
  documented Defender-blocked host-helper file and native hardlink/temp case
  are excluded. The
  broader launcher-oriented run reached 829 passes with only four known
  Defender host-helper failures. Source/task-state checkpoint `e18fb3a` passed
  exact-head CI/CD run `34280588649`, Task-087 run `34280588654`, and external
  Trivy; all nine applicable pull-request checks succeeded. The independently
  reviewed held-inventory layer explicitly did not deny arbitrary absolute
  child dynamic-load destinations.
- A local source-only follow-up now closes that gap for one fixed CPython
  command. An opt-in `DEBUG_PROCESS` backend inspects each frozen process-image
  and DLL event through the exact Windows-supplied file handle; package-private
  AMD64 images must match the held inventory's stable identity, hash, and path,
  while other images must be direct System32 files whose leaf names occur in
  the reviewed static-import/API-set policy or the explicit `ntdll.dll`,
  `kernelbase.dll`, and `ucrtbase.dll` bootstrap set. The process prohibits
  dynamic code and applies Windows' child-process creation restriction in
  addition to treating any unexpected descendant debug event as a denial.
  Cleanup does not claim containment until it has continued the root exit
  event, and native event-conversion cleanup failures plus repeated main-thread
  interruptions remain fail-closed. The first independent review found one
  High child-debug escape and four Medium allowlist, cleanup, exit-drain, and
  interruption issues; all are corrected, and re-review returned PASS with no
  open findings. Focused tests passed 104/104 and the complete launcher
  selection passed 858/858 before checkpoint;
  Black, blocking Flake8, strict mypy, medium/high Bandit, compilation, and
  diff checks pass. An earlier full unit run reached 1,185 passes and 74 skips,
  with its 19 failures confined to the documented Defender/AMSI block on the
  unchanged dormant PowerShell helper. The follow-up remains unwired and is
  intentionally not yet a Docker, Compose, or Podman provider-child executor.
  Source checkpoint `76bb3cb` then passed every Task-087, frontend, Docker-
  frontend, security, and Trivy job, but CI/CD run `34291611878` failed four
  portable native-shim tests on Ubuntu/Python 3.12 because the shim did not
  provide Windows-only `ctypes.set_last_error`/`get_last_error`; the Python
  3.11 matrix leg was cancelled during dependency installation by fail-fast,
  and the dependent build skipped. Test-only checkpoint `7233dc3` supplies that
  simulated last-error state and adds timeout coverage. Production source is
  unchanged. The corrected focused set passes 105/105 and the complete launcher
  selection passes 859/859; Black, blocking Flake8, compilation, and diff
  checks pass. Exact-head CI/CD run `34293025363`, Task-087 run `34293025481`,
  and external Trivy passed all nine applicable checks; both Ubuntu Python
  matrix legs passed, and the main-only build skipped as designed for a pull
  request.
- A September 9 local source-only slice extends the exact debug-event policy to
  one separately authenticated provider role plus one active exact runtime-
  child role. The native Job Object admits at most the provider and one child;
  the provider remains alive while the child runs, every process image and DLL
  must match its role-specific stable identity/hash/path policy or a reviewed
  direct-System32 leaf. The Job limit prevents a third concurrent process from
  remaining active; an observed unexpected/concurrent process event fails and
  drains the operation, without claiming that an association denial alone
  terminates the existing Job.
  Provider requests are reconstructed from the exact Podman Compose plan with
  a fixed shell-free argument vector and the ten-key constructed environment;
  the native debug adapter closes only process/DLL image-file handles and leaves
  debugger-owned process/thread handles to Windows through exit continuation.
  Focused tests pass 152/152 and the complete launcher-prefix regression
  selection passes 827/827 outside the sandbox required by its native Windows
  handle case. Black, blocking Flake8, strict mypy, medium/high Bandit, source
  sensitive-term scanning, and diff checks pass. This slice remains unwired:
  no Docker, Podman, Compose, launcher, repair, filesystem mutation, package,
  or publication path ran. The initial independent review found one High
  Windows debug-handle ownership defect and one Medium Job-limit overclaim;
  both are corrected, and re-review returned PASS with no open findings.
  Source checkpoint `d40bb7f` then passed exact-head CI/CD run `34359261079`
  and Task-087 run `34359261077`; all nine applicable checks succeeded and the
  pull-request-only build skipped as designed.
- A subsequent local source-only increment now composes the authenticated
  provider artifacts, held base-CPython closure, held Podman application load
  surface, and captured endpoint key/discovery artifacts under one synchronous
  owner. Role policies are available only while every nested file and directory
  lifetime lock is held, and the returned redacted evidence binds the exact
  request, provider/child policies, endpoint material, and dynamic-load result.
  Replacement, identity mismatch, same-thread reentry, cross-thread close, and
  post-operation drift tests fail closed. The evidence explicitly records that
  no live network peer was observed: this is the source-level endpoint contract
  needed before a real provider trace, not the live trace itself. Independent
  review found one Medium pre-callback inventory timing gap; the corrected
  deepest-boundary check and adversarial regression passed re-review with no
  findings remaining. Focused tests pass 77/77, and the wider launcher
  regression selection passes 885/885 with the documented Defender/AMSI helper
  and restricted native-hardlink host cases excluded. Source checkpoint
  `1547f2a` passed exact-head CI/CD run `34370131662`, Task-087 run
  `34370131570`, and external Trivy; all nine applicable pull-request checks
  passed and the main-only build skipped as designed.
- The next local source-only increment closes that owner's residual outer-input
  lifetime gap. It binds exact release-manifest and package-policy identities
  into the target token and every command plan, packages and build-inspects the
  runtime dependency policy, and holds ordered Compose/environment/security
  file handles plus package-root and five Windows process-environment path
  hierarchies through provider execution. A pre-execution validator runs after
  the provider/runtime leases are fully acquired; simulated drift at that
  boundary prevents the native backend from running. The focused target,
  execution, and transaction set passes 98/98; the wider launcher selection
  passes 893/893 with the known restricted-host native hardlink case
  deselected. Static/security checks pass. Independent inspect-only review
  returned CLEAN/PASS with no findings after its own 324 focused tests. The
  slice remains unwired and is ready for checkpointing.
- Keep source, preview, and signing gates separate. Findings 1-8 and the
  source-level provider `.env` correction gate PR #67 source re-review;
  staged-copy/provenance-v2 and the explicitly approved exact-patch/hash-locked
  Python 3.12 build gate a new validation artifact or unsigned preview;
  Task-100 still owns production
  signing and representative managed-endpoint qualification.
- Preserve the existing no-helper/no-listener/no-PowerShell/no-admin boundary,
  explicit Task-086 fallback, rootless-Podman-without-default-change boundary,
  all eight named volumes, and normal OneDrive-compatible package behavior.
  PR #67 remains Draft, and no merge, package, or publication acceptance is
  implied by lifecycle checks or the design checkpoint.
- Treat the August 19 decision as Proceed to unsigned preview integration under
  ADR-019. Signing, `v0.1.3-rc.N`, and representative managed-endpoint
  qualification belong to Task-100 in October after the satisfactory-package
  gate.
- Keep Task-086 as the supported command-based fallback until the replacement
  launcher path is accepted for its stated preview or signed-candidate scope.

### **TASK-089: cdcai Adoption Preparation And Deferred Ownership Transfer**

**Status**: BLOCKED / OWNER-GATED - preparation only; no cdcai mutation
**Type**: C (Repository Migration / Release Ownership / Handoff)
**Priority**: HIGH
**Estimated Effort**: 1-2 days after qualification and authorization
**Task File**:
`.agent_work/tasks/active/TASK-089-cdcai-migration-execution.md`

**Current Boundary**:

- The final cdcai tag and release title are selected before the official build.
- Neither `v0.1.3-preview.N` nor `v0.1.3-rc.N` dictates the final cdcai
  identity.
- Task-100 must complete the signed-candidate and managed-endpoint gate before
  official publication.
- Execution waits for owner qualification, explicit adoption approval, and an
  approved release/package/backlog transfer plan.

---

## Sprint 09 Sequence

1. [x] Preserve the completed Task-099 evidence and activate Task-101 for the
   newly disclosed alert `#76`.
2. [x] Complete Task-101's supported Node/Puppeteer remediation and required
   clean-install, audit, lock-graph, frontend, browser, Windows-helper, and
   Docker-build validation.
3. [x] Merge PR #72 after its final exact-head checks pass, then confirm alert
   `#76` closes without dismissal on the default branch.
4. [x] Bring the accepted Task-101 change into Draft PR #67 and preserve its
   recorded ADR-019 proceed disposition during semantic reconciliation.
5. [x] Require green checks at the new exact PR #67 head.
6. [x] Explicitly resume Task-087 only after steps 4-5 pass.
7. [x] Require green checks on the Task-101 completion / Task-087 resume
   lifecycle head. At `6e0f744`, CI/CD run `32385304086` and Task-087 run
   `32385304052` passed.
8. [x] Validate the PR #67 technical/security remediation design through both
   `.agent_work` validators, diff/link/sanitization checks, current upstream
   toolchain review, and independent runtime/recovery/security-boundary audits.
9. [x] Obtain explicit project-lead approval before IMPLEMENT; approval was
   recorded August 21 for the August 20 remediation design.
10. [ ] Implement the exact-target, trusted-runtime, Windows-trust, durable-
   recovery, cross-session-lock, filesystem, and provider `.env` source gate;
   run adversarial/local/live-isolated validation without reviving earlier
   helper, bypass, admin, runtime-default, or volume-deletion paths.
11. [ ] Require exact-head CI/Task-087 checks and independent technical/security
    re-review before any PR #67 merge decision.
12. [ ] Complete staged-byte/archive verification and the explicit hash-locked
    Python 3.12 provenance-v2 build gate, then integrate a new normal-user
    unsigned preview-package path with accurate manifests, checksums, notices,
    and user guidance.
13. [ ] Test each published `v0.1.3-preview.N` through the actual GitHub download
    path on an approved unmanaged clean Windows machine without security
    exclusions or bypass instructions.
14. [ ] Keep production signing and representative managed-endpoint validation
    scheduled as Task-100 after the ADR-019 satisfactory-package decision.
15. [ ] Select Task-096 next, followed by Task-097. Keep Tasks 091-093 behind
    the stable unsigned package/runtime-shape boundary; Task-091 prepares the
    owner-runnable harness before Task-100.

Task-058 and Task-059 remain conditional stretch work. Task-094 remains
evidence-gated. Task-101 is completed, and Task-087 is active in PR #67 Gate A
IMPLEMENT. Task-099 and Task-101 stay in `tasks/active/` until
Sprint 09 closeout.

---

## Runtime Coordination

Before any Docker- or Podman-dependent work:

1. Tell the user which runtime profile is required.
2. Ask the user to start Docker Desktop and/or the Podman machine.
3. Wait for confirmation before beginning runtime-dependent validation.
4. Allow time for a workstation restart when Docker Desktop requires it.

Planning, documentation, static source review, and branch reconciliation do
not require a runtime startup request.

---

## Related Sources

- [Canonical October Fix-First Roadmap](./context/status/Handoff-Planning/2026-07-23-OCTOBER-FIX-FIRST-IMPLEMENTATION-ROADMAP.md)
- [Pilot And Adoption Track](./context/status/Handoff-Planning/PILOT-FEEDBACK-AND-CDC-AI-ADOPTION-PLAN.md)
- [Task Backlog](./task-backlog.md)
- [Requirements](./requirements.md)
- [Design](./design.md)
- [Completed Tasks](./completed-tasks.md)
