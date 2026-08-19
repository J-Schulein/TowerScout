# TASK-101: extract-zip Advisory Assessment And Release-Gate Disposition

**Status**: IN_PROGRESS - selected August 19, 2026; exact dependency and
supported-path reachability are classified, while the focused Node/Puppeteer
remediation and regression validation remain open
**Priority**: HIGH
**Type**: C (Security Remediation / CI And Release Gate)
**Estimated Effort**: 1-2 days plus CI rerun timing
**Target Sprint**: Sprint 09 immediate gate before Task-087 resumes
**Owner**: TowerScout release owner / active agent support
**Created**: August 19, 2026
**Selected**: August 19, 2026

## Objective

Remove or otherwise safely disposition the high-severity development-only
`extract-zip==2.0.1` path, restore TowerScout's deliberately blocking frontend
dependency-security gate, and provide the compatibility evidence required for
Task-087 implementation, PR #67 merge, and candidate-package work to resume.

## Current Evidence And Boundary

- Dependabot alert `#76` maps to `GHSA-jmr9-qjv8-65gv` /
  `CVE-2026-56876`. GitHub currently lists `extract-zip<=2.0.1` as affected
  and lists no patched `extract-zip` release.
- The exact lock graph is
  `puppeteer@24.19.0 -> @puppeteer/browsers@2.10.8 -> extract-zip@2.0.1`.
- The dependency is development-only. It is not copied into the TowerScout
  Python runtime image or normal-user Windows release ZIP.
- The main `frontend-test` job installs the dependency with
  `PUPPETEER_SKIP_DOWNLOAD=true`, so that failing job does not run browser ZIP
  extraction. Its blocking `npm audit --audit-level=high` correctly stops the
  job before bundle and frontend contract tests.
- The Task-087 Puppeteer jobs can exercise the browser-install path and also
  install a separately pinned Playwright Chromium. Their current
  `PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=false` setting must be replaced with the
  supported skip-download configuration so browser acquisition is explicit
  and non-redundant.
- PR #67 review may continue. New Task-087 implementation, package integration,
  merge, and candidate publication wait for this task. No evidence indicates
  exploitation, and no end-user runtime vulnerability is claimed.

## Requirements (EARS Notation)

- WHEN a blocking high-severity npm advisory affects a supported development or
  CI path, THE PROJECT SHALL remove the vulnerable path or document an approved
  time-bounded residual-risk disposition before merge or publication.
- WHEN remediation crosses a Node or Puppeteer major-version boundary, THE
  PROJECT SHALL update every maintained build/test baseline consistently and
  run proportionate frontend, browser, container-build, and lock-graph
  regression validation.
- WHEN TowerScout supplies a browser executable separately, THE CI WORKFLOW
  SHALL avoid an unnecessary second Puppeteer-managed browser download.
- WHEN Task-101 passes its acceptance gates, THE PROJECT SHALL record the
  evidence and explicitly resume Task-087 without rewriting Task-099's dated
  completion history.

## Acceptance Criteria

- [x] The advisory, exact dependency graph, fixed-version availability,
  supported-path reachability, and end-user runtime boundary are documented.
- [ ] The maintained baseline is Node 22.12+ across CI, the frontend Docker
  build stage, and `package.json`, and is compatible with the selected exact
  Puppeteer 25.x release.
- [ ] The exact Puppeteer/lockfile update removes vulnerable `extract-zip` from
  the installed dependency graph; no broad override or forced downgrade masks
  the advisory.
- [ ] Task-087 browser workflows use one intentional browser-install source and
  do not execute a redundant Puppeteer download path.
- [ ] A clean lockfile install and blocking `npm audit --audit-level=high` pass.
- [ ] Frontend bundle reproducibility, setup-wizard contracts, and provider-
  state regression tests pass.
- [ ] The existing CommonJS Puppeteer consumers still load successfully after
  the major-version update.
- [ ] Task-087 production-controller, simulated-helper browser, and Windows
  host-helper jobs pass after the dependency change.
- [ ] The Docker frontend stage builds successfully with the selected Node
  baseline and still produces the expected committed bundle.
- [ ] GitHub alert `#76` closes through dependency reconciliation without
  dismissal, or any residual-high exception receives the explicit approvals,
  compensating controls, and expiry required by SEC-001.
- [ ] Task-087's tracker and task file are changed from paused to resumed only
  after the blocking gate and required regression evidence pass.

## Dependencies

- Completed Tasks 098 and 099 and their preserved dated security baselines
- Dependabot alert `#76` and the current `package-lock.json` dependency graph
- A supported Puppeteer 25.x release using `@puppeteer/browsers` 3.x, whose
  upstream implementation no longer depends on vulnerable `extract-zip`
- A Node 22.12+ maintained baseline across CI and the Docker build stage
- PR #67 and Task-087 browser-contract workflows for regression validation

## Implementation Plan

1. Reproduce and record the exact npm audit and lock-graph result without
   mutating dependencies.
2. Trial an exact supported Puppeteer 25.x release with Node 22.12+, then
   update the maintained Node build baseline, exact Puppeteer pin, and lockfile
   together without `npm audit fix --force`.
3. Make Task-087 browser acquisition explicit by skipping Puppeteer's
   redundant download and retaining the one pinned browser source used by the
   tests.
4. Run the clean-install, audit, graph, bundle, frontend contract, browser,
   Windows helper, and Docker build validation matrix.
5. Land the remediation as a focused Task-101 change from current `main`,
   reconcile the GitHub alert and CI result, bring the accepted change into PR
   #67, and resume Task-087 only when this gate passes.

---

## Implementation Log

### 2026-08-19 - Selected As Immediate Security Gate

**Objective**: Activate the newly disclosed dependency follow-up before more
Task-087 implementation or release-package work proceeds.

**Context**: PR #67's `frontend-test` job failed after dependency installation
because the intentionally blocking npm audit found high-severity alert `#76`.
The finding opened after Task-099's August 11 closeout and therefore requires a
unique follow-up rather than rewriting that completed task.

**Decision**: Select Task-101 as the immediate Sprint 09 implementation lane.
Pause new Task-087 implementation and candidate-package integration while
keeping PR #67 open for reviewer input. Prefer a focused, validated
Node/Puppeteer upgrade that removes the vulnerable dependency path; do not use
`npm audit fix --force`, weaken the blocking threshold, or dismiss the alert.

**Execution**: Created this active Type C task record and reconciled Task-087
plus the current roadmap and handoff sources to the paused dependency-gate
state. No dependency, workflow, runtime, package, or release state changed by
this documentation-only transition.

**Output**: Task-101 is the sole immediate implementation gate. Task-087's
accepted evidence and Draft PR remain preserved and reviewable, but new
implementation/package work waits for Task-101 acceptance.

**Validation**: PASS for the lifecycle transition on August 19, 2026. The
TowerScout quick workspace checker and canonical `.agent_work` validator
passed, and `git diff --check` found no whitespace errors. Dependency
remediation validation remains open.

**Next**: Implement the focused Node/Puppeteer remediation, execute the full
compatibility matrix, and resume Task-087 only after the blocking gate passes.

---

## Validation Results

### Task Activation - August 19, 2026

**Test Status**: PASS for task activation; implementation validation remains
open

- [x] Active task membership matches `current-tasks.md`.
- [x] Task-101 is represented only as selected active work, not future backlog
  work.
- [x] Task-087 is consistently paused on Task-101 without changing completed
  implementation evidence.
- [x] Quick workspace checker, canonical validator, and `git diff --check`
  pass.
- [x] No provider key, certificate detail, browser artifact, raw support log,
  dependency secret, or package output was added.
