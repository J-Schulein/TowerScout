# Task-087 Controlled Repair Pre-Implementation Checkpoint

**Date**: August 6, 2026
**Authoritative Branch**: `feature/task-087-windows-launcher-prototype`
**Branch Head At Checkpoint**: `522c44b5c3099965acbfce434ee1fd09472f0d66`
**Validated Exact Source**: `4327fb6288f4f8c83202f548a2ba7cb2dcf9bab6`
**Draft PR**: [#67](https://github.com/J-Schulein/TowerScout/pull/67)
**Disposition**: Planning and preservation complete; controlled repair is not
implemented or authorized for live execution by this checkpoint

## Purpose

Preserve the current repository state and establish the rules for extending
the working non-mutating launcher into a transactional provider-TLS repair
prototype. This checkpoint is intentionally written before controlled-mutation
code begins so the next slice does not recreate the browser/helper design,
repeat earlier packaging and validation mistakes, or weaken the Task-086
fallback.

## Preservation Record

The previously uncommitted root-worktree changes were preserved without
altering this prototype branch:

- remote checkpoint branch:
  `checkpoint/task-087-pre-implementation-20260806`
- `133686e` - Task-087 launcher-pivot planning, reviews, ADR, roadmap, and task
  state
- `bfb4697` - unrelated monthly-reporting skill work, deliberately kept in a
  separate commit

The checkpoint branch is a recovery record, not a branch to merge wholesale
into the prototype. Reconcile individual documentation changes deliberately
against the newer Task-087 evidence and source on this branch.

At this checkpoint, the prototype worktree is clean and tracks
`origin/feature/task-087-windows-launcher-prototype`. The current launcher is a
visible Python/Tkinter, preview-only application. The unsigned full-runnable
package passed its authorized development-workstation proof, but no TLS repair,
certificate inspection, trust mutation, signing, managed-endpoint acceptance,
merge, or release has occurred.

## Lessons That Control The Next Slice

1. **Do not revive the browser/helper control plane.** The browser must not
   issue host operations. Keep every existing helper/browser activation flag
   off, bind no new listener, and do not extend PR #64.
2. **Do not couple normal operation to dormant helper code.** The full-package
   run proved that unconditional `TowerScoutHostHelper.ps1` imports could make
   ordinary setup and stop fail under AMSI even when the helper was unused.
   Launcher, setup, stop, repair, and packaging must remain helper-free.
3. **Do not bypass endpoint protections.** No hidden PowerShell worker,
   execution-policy bypass, antivirus exclusion, policy suppression, or
   administrator-only workaround belongs in the normal path. A blocked action
   is a product finding, not a reason to conceal or force the process.
4. **Execute only fixed TowerScout operations.** Retain `shell=False`, fixed
   executable and argument lists, null standard input, bounded timeouts,
   sanitized results, and the proven Windows child-process flags. Never accept
   browser text, free-form commands, executable paths, environment overrides,
   or arbitrary extra arguments.
5. **Bind every action to an exact target.** Before preview or mutation, verify
   the package root, package/source identity, engine, CPU/GPU mode, app port,
   Compose project, image identity, and persistent-volume scope. Refuse
   ambiguous, stale, missing, or changed targets instead of guessing.
6. **Package only committed exact source.** Commit and validate source before
   assembly. Bind the launcher executable and tree to that commit, verify the
   pristine extracted inventory, and do not build evidence from a dirty
   working tree. Preserve the validation-only identity; do not create a tag,
   release, or `v0.1.3-rc.N` identity for prototype artifacts.
7. **Tests must exercise product code and packaged behavior.** Do not use
   fallback implementations or self-referential mocks that reconstruct the
   expected request or operation in the test. Include negative assertions for
   forbidden helper imports, listeners, shell execution, arbitrary inputs,
   sensitive output, and mutation during preview.
8. **Treat repair as a transaction, not a script button.** Require preflight,
   private change preview, explicit confirmation, backup, exact certificate
   selection, staged trust update, verification, stop/restart of the same
   profile, readiness, provider retry, and bounded rollback/recovery.
9. **Fail safely and preserve data.** No normal repair or stop path may delete
   named volumes. Interrupted repair, launcher closure, duplicate clicks,
   subprocess timeout, restart failure, readiness timeout, and provider retry
   failure must end in a sanitized recoverable state with Task-086 guidance.
10. **Keep trust domains separate.** Task-087 repairs application-provider TLS
    for Google and Azure inside the TowerScout runtime. It must not silently
    modify the Windows trust store, install a Podman Compose provider, or alter
    Podman-machine image-pull/build trust; those are separate decisions.
11. **Protect evidence and secrets.** Do not retain provider keys, certificate
    subjects/thumbprints, raw provider or subprocess output, local paths,
    environment dumps, browser traces, or unsanitized logs. Record only fixed
    categories, bounded state transitions, hashes, and redacted outcomes.
12. **CI availability is not CI success.** Local implementation and validation
    may continue during a GitHub Actions outage, but no missing, delayed, or
    timed-out workflow is evidence of a pass. Merge and release gates remain
    closed until the required workflows run successfully after recovery.

## Controlled Repair Implementation Order

1. Define the repair transaction and recovery state machine before adding a UI
   action.
2. Add a fixed, previewable operation plan bound to the exact runtime profile.
3. Add unit and package-boundary tests for success, rejection, timeout,
   interruption, rollback, duplicate-operation, and redaction behavior.
4. Preserve Task-086 as the reviewed manual fallback. Use a fixed native
   adapter for the launcher because the ordinary no-bypass script proof is
   blocked by effective workstation policy; do not copy shell behavior or
   expose raw output.
5. Prove backup, staging, verification, and recovery with isolated fixtures
   before exercising a real container trust change.
6. After explicit runtime confirmation, run the first live repair only against
   an isolated Docker CPU validation package with unique port, Compose project,
   and named volumes. Preserve the existing TowerScout installation.
7. Verify restart, readiness, Google connectivity, failure recovery, and the
   unchanged manual fallback. Add Azure and Podman only after the Docker slice
   passes without expanding the trust boundary.
8. Rebuild from a clean exact commit, rerun local and recovered CI validation,
   then keep signing and representative managed-endpoint acceptance as separate
   candidate-inclusion gates.

## Start Checklist

- [x] Existing root-worktree changes preserved on a dated remote checkpoint
  branch.
- [x] Prototype work isolated on a clean branch and separate worktree.
- [x] Non-mutating exact-source package evidence preserved.
- [x] Task-086 manual repair remains present and supported.
- [x] Dormant helper and browser mutation remain disabled and out of the
  validation package.
- [x] Prior failures and corrective lessons recorded above.
- [x] Controlled-repair state machine and rollback contract reviewed.
- [x] Fixed native adapter and negative security tests implemented.
- [x] User confirms the required container runtime before any live validation.
- [x] Live mutation receives a separately stated target, scope, and recovery
  check before execution.
- [ ] GitHub Actions completes successfully before merge consideration.
- [ ] Production-shaped signed artifact passes representative managed-endpoint
  validation before candidate inclusion.

## Post-Checkpoint Outcome

Commits `27cc22d` and `3e77afd` implemented the native fixed repair transaction
and approved Podman-provider preflight. After UI integration, the targeted
launcher/runtime selection passed 130 tests
using repository-local pytest temp storage. After an exact-target preflight,
the current source adapter completed one Google/Docker transaction against the
isolated `towerscout-task087-full-4327fb6` project. The post-check found healthy
`setup_required` readiness, a matching image digest, persisted CA settings and
certificate files, no remaining private staging directory, and all eight named
volumes present.

Podman did not proceed to mutation: its engine was reachable, but Compose
resolved no approved non-Docker-Desktop provider. No provider was installed or
silently substituted. The coordinator remains fail-closed by default. Commit
`0901cc5` subsequently connected it to a separate visible repair action with
an exact public target summary, typed `REPAIR TLS AND RESTART` confirmation,
and sanitized progress and recovery states.

## Immediate Next Action

The exact-source `0901cc5b8a2e` launcher-policy package passed structural and
archive verification and opened responsively against its non-runnable
sentinel. Generate a full-runnable package from that exact source in an
approved environment, then add UI-driven Google, Azure, and controlled
recovery proofs. The local no-bypass PowerShell policy blocks the normal
package generator; do not bypass it or substitute an older-source base.
Validate Podman only after its separately managed approved provider
precondition is satisfied. GitHub Actions, signing, and representative
managed-endpoint acceptance remain separate gates.
