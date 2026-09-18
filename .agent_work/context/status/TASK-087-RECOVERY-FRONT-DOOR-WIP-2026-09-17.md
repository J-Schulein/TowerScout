# TASK-087 Recovery And Forward-Journal WIP Handoff

**As Of**: September 18, 2026 production-integration checkpoint
**Branch**: `feature/task-087-windows-launcher-prototype`
**Local Head**: `2999da0`
**Remote/PR Head**: `a8215b4` before the current publish
**State**: Recovery front door and startup admission are exact-head validated;
durable rollback/forward preparation, certificate/provider/runtime mutation,
terminal verification/commit, exact cleanup, recovery-on-failure, and the
production typed-confirmation handoff are committed. Exact authenticated
pre-arm abort is committed and independently reviewed with zero blockers; no
live mutation has been run

## Remote Status

PR #67 remains Draft. The latest fully validated exact
head is `250ea5b`: CI/CD run `35379191029`,
Task-087 run `35379191026`, and Trivy are fully green; the main-only build is
skipped as designed.

## Current Checkpoint

Checkpoints `9d7f533`, `8a6dd47`, `9bdf51c`, `244eeb7`, and `fa9d3eb` add a
separate authenticated forward repair stream, exact candidate staging/apply,
forward-temp cleanup, and exact native plan preparation without changing the
proven rollback chain:

- the stream is anchored to the exact rollback journal ID and
  `rollback_armed` generation digest;
- its strict sequence covers certificate plan/create/verify/apply, provider
  environment plan/create/verify/apply, runtime stop/start, verification,
  commit, cleanup pending, and cleaned;
- every provider transition binds the exact provider mini-journal ID, sequence,
  and generation digest;
- protected create-only generations and repairable pointers use a separate
  native `repair-*` namespace;
- fresh-process discovery requires a unique exact rollback/forward/provider
  relationship and treats any substitution or ambiguity as blocking; and
- rollback resumption receives the provider stream owned by the authenticated
  forward journal, including its terminal applied state;
- both unpredictable certificate temp names are durable before creation and
  both stable identities are durable before content writes;
- native staging creates only protected-root `CREATE_NEW` regular files with
  the exact current-user/SYSTEM DACL, flushes and rereads exact bytes, and
  verifies by no-follow reopen before the verified generation; and
- retry handles bytes-written/generation-missing and generation-written/pointer-
  missing windows without choosing another name or accepting drift; and
- apply independently reconciles the authenticated pointer, retains both exact
  protected-root sources, accepts only the authenticated original/absence or
  already-applied candidate, atomically replaces and flushes each destination,
  proves both stage paths absent, then persists `certificates_applied`; and
- cleanup accepts exact absence and otherwise deletes only the two recorded host
  identities after revalidating restrictive DACL, size, and full content hash;
  and
- target capture retains the exact twice-reviewed Windows root material only
  for the owner's lifetime, reads the fixed OS bundle through a bounded
  no-follow Docker/Podman command, and fails closed before producing a
  mismatched or oversized replacement plan.

Checkpoint `500a18a` integrates the complete coordinator with the production
typed-confirmation call site. It requires all three ordered authorization hooks,
adopts and terminally revalidates the rebound exact owner, closes authority on
every exit, and emits only fixed public success/failure messages. The legacy
`repair.py` transaction is no longer authoritative, but remains in-tree as a
compatibility/test reference pending final disposition. No live runtime
mutation was run.

Checkpoint `2999da0` closes the remaining rollback-preparation failure window.
Generation 1 binds the exact encrypted blob digests/sizes; same-session and
fresh-process failures before `rollback_armed` delete only those matching
journal-authorized blobs, prove both absent, and append
`aborted_without_mutation` at most once. Ambiguous residue remains preserved and
recovery-pending. A missing/stale pointer after terminal append repairs only
that pointer, and all pre-arm/aborted states are rejected by rollback admission.
Independent review initially found two residual sequence-based routing defects;
both were replaced with one authenticated state predicate and direct concrete-
adapter tests. Re-review returned zero blockers.

Do not stage or remove the ACL-inaccessible `.agent_work/pytest-basetemp-*`
directories. They are local test residue and unrelated to the candidate.

## Evidence Completed

- Exact plan/retained-target/recovery/journal selected ring: `347/347` passed.
- Certificate/recovery/storage staging ring: `197/197` passed.
- Forward journal/storage/scanner/context tests: `65/65` passed before the
  certificate staging extension.
- Broader selected recovery/provider/target/native-storage ring: `700/700`
  passed in a fresh external temp root.
- Native storage file: `76/76` passed in an isolated external temp root;
  its non-native subset passed `93/93`.
- Black, strict mypy, blocking/unused-code Flake8, Bandit, compilation, and
  `git diff --check` pass for the affected source. The added context regression
  also passes no-cache single-worker Black and blocking Flake8.
- Production handoff evidence passes `18/18` focused, `99/99` launcher-facing,
  and `1881/1881` broad selected integration tests in a fresh elevated external
  temp root; Black, strict mypy, blocking Flake8, Bandit, compilation, and diff
  checks pass for the five changed files.
- Pre-arm reconciliation passes `60/60` focused routing tests and `316/316`
  complete recovery-ring tests. The non-helper unit baseline collected `2840`
  tests and exited `0`. Changed-file Black/blocking Flake8, strict isolated
  mypy for final routing modules, medium/high Bandit, compilation, editor
  diagnostics, and diff checks pass. The isolated PowerShell helper module
  still exits nonzero under local endpoint protection; source-only contract
  tests pass and no assertion was weakened.

Earlier test failures were corrected before checkpointing: one synthetic digest
fixture was not 64 characters, one pointer test double hardcoded the rollback
namespace, and shared pytest temp roots produced ACL setup failures. Corrected
fixtures and fresh external-root runs pass. A system Python 3.14 invocation had
no pytest, and a cached Black invocation stalled; the repository Python 3.12
and no-cache single-worker replacements pass. No failed product check is being
carried.

## Completed Resume Sequence

1. Recovery-front-door source/tests were committed as `b2f6458`; documentation
   checkpoint `88d29f2` passed exact-head workflows.
2. Startup admission was committed as `ee76805`; documentation checkpoint
   `b2369bb` passed CI/CD run `35358921493`, Task-087 run `35358921527`, and
   Trivy.
3. The forward journal, durable namespace, cross-protocol provider linkage, and
   direct recovery-provider regression were committed as `9d7f533`; docs at
   `4ced15d` passed all exact-head checks.
4. Exact forward certificate temp metadata plus protected native candidate
   staging through verified generation were committed as `8a6dd47`.
5. Retained-target atomic certificate apply plus durable
   `certificates_applied` proof were committed as `9bdf51c`.
6. Retry-safe exact forward-candidate temp cleanup was committed as `244eeb7`.
7. Exact retained-root plus bounded system-bundle plan preparation was committed
   as `fa9d3eb`.
8. Exact original package/container state capture plus fresh pre-mutation
   readiness authority was committed as `e4261e0`. Focused tests pass
   `146/146`; strict typing, formatting, blocking lint, focused Bandit,
   compilation, and diff checks pass.
9. Durable rollback preparation, verified forward certificate staging, and
   exact provider mini-journal linkage were committed as `1c59252`. The
   affected rollback/forward/provider ring passes `181/181`; mutation remains
   unreachable from the launcher.
10. Certificate apply/exact temp cleanup and provider environment stage/
    promotion were composed as `4b9a44d`. The forward journal reaches current
    `environment_applied`; focused tests pass `16/16`, strict typing and
    focused static/security checks pass, and no launcher call site was added.
11. Exact old-container removal was composed as `e9a8559`; the retained owner
    is consumed at the fixed direct-ID removal boundary after durable
    `runtime_stopping` intent and reaches current `runtime_stopped` only on
    exact successful process evidence.
12. Repaired-profile start/rebinding was composed as `ab5aefa`. Fresh inputs
    and exact absence are captured twice, only the fixed service is started,
    and a new owner is returned after unchanged image/all-volume proof and a
    changed container. The expanded runtime/repair ring passes `371/371` and
    focused static/security checks pass.
13. Terminal verification and commit were composed as `78a77f1`. The stage
    persists `success_verifying`, revalidates exact target/environment/
    certificate authority, runs bounded readiness and provider probes, closes
    target ownership, and only then records `committed`.
14. Exact encrypted rollback-backup cleanup was composed as `464a4fd`. It
    accepts exact absence or deletes only both authenticated blobs, records
    `cleaned` on success, and records `recovery_cleanup_pending` on failure.
15. Full stage coordination and recovery-on-failure were composed as
    `080fef8`. Same-session durable state is rescanned; incomplete repairs
    resume rollback, committed cleanup failures resume cleanup, and terminal
    paired journal history is suppressed in both directions. The selected Gate
    A runtime/recovery/repair ring passes `1818/1818`; focused static/security
    checks pass.
16. Production typed-confirmation integration was composed as `500a18a`.
    Required hooks enforce the pre-mutation, pre-restart, and rebound-owner
    terminal boundaries exactly once; fixed public outcomes replace private
    native failures. The integrated selected ring passes `1881/1881` plus all
    focused static/security checks.

## Resume Point

Push `2999da0` and this documentation checkpoint, then require exact-head
CI/CD, Task-087, and Trivy success. Legacy `repair.py` is retained only as an
explicit unreachable compatibility/test fixture; production imports are gone.
Keep live mutation on hold until runtime readiness is explicitly confirmed,
then complete the revocation-aware fixed-host Windows and approved
Docker/rootless-Podman proof before the Gate A/PR #67 decision.

The successful revocation-aware Windows trust proof and isolated Docker/rootless
Podman mutation/recovery evidence still require a supported context and explicit
runtime-readiness confirmation. Do not run those live mutations before that
confirmation.
