# TASK-087 Recovery And Forward-Journal WIP Handoff

**As Of**: September 18, 2026 certificate-temp-cleanup checkpoint
**Branch**: `feature/task-087-windows-launcher-prototype`
**Local Head**: `244eeb7`
**Remote/PR Head**: `c62f759`
**State**: Recovery front door and startup admission are exact-head validated;
durable forward linkage, candidate staging/apply, and exact forward-temp cleanup
are committed locally; transaction integration remains disabled

## Remote Status

PR #67 remains Draft at pushed head `c62f759`; its specialized/security checks
pass while Python 3.11/3.12 remain in progress. Validated exact head `9873c42`
is fully green in CI/CD run `35364176635`, Task-087 run `35364176462`, and
Trivy. The main-only build is skipped as designed.

## Current Checkpoint

Checkpoints `9d7f533`, `8a6dd47`, `9bdf51c`, and `244eeb7` add a separate
authenticated forward repair stream, exact candidate staging/apply, and
forward-temp cleanup without changing the proven rollback chain:

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
  identities after revalidating restrictive DACL, size, and full content hash.

The checkpoint intentionally provides no integrated live runtime mutation. The
legacy `repair.py`
transaction is still not authoritative and forward mutation remains disabled.

Do not stage or remove the ACL-inaccessible `.agent_work/pytest-basetemp-*`
directories. They are local test residue and unrelated to the candidate.

## Evidence Completed

- Retained-target/recovery/journal selected ring: `339/339` passed.
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

## Resume Point

Refactor `repair.py` around the immutable resolved target, forward journal,
and durable rollback manager. Preserve the `BEFORE_MUTATION`, `BEFORE_RESTART`,
and `TERMINAL` revalidation order and keep live mutation disabled until the
integrated path is complete and reviewed.

The successful revocation-aware Windows trust proof and isolated Docker/rootless
Podman mutation/recovery evidence still require a supported context and explicit
runtime-readiness confirmation. Do not run those live mutations before that
confirmation.
