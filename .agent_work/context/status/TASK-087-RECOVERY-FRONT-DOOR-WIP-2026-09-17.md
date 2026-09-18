# TASK-087 Recovery And Forward-Journal WIP Handoff

**As Of**: September 18, 2026 certificate-staging checkpoint
**Branch**: `feature/task-087-windows-launcher-prototype`
**Local Head**: `8a6dd47`
**Remote/PR Head**: `4ced15d`
**State**: Recovery front door and startup admission are exact-head validated;
durable forward linkage and certificate candidate staging are committed locally;
certificate apply and transaction integration remain disabled

## Remote Status

PR #67 remains Draft at exact head `4ced15d`. CI/CD run `35362357713`, Task-087
run `35362357721`, and Trivy are green: Python 3.11, Python 3.12, security,
frontend, Docker frontend, production controller contracts/e2e, and Windows
host-helper contracts pass. The main-only build is skipped as designed.

## Current Checkpoint

Checkpoints `9d7f533` and `8a6dd47` add a separate authenticated forward repair
stream and exact certificate candidate staging without changing the proven
rollback chain:

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
  missing windows without choosing another name or accepting drift.

The checkpoint intentionally provides no certificate apply executor, forward
cleanup owner, or live runtime mutation. The legacy `repair.py`
transaction is still not authoritative and forward mutation remains disabled.

Do not stage or remove the ACL-inaccessible `.agent_work/pytest-basetemp-*`
directories. They are local test residue and unrelated to the candidate.

## Evidence Completed

- Certificate/recovery/storage selected ring: `197/197` passed.
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

## Resume Point

Add authenticated certificate apply and cleanup ownership, then refactor
`repair.py` around the immutable resolved target, forward journal,
and durable rollback manager. Preserve the `BEFORE_MUTATION`, `BEFORE_RESTART`,
and `TERMINAL` revalidation order and keep live mutation disabled until the
integrated path is complete and reviewed.

The successful revocation-aware Windows trust proof and isolated Docker/rootless
Podman mutation/recovery evidence still require a supported context and explicit
runtime-readiness confirmation. Do not run those live mutations before that
confirmation.
