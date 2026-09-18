# TASK-087 Recovery Front Door WIP Handoff

**As Of**: September 18, 2026 checkpoint closeout
**Branch**: `feature/task-087-windows-launcher-prototype`
**Local/Remote/PR Head**: `bd354eb`
**Implementation Baseline**: `d1494f6`
**Implementation Checkpoint**: `b2f6458`
**State**: Source and tests committed locally; documentation/push pending

## Remote Status

PR #67 remains Draft at exact head `bd354eb`. The refreshed PR check set is
green: Python 3.11, Python 3.12, security, frontend, Docker frontend, production
controller contracts/e2e, Windows host-helper contracts, and Trivy pass. The
main-only build is skipped as designed.

## Local Candidate

The working tree adds the fresh-process native recovery front door needed after
`d1494f6`:

- capture the fixed package-root trust and protected recovery root without
  accepting an ambient caller path;
- acquire the environment mutex before scanning protected journals;
- reject pending provider recovery before target-lock acquisition;
- reconstruct certificate and rollback-runtime authority only from the
  authenticated repair chain;
- recover either a still-present exact target or an authenticated exact-absence
  target while deriving the same stable target mutex name;
- complete the ordered lock pair from the already-held environment mutex;
- transfer package-root, protected-root, scan, and lock ownership into
  `HeldWindowsTransactionContext`, run the durable native recovery manager, and
  require a clean rescan before success; and
- make confirmation reject a new repair when authenticated repair recovery is
  pending while allowing a retained context to resume that recovery explicitly.

The launcher app does not call this front door yet. Forward repair mutation
remains disabled, and no live Docker, Podman, certificate, `.env`, or runtime
mutation was run in this session.

### Uncommitted source files

- `launcher/towerscout_launcher/exact_target_confirmation.py`
- `launcher/towerscout_launcher/runtime_target_inputs.py`
- `launcher/towerscout_launcher/windows_mutex.py`
- `launcher/towerscout_launcher/windows_recovery_front_door.py` (new)
- `launcher/towerscout_launcher/windows_recovery_manager_native.py`
- `launcher/towerscout_launcher/windows_recovery_runtime_available_native.py`
- `launcher/towerscout_launcher/windows_transaction_context.py`

### Uncommitted test files

- `tests/unit/test_launcher_exact_target_confirmation.py`
- `tests/unit/test_launcher_runtime_target_inputs.py`
- `tests/unit/test_launcher_windows_mutex.py`
- `tests/unit/test_launcher_windows_recovery_backup_storage.py`
- `tests/unit/test_launcher_windows_recovery_front_door.py` (new)
- `tests/unit/test_launcher_windows_recovery_runtime_available_native.py`
- `tests/unit/test_launcher_windows_recovery_scan.py`
- `tests/unit/test_launcher_windows_transaction_context.py`

Do not stage or remove the ACL-inaccessible `.agent_work/pytest-basetemp-*`
directories. They are local test residue and are unrelated to the candidate.

## Evidence Completed

- Focused recovery/lock/target-input suite: `223/223` passed.
- Direct native-manager certificate/runtime-authority reconstruction regression:
  `2/2` passed.
- All 15 touched source/test files pass Black `--check --no-cache -W 1`,
  blocking and unused-import/local Flake8, compilation, Python 3.11 AST grammar,
  and `git diff --check`.
- All seven touched source files pass strict mypy and Bandit.

Every observed failure was addressed before stopping:

- two parameterized tests initially failed because the new test omitted
  `resolve_present_runtime_target`; the import was added and the complete
  223-test set passed;
- Bandit initially reported two `B110` silent handlers; both paths now record
  explicit control-flow outcomes and Bandit passes;
- earlier formatter/type checks found formatting, a stale constructor
  reference, optional narrowing, and an incompatible callable protocol; those
  were corrected and the replacement Black/strict-mypy runs pass; and
- the failed exact-head query using unquoted PowerShell `@{u}` was a shell parse
  error before execution; separate quoted queries confirmed local, upstream,
  and PR head `bd354eb`.

No failed product check is being carried.

## Completed Resume Sequence

1. The final focused command passed `226/226` after two review-driven adversarial
   tests were added.
2. Full source review found no ownership or sanitization defect; it corrected a
   stale module contract and strengthened present-to-absent/interruption proof.
3. The broad non-native ring passed `849/849`; 12 isolated Windows-native files
   passed `245/245` in fresh external roots.
4. Black, strict mypy, blocking/unused-code Flake8, Bandit, compilation, Python
   3.11 grammar, and diff checks passed. The multiprocessing Flake8 environment
   denial was superseded by clean single-worker runs.
5. Source and tests were committed as `b2f6458`. Next, push the documentation
   ledger and require exact-head workflows before launcher admission.

Before enabling forward mutation, resolve two design boundaries explicitly:

- the current repair journal is a rollback chain, not yet a durable forward
  transaction with every certificate, `.env`, restart, verification, commit,
  and rollback boundary; and
- provider recovery after provider apply needs authenticated terminal-provider
  linkage. The cross-protocol scan currently retains only pending provider
  state, so terminal linkage cannot be inferred or accepted ambiently.

The successful revocation-aware Windows trust proof and isolated Docker/rootless
Podman mutation/recovery evidence remain blocked on a supported context and the
user's explicit runtime-readiness confirmation. Do not run those live mutations
until that confirmation is provided.
