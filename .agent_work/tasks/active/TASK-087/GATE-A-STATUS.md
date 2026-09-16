# TASK-087 Gate A Status

**As Of**: September 16, 2026
**Branch**: `feature/task-087-windows-launcher-prototype`
**Implementation Head**: `7b96a6b8b5a0f77667ef2476a7767795ba8242e3`
**Validated Exact Head**: `7b96a6b8b5a0f77667ef2476a7767795ba8242e3`
**Local Candidate**: Evidence reconciliation only; no uncommitted source
candidate
**Current Checkpoint**: Slices 2-3 exact-target confirmation wiring complete.
The latest fixed-host retry returned only `chain_unverified` for both approved
hosts, so slice 4 remains partial. Slice 5 has independently reviewed
protected-state/DPAPI and secure-absence foundations. Its pure byte-transform/
state-classification prerequisite is committed, independently reviewed, and
exact-head validated at `0efeff7`. Independently reviewed checkpoint `1c45445`
adds journal-gated native temp staging and passed exact-head CI/CD run
`35005869321`, Task-087 run `35005869200`, and Trivy. Durable journal storage
and ACL-preserving atomic promotion/replacement remain open. Documentation
checkpoint `42180b1` passed CI/CD run `35006846090`, Task-087 run
`35006846025`, and Trivy. Independently reviewed checkpoint `8bb6b33` adds strict
protected generation/pointer codecs and fail-closed environment-temp chain
selection. Its exact-head CI/CD run `35010304611`, Task-087 run `35010304675`,
and Trivy passed; the main-only build skipped as designed. No native persistence,
pointer repair, backup, or recovery action exists. Documentation checkpoint
`e86c41c` passed exact-head CI/CD run `35011029262`, Task-087 run `35011029309`,
and Trivy. The next checkpoint, `53bed46`, added only the root-owned pure
orchestration port and passed exact-head CI/CD run `35013069183`, Task-087 run
`35013069124`, and Trivy; the main-only build was neutral as designed. The native
file adapter and pointer protocol remained open at that point. Documentation
checkpoint `2e0f90e` passed exact-head CI/CD run `35014300773`, Task-087 run
`35014300816`, and Trivy. Independently reviewed
implementation checkpoint `4a96dd2` adds the native generation-file adapter and
passed exact-head CI/CD run `35016174147`, Task-087 run `35016174145`, and
Trivy; the main-only build was neutral as designed. Documentation checkpoint
`050dc5c` passed exact-head CI/CD run `35018010005`, Task-087 run `35018010006`,
and Trivy; the main-only build was neutral as designed. Independently reviewed
implementation checkpoint `221612c` adds pure pointer-aware load and
ensure/repair orchestration above the native generation-file adapter. It passed
exact-head CI/CD run `35019327044`, Task-087 run `35019327058`, and Trivy; the
main-only build was neutral as designed. Independently reviewed implementation
checkpoint `95ca37d` adds native protected pointer reads and write-through
replacement with exact success-path verification; same-call API-error
reconciliation and recovery remain open. Initial and final exact-diff reviews
returned `CLEAN/PASS` with no actionable Low-or-higher findings. It passed
exact-head CI/CD run `35021545053`, Task-087 run `35021545062`, and Trivy; the
main-only build was neutral as designed.
Documentation checkpoint `145e0b9` then passed exact-head CI/CD run
`35022713082`, Task-087 run `35022713013`, and Trivy; the main-only build was
neutral as designed. Independently reviewed implementation checkpoint `ebb9d69`
accepts an ordinary move API error as success only after same-call source-
absence and exact destination identity/DACL/path/size/byte proof. Restart
classification, durable temp-identity binding, and cleanup remain open. Its
focused, adjacent, and full launcher tests pass `39/39`, `105/105`, and
`1647/1647`; initial and final independent reviews returned `CLEAN/PASS` with no
actionable Low-or-higher findings. It passed exact-head CI/CD run `35025200641`,
Task-087 run `35025200635`, and Trivy; the main-only build was neutral as
designed.
Exact-head validated checkpoint `31f63f2` adds a pure authenticated recovery-
pointer transition model. It classifies restart outcomes while retaining the
sealed-chain trust boundary, but it does not wire native transition
persistence, cleanup, backup/recovery action, staging/promotion, `.env`
replacement, or runtime mutation. Focused tests pass `29/29`, adjacent tests
pass `134/134`, and the complete launcher suite passes `1665/1665`; exact-head
CI/CD, Task-087, and Trivy checks are green, while the main-only build is
neutral as designed.
Independently reviewed and exact-head validated checkpoint `5252c7a` adds
create-only protected persistence and fresh-process authenticated reload for
pointer-transition generations while the protected root remains held. It
extends the native generation adapter only for the exact transition-generation
namespace. It does not create, replace, promote, or delete pointer files and
does not mutate `.env`, repair state, or runtime state. Focused transition-
storage tests pass `6/6`, integrated transition/journal/native-storage tests
pass `83/83`, and the complete launcher suite passes `1672/1672`. Exact-head
CI/CD run `35113158404`, Task-087 run `35113158461`, and Trivy are green; the
main-only build is neutral as designed.
Independently reviewed implementation checkpoint `7341997` consumes that
authenticated plan to create the exact named pointer temp, enforce the
current-user/SYSTEM protected DACL, write and flush canonical pointer bytes,
verify them on the creation handle and a no-follow reopen, and persist
`POINTER_TEMP_CREATED` with the verified stable identity. Docstring-only exact
head `dd0d42d` accurately records that boundary. Focused tests pass `55/55`,
the adjacent recovery ring passes `118/118`, and the complete launcher suite
passes `1681/1681`. CI/CD run `35117176978`, Task-087 run `35117176506`, and
Trivy are green at `dd0d42d`; the main-only build is neutral as designed. No
destination promotion, cleanup, backup/recovery action, `.env` replacement,
repair, or runtime mutation is enabled.
Independently reviewed and exact-head validated checkpoint `299ae96` consumes
that authenticated created record through a separate promotion-only port. It
verifies the exact source and prior destination or absence before moving only
the recorded temp, reconciles ordinary API errors only from exact completed-
move evidence, and requires `MOVE_COMPLETED` without adding another transition
state. Focused tests pass `79/79`, the adjacent recovery ring passes `142/142`,
and the complete launcher suite passes `1705/1705`. CI/CD run `35120250430`,
Task-087 run `35120250774`, and Trivy are green; the main-only build is neutral
as designed.
Independently reviewed and exact-head validated checkpoint `53b618b` removes
only the exact zero-byte orphan authorized by an authenticated
`POINTER_TEMP_PLANNED` record. A cleanup-only native adapter opens the recorded
leaf without following reparse points, twice verifies its stable identity,
zero size, exact path, local regular single-link facts, and protected current-
user/SYSTEM DACL, marks that held handle for deletion, closes it, and proves
absence before exact creation is retried. Written or drifted objects are
preserved, and `POINTER_TEMP_CREATED` is never routed through cleanup. Focused
cleanup tests pass `13/13`, transition-storage tests pass `20/20`, the adjacent
recovery ring passes `220/220`, and the complete launcher suite passes
`1721/1721`. CI/CD run `35123786391`, Task-087 run `35123786272`, and Trivy are
green; the main-only build is neutral as designed. Backups, full recovery
states, `.env` replacement, repair, and runtime mutation remain disabled.
Independently reviewed and exact-head validated checkpoint `d6ce415` adds
strict purpose-separated encrypted exact-state environment and fixed-
certificate backup envelopes bound to the complete journal stream. Focused
tests pass `10/10`, adjacent backup/journal/protected-state tests pass `47/47`,
and the complete launcher suite passes `1731/1731`. Two independent reviews
returned `CLEAN/PASS` with no actionable Low-or-higher findings. CI/CD run
`35126475641`, Task-087 run `35126475645`, and Trivy are green; the main-only
build is neutral as designed. Backup persistence, journal backup states,
restore, `.env` replacement, repair, and runtime mutation remain disabled.
Independently reviewed and exact-head validated checkpoint `1ecfd5e` adds a
strict singleton `backup_preparing` generation. It authenticates both sealed
backups against the exact stream before generating two independent
unpredictable names, records only exact prior-state summaries, persists through
the existing root-held immutable append path, and returns only after complete
authenticated reread. Focused preparation/journal tests pass `36/36`, and the
complete launcher suite passes `1741/1741`. Three independent reviews returned
`CLEAN/PASS`. CI/CD run `35129510795`, Task-087 run `35129510839`, and Trivy are
green; the main-only build is neutral as designed. Backup blobs,
`backup_verified`, `rollback_armed`, restore, and mutation remain disabled.
Independently reviewed and exact-head validated checkpoint `21aba57` reloads
that durable singleton under the same held protected root, reauthenticates both
envelopes and every prior-state summary, and creates only the exact two planned
DPAPI ciphertext blobs. Each create uses `CREATE_NEW`, the protected current-
user/SYSTEM DACL, complete write plus flush, and same-handle and no-follow reopen
verification of stable identity, path, local regular single-link facts,
security, size, and exact bytes. Partial or ambiguous artifacts are preserved.
Focused tests pass `22/22`, adjacent recovery tests pass `161/161`, and the
complete launcher suite passes `1763/1763`. CI/CD run `35133270798`, Task-087
run `35133270809`, and Trivy are green; the main-only build is neutral as
designed. `backup_verified`, `rollback_armed`, restore, and mutation remain
disabled.
Independently reviewed and exact-head validated checkpoint `92acf29`
reauthenticates both original sealed backups, reloads the singleton preparation
under the held protected root, and freshly reverifies both exact encrypted blob
files before appending and reauthenticating generation 2 `backup_verified`.
Focused tests pass `83/83`, adjacent recovery tests pass `212/212`, and the
complete launcher suite passes `1776/1776`. CI/CD run `35136560668`, Task-087
run `35136560565`, and Trivy are green; the main-only build is neutral as
designed. `rollback_armed`, restore, cleanup, and mutation remain disabled.
Independently reviewed and exact-head validated checkpoint `deee6ab` reloads
exactly that authenticated two-generation chain, reconstructs both expected
blob receipts only from durable records, freshly reverifies both exact files
under one held protected-root interval, and appends and reauthenticates
generation 3 `rollback_armed`. Focused tests pass `47/47`, adjacent recovery
tests pass `105/105`, and the complete launcher suite passes `1781/1781`.
CI/CD run `35141054176` passed. Task-087 run `35141054097` passed on its failed-
job rerun after an unrelated first-attempt legacy helper cleanup failure;
Trivy is green and the main-only build is neutral as designed. No pointer
update, restore, cleanup, `.env` replacement, certificate write, repair, or
runtime mutation is enabled.
Independently reviewed and exact-head validated checkpoint `7b96a6b` reloads
exactly that authenticated three-generation chain, reconstructs both expected
receipts only from its durable records, freshly reverifies both exact encrypted
blobs under one held protected-root interval, and repairs the metadata pointer
to the exact generation-3 `rollback_armed` tip. Already-current activation is
idempotent and a failed pointer write is safely retryable. Focused tests pass
`18/18`, the adjacent recovery ring including the native pointer adapter passes
`183/183`, and the complete launcher suite passes `1785/1785`. CI/CD run
`35144293843`, Task-087 run `35144293704`, and Trivy passed; the main-only build
is neutral as designed. No recovery action, cleanup, `.env` replacement,
certificate write, repair, or runtime mutation is enabled.
**Draft PR**: [#67](https://github.com/J-Schulein/TowerScout/pull/67)
**Overall State**: IN_PROGRESS / Gate A source implementation
**Gate A Exit**: NOT MET
**Runtime Mutation**: Disabled; exact-target confirmation is locally wired but
cannot perform repair

## Purpose And Authority

This is the canonical detailed burn-down for the nine approved Gate A source
slices. [`current-tasks.md`](../../../current-tasks.md) remains the authoritative
sprint/task selection source. The
[`August 20 technical/security remediation design`](./TECHNICAL-SECURITY-REMEDIATION-DESIGN-2026-08-20.md)
remains the authority for requirements, implementation boundaries, and Gate A
exit criteria. The
[`main Task-087 file`](../TASK-087-host-side-tls-repair-control-plane.md)
remains the chronological evidence record.

Status in this file answers four separate questions:

- **COMPLETE**: the approved source outcome is implemented, adversarially
  tested, independently reviewed, and represented by a committed checkpoint.
- **BUILT BUT UNWIRED**: material production components exist and have been
  reviewed, but the launcher cannot use them end to end.
- **PARTIAL**: only some of the approved outcome exists.
- **NOT STARTED**: the Gate A replacement outcome has not been implemented,
  even if older prototype behavior exists.
- **VALIDATION CONTINUES**: incremental checks exist, but the final Gate A
  validation set and exit decision remain outstanding.
- **IMPLEMENTED / REVIEW PENDING**: the approved source outcome and focused
  evidence exist locally, but the required independent review and committed
  checkpoint have not yet closed the slice.

## Fixed Gate A Burn-Down

| ID | Approved slice | State | Material evidence already completed | Remaining before this slice is complete |
| ---: | --- | --- | --- | --- |
| 1 | Contracts and models | **COMPLETE** | Immutable target/plan contracts, redacted summaries, mutation-off default, Windows-path portability, and adversarial contracts are checkpointed from `7ad221d` through `0eebe7b`. | Keep the contracts stable while later integration consumes them. |
| 2 | Runtime resolver | **COMPLETE** | The reviewed resolver/facade chain through `db7aee8` remains unchanged. The September 14 checkpoint makes the production confirmation coordinator call that facade with only the provider enum, retain its exact owner across typed confirmation, and close it on rejection, timeout, error, invalid stage, or the mutation-disabled terminal path. Independent review findings are reconciled. | Keep the exact owner contract stable while later transaction work consumes it. |
| 3 | Target resolver | **COMPLETE** | The reviewed normalized target, observation, ownership, and factory chain through `db7aee8` remains unchanged. The September 14 checkpoint displays only `PublicRepairSummary`, revalidates immediately before accepting confirmation, and requires `BEFORE_MUTATION`, `BEFORE_RESTART`, and `TERMINAL` exactly once in order. A skipped, repeated, or backward stage closes the owner and invalidates authorization. Current execution reaches `BEFORE_MUTATION` and then fails closed because mutation is disabled; slice 7 must implement the authorized stop/recreation semantics behind later hooks. Independent review findings are reconciled. | Preserve these hooks while slice 7 implements the authorized stop/recreation semantics. |
| 4 | Windows trust proof | **PARTIAL** | The reviewed Windows-root eligibility and exact-root selection contracts remain. The September 14 review remediation creates a bounded exact Windows-`CA` plus server-intermediate snapshot, supplies it as an additional build store, rejects every candidate whose intermediate fingerprint is outside that snapshot, retains one exclusive filtered root store, restores cache-only chain revocation, disables AIA/root auto-update, and applies SSL hostname policy. A fresh sanitized retry returned `chain_unverified` for both Azure and Google, consistent with the earlier detailed offline/unknown cached-revocation failure. Earlier disposable network-disabled Docker and rootless-Podman checks showed exactly one selected PEM crossed the boundary, but that selection predates restored revocation and therefore proves transport containment only, not current end-to-end trust success. No certificate bytes or identity were stored as evidence. | Obtain a successful fixed-host proof with current revocation enforcement in a supported Windows context, then repeat the one-selected-root Docker and rootless-Podman containment proof from those same reviewed bytes. |
| 5 | Windows security proof | **PARTIAL** | Independently reviewed checkpoint `2edcb8e` resolves Local AppData through the Windows Known Folder API; creates only `TowerScout\Recovery\v1`; requires each state directory to have a protected, exact current-user/SYSTEM full-control DACL; retains and revalidates its handle-bound hierarchy; and adds UI-forbidden, current-user-only, purpose-separated DPAPI. Earlier checkpoints `2d37e66`, `f7d21a9`, and `16604c8` provide the handle/file-ID, owner, DACL, reparse, hard-link, supported cloud/OneDrive, secured cross-session mutex, and ordered `.env`/target-lock foundations. Checkpoint `14b77e4` retains package-root trust, binds canonical absence evidence to that root identity, and rechecks the exact `.env` child through a no-follow native open. Checkpoint `0efeff7` adds the pure planner with bounded strict UTF-8/BOM/NUL policy, exact two-setting changes that preserve unrelated bytes/newline form, immutable original/candidate hashes, and exact original/candidate/absent/third-state classification; focused/full launcher validation, independent review, and exact-head workflows pass. Independently reviewed and exact-head validated checkpoint `1c45445` adds a private journal-gated staging boundary: unpredictable same-directory `CREATE_NEW`, exact protected current-user/SYSTEM DACL, zero-byte created-state receipt before write, complete bounded writes, `FlushFileBuffers`, same-handle readback, close, and no-follow reopen identity/DACL/hash verification before the verified receipt. Its Windows-native smoke uses an isolated pytest temp only. | Add the durable journal implementation, native destination promotion/replacement, indeterminate-result classification, and exact orphan cleanup; then exercise all slice 5 primitives together. |
| 6 | Recovery manager | **PARTIAL** | Checkpoints through `31f63f2` provide authenticated environment-journal storage, metadata-pointer handling, same-call move reconciliation, and the pure pointer-transition/restart-classification model. Checkpoint `5252c7a` adds create-only protected transition-generation persistence and fresh-process authenticated reload. Checkpoint `7341997` plus `dd0d42d` add exact planned pointer-temp creation, full native verification, and durable stable-identity binding. Independently reviewed and exact-head validated checkpoint `299ae96` promotes only that authenticated temp after exact source/prior-destination proof and requires exact `MOVE_COMPLETED` evidence under the held protected root. Independently reviewed and exact-head validated checkpoint `53b618b` removes only the exact authenticated planned-state zero-byte orphan by its verified held handle and proves absence before creation retry. Checkpoint `d6ce415` adds pure purpose-separated encrypted exact-state environment and fixed-certificate backup envelopes bound to the journal stream. Independently reviewed and exact-head validated checkpoint `1ecfd5e` adds authenticated singleton `backup_preparing` intent with exact future blob names and prior-state summaries. Independently reviewed and exact-head validated checkpoint `21aba57` reloads that durable authority under the same root hold and creates and fully verifies only the two exact planned encrypted blobs while preserving ambiguous artifacts. Independently reviewed and exact-head validated checkpoint `92acf29` reauthenticates the sealed sources, freshly reverifies both exact blobs under that held root, and persists and reauthenticates `backup_verified`. Independently reviewed and exact-head validated checkpoint `deee6ab` reconstructs both expected receipts from that authenticated chain, freshly reverifies both exact blobs under one held-root interval, and appends and reauthenticates generation 3 `rollback_armed`. Independently reviewed and exact-head validated checkpoint `7b96a6b` freshly reverifies both exact blobs under the same root hold and repairs the metadata pointer to the exact armed tip with idempotent current-pointer behavior and safe retry after write failure. | Add full recovery states, fresh-process idempotent recovery, verified rollback, cleanup-pending retention, and cross-protocol scanning. |
| 7 | Transaction refactor | **NOT STARTED** | The older prototype transaction and historical live evidence remain available as behavior references only. | Refactor `repair.py` to consume the immutable resolved target and recovery manager, remove process-memory-only backup and unchecked rollback, and enforce pre-write/pre-restart/terminal revalidation. |
| 8 | Provider installer hardening | **PARTIAL** | Historical checkpoint `3990bc0` closed provider dependency/wheel reproducibility and version verification. Independently reviewed checkpoint `7a0c35a` makes the installed `site-packages` inventory deterministic and provider-only by replacing pip-added metadata with the exact retained wheel inventory, prevents wrapper/bootstrap drift, and suppresses bytecode across the current PowerShell provider path. Its ambient Python compatibility probe is not authentication. | Reuse the protected atomic `.env` contract, change only `PODMAN_COMPOSE_PROVIDER`, remove persistent whole-file plaintext backup/output, and add crash/orphan reconciliation. |
| 9 | Gate A source validation and review | **VALIDATION CONTINUES** | Every completed increment has focused tests and independent review. Secure-absence checkpoint `14b77e4` passed its exact-head gates. Pure-planner checkpoint `0efeff7` passes `47/47` focused and `1536/1536` launcher tests plus static checks and independent source review. Staging checkpoint `1c45445` passes `24/24` focused tests, including real Windows ctypes and retained-native-handle smokes, and `169/169` adjacent tests plus focused static/security checks and independent review. Checkpoint `8bb6b33` passes `26/26` focused journal, `152/152` adjacent, and `155/155` isolated late-launcher tests plus focused static/security checks and CLEAN/PASS corrected-diff independent review. Its exact-head CI/CD run `35010304611`, Task-087 run `35010304675`, and Trivy passed. Documentation checkpoint `e86c41c` passed exact-head CI/CD run `35011029262`, Task-087 run `35011029309`, and Trivy; both main-only builds skipped as designed. Independently reviewed checkpoint `53bed46` passes `20/20` focused, `164/164` adjacent, and `167/167` isolated late-launcher tests plus focused static/security checks and CLEAN/PASS review with no actionable Low-or-higher findings. Its exact-head CI/CD run `35013069183`, Task-087 run `35013069124`, and Trivy passed; the main-only build was neutral as designed. Documentation checkpoint `2e0f90e` passed exact-head CI/CD run `35014300773`, Task-087 run `35014300816`, and Trivy. Independently reviewed checkpoint `4a96dd2` passes `18/18` focused, `182/182` adjacent, and `185/185` isolated late-launcher tests plus focused static/security checks, a real Windows round trip, and two CLEAN/PASS reviews with no actionable Low-or-higher findings. Its exact-head CI/CD run `35016174147`, Task-087 run `35016174145`, and Trivy passed; the main-only build was neutral as designed. Independently reviewed checkpoint `221612c` passes `19/19` focused, `192/192` adjacent, and `195/195` isolated late-launcher tests plus focused static/security checks and final CLEAN/PASS review. Its exact-head CI/CD run `35019327044`, Task-087 run `35019327058`, and Trivy passed; the main-only build was neutral as designed. Independently reviewed checkpoint `95ca37d` passes `32/32` focused, `206/206` adjacent, and `209/209` isolated late-launcher tests plus a real Windows replacement round trip, focused static/security checks, and final CLEAN/PASS review. Its exact-head CI/CD run `35021545053`, Task-087 run `35021545062`, and Trivy passed; the main-only build was neutral as designed. | After slices 2-8 are integrated, run the final broad/adversarial set, fresh-process recovery, isolated Docker CPU then approved rootless-Podman CPU mutation/recovery, OneDrive and two-session Windows proofs, all-volume verification, exact-head workflows, and final independent review. |

**Slice 9 validation ledger continuation**: Independently reviewed checkpoint
`ebb9d69` passes `39/39` focused, `105/105` adjacent, and `1647/1647` complete
launcher tests plus Black, strict mypy, blocking Flake8, medium/high Bandit,
compilation, diagnostics, task-structure, and diff checks. Initial and final
exact-diff reviews returned `CLEAN/PASS` with no actionable Low-or-higher
findings. Its exact-head CI/CD run `35025200641`, Task-087 run `35025200635`, and
Trivy passed; the main-only build was neutral as designed.

**Slice 9 validation ledger continuation**: Exact-head checkpoint `31f63f2`
passes `29/29` focused pointer-transition tests, `134/134` adjacent recovery
tests, and `1665/1665` complete launcher tests. CI/CD, Task-087, and Trivy
checks are green; the main-only build is neutral as designed. This is pure
classification only and does not authorize cleanup, recovery, `.env`
replacement, or runtime mutation.

**Slice 9 validation ledger continuation**: Independently reviewed checkpoint
`5252c7a` passes `6/6` focused transition-storage tests, `83/83` integrated
transition/journal/native-storage tests, and `1672/1672` complete launcher
tests. Black, strict mypy, focused blocking Flake8, medium/high Bandit, editor
diagnostics, and `git diff --check` pass. Independent review returned
`CLEAN/PASS` with no actionable Low-or-higher findings. Its exact-head CI/CD
run `35113158404`, Task-087 run `35113158461`, and Trivy passed; the main-only
build was neutral as designed. This checkpoint persists and reloads sealed
transition generations only and does not authorize pointer-file mutation,
cleanup, recovery, `.env` replacement, or runtime mutation.

**Slice 9 validation ledger continuation**: Independently reviewed
implementation checkpoint `7341997` and docstring-only exact head `dd0d42d`
pass `55/55` focused pointer-temp tests, `118/118` adjacent recovery tests, and
`1681/1681` complete launcher tests. Black, strict mypy, focused blocking
Flake8, medium/high Bandit, compilation, editor diagnostics, and
`git diff --check` pass. Corrected independent review returned `CLEAN/PASS`
with no actionable Low-or-higher findings. Exact-head CI/CD run `35117176978`,
Task-087 run `35117176506`, and Trivy passed at `dd0d42d`; the main-only build
was neutral as designed. This checkpoint creates and verifies only the exact
planned pointer temp and persists its identity. It does not promote or delete
the file or authorize recovery, `.env` replacement, repair, or runtime mutation.

**Slice 9 validation ledger continuation**: Independently reviewed and exact-
head validated checkpoint `299ae96` passes `79/79` focused promotion tests,
`142/142` adjacent recovery tests, and `1705/1705` complete launcher tests.
Black, strict mypy, focused blocking Flake8, medium/high Bandit, compilation,
editor diagnostics, and `git diff --check` pass. Independent review returned
`CLEAN/PASS` with no actionable Low-or-higher findings. Exact-head CI/CD run
`35120250430`, Task-087 run `35120250774`, and Trivy passed; the main-only build
was neutral as designed. This checkpoint promotes only the authenticated
pointer temp and does not authorize cleanup, backups, recovery, `.env`
replacement, repair, or runtime mutation.

**Slice 9 validation ledger continuation**: Independently reviewed and exact-
head validated checkpoint `53b618b` passes `13/13` focused cleanup tests,
`20/20` transition-storage tests, `220/220` adjacent recovery tests, and
`1721/1721` complete launcher tests. Black, strict mypy, focused blocking
Flake8, medium/high Bandit, compilation, editor diagnostics, and
`git diff --check` pass. Two independent reviews returned `CLEAN/PASS` with no
actionable Low-or-higher findings. Exact-head CI/CD run `35123786391`, Task-087
run `35123786272`, and Trivy passed; the main-only build was neutral as designed.
This checkpoint removes only the exact zero-byte orphan authorized by an
authenticated `POINTER_TEMP_PLANNED` record through verified held-handle
deletion and does not clean `POINTER_TEMP_CREATED` or authorize backups,
recovery, `.env` replacement, repair, or runtime mutation.

**Slice 9 validation ledger continuation**: Independently reviewed and exact-
head validated checkpoint `21aba57` passes `22/22` focused backup-storage tests,
`161/161` adjacent recovery tests, and `1763/1763` complete launcher tests.
Black, strict mypy, focused blocking Flake8, medium/high Bandit, compilation,
editor diagnostics, secret review, and indexed diff checks pass. Final
correctness review and independent arbitration returned `CLEAN/PASS` with no
actionable Low-or-higher finding. Exact-head CI/CD run `35133270798`, Task-087
run `35133270809`, and Trivy passed; the main-only build was neutral as designed.
This checkpoint creates and verifies only the exact two authenticated DPAPI
ciphertext blobs and does not advance the journal, classify recovery, restore,
replace `.env`, authorize repair, or mutate runtime state.

**Slice 9 validation ledger continuation**: Independently reviewed and exact-
head validated checkpoint `92acf29` passes `83/83` focused backup-verification
tests, `212/212` adjacent recovery tests, and `1776/1776` complete launcher
tests. Black, strict mypy, focused blocking Flake8, medium/high Bandit,
compilation, editor diagnostics, secret review, and indexed diff checks pass.
Two independent reviews returned `CLEAN/PASS` with no actionable Low-or-higher
finding. Exact-head CI/CD run `35136560668`, Task-087 run `35136560565`, and
Trivy passed; the main-only build was neutral as designed. This checkpoint
persists and reauthenticates only `backup_verified`; it does not update the
pointer, establish `rollback_armed`, restore or clean data, authorize repair, or
mutate runtime state.

**Slice 9 validation ledger continuation**: Independently reviewed and exact-
head validated checkpoint `deee6ab` passes `47/47` focused rollback-armed tests,
`105/105` adjacent recovery tests, and `1781/1781` complete launcher tests.
Black, strict mypy, focused blocking Flake8, medium/high Bandit, compilation,
editor diagnostics, secret review, and indexed diff checks pass. Final
independent re-review returned `CLEAN/PASS` with no actionable Low-or-higher
finding. Exact-head CI/CD run `35141054176` passed. Task-087 run `35141054097`
passed on its failed-job rerun after the first attempt's unchanged legacy
Windows helper cleanup test reported an authenticated live helper and then
exited nonzero; Trivy passed, and the main-only build was neutral as designed.
This checkpoint freshly reverifies both exact authenticated backup blobs under
one held protected-root interval and appends and reauthenticates generation 3
`rollback_armed` without caller-supplied receipt authority. It does not update
the pointer, restore or clean data, replace `.env`, write certificates,
authorize repair, or mutate runtime state.

**Slice 9 validation ledger continuation**: Independently reviewed and exact-
head validated checkpoint `7b96a6b` passes `18/18` focused backup-storage
tests, `183/183` adjacent recovery tests including `74/74` native pointer-
adapter tests, and `1785/1785` complete launcher tests. Black, strict mypy,
focused blocking Flake8, medium/high Bandit, compilation, editor diagnostics,
secret review, and indexed diff checks pass. Final independent review returned
`CLEAN/PASS` with no blocking or material finding. Exact-head CI/CD run
`35144293843`, Task-087 run `35144293704`, and Trivy passed; the main-only build
was neutral as designed. This checkpoint reloads exactly the authenticated
three-generation chain and freshly reverifies both exact encrypted blobs under
one held protected-root interval before repairing the metadata pointer to the
exact generation-3 `rollback_armed` tip. It does not restore or clean data,
replace `.env`, write certificates, authorize repair, or mutate runtime state.

## Progress Interpretation

Gate A is materially advanced but remains open. Group 1's exact-runtime and
exact-target outcomes are complete. The Windows-trust implementation is
review-remediated, but its successful
fixed-host proof remains open because the current workstation correctly fails
closed when it cannot construct the required revocation-aware chain. Slice 5's
protected-state and DPAPI foundation is now independently reviewed, while
secure absence is independently reviewed with its checkpoint and exact-head
gates complete. The pure transform/state planner is committed, independently
reviewed, and exact-head validated at `0efeff7`. Independently reviewed and
exact-head validated checkpoint `1c45445` adds the
journal-gated restrictive candidate-temp staging prerequisite; durable journal
storage, native destination promotion/replacement, classification, cleanup,
and recovery remain. Slice 6 is now partial: independently reviewed and exact-
head validated checkpoint `8bb6b33` adds only the pure authenticated generation/
pointer format and fail-closed environment-temp chain selector, with all sealed
candidates authenticated inside selection. Native persistence/enumeration,
pointer repair, backup, recovery, cleanup, and cross-protocol scanning remain.
Checkpoint `53bed46` adds only root-owned persistence/enumeration orchestration
over an injected file port. Independently reviewed and exact-head validated
checkpoint `4a96dd2` adds the bounded native generation adapter with protected
DACL and flush/reopen verification. Independently reviewed and exact-head
validated checkpoint `221612c` adds pure pointer-aware load, classification,
and missing/stale repair orchestration over an injected pointer port.
Independently reviewed and exact-head validated checkpoint `95ca37d` adds native
protected pointer read and successful replacement with close-before-rename and
exact destination verification. Independently reviewed and exact-head validated
checkpoint `ebb9d69` adds same-call completed-move reconciliation after an
ordinary API error. Exact-head validated checkpoint `31f63f2` adds the pure
authenticated pointer-transition and restart-classification model.
Independently reviewed and exact-head validated checkpoint `5252c7a` adds
create-only durable transition-generation persistence and fresh-process
authenticated reload under the held protected root. Independently reviewed
implementation checkpoint `7341997` and docstring-only exact head `dd0d42d`
add exact planned pointer-temp creation, native verification, and durable
identity binding. Independently reviewed and exact-head validated checkpoint
`299ae96` adds journal-bound promotion with exact source, prior-destination, and
completed-move proof. Independently reviewed and exact-head validated checkpoint
`53b618b` adds exact authenticated planned-state zero-byte orphan cleanup by
verified held handle. Independently reviewed and exact-head validated checkpoint
`21aba57` adds create-only encrypted backup-blob persistence under freshly
reloaded held-root authority. Independently reviewed and exact-head validated
checkpoint `92acf29` adds exact held-root blob rereads and authenticated
`backup_verified` persistence. Independently reviewed and exact-head validated
checkpoint `deee6ab` adds a fresh held-root reread of both exact authenticated
blobs and durable generation 3 `rollback_armed`. Independently reviewed and
exact-head validated checkpoint `7b96a6b` freshly reverifies both exact blobs
under the same root hold and selects the exact armed tip through the metadata
pointer, with idempotent already-current behavior and safe retry after pointer-
write failure. Full recovery action, cleanup-pending retention, and cross-
protocol scanning remain.
The
branch has accumulated substantial
implementation, test, review, and documentation activity since reviewed
lifecycle head `6e0f744`; the slice states above, not commit count or line
count, determine completion.

## Remaining Outcome Sequence

1. **Finish slice 4.** Obtain a successful current fixed-host Windows trust
   proof with cache-only revocation,
   then repeat Docker/rootless-Podman one-root containment. Keep mutation disabled.
2. **Finish Windows mutation foundations (slice 5).** Use the reviewed pure
  transform/state plan, secure absence, protected Local AppData, current-user
  DPAPI, path, and mutex controls. Build durable journal generations and
  reconciliation on the reviewed temp-staging prerequisite, then implement
  native ACL-preserving atomic promotion/replacement and exact post-call
  classification only through the durable recovery protocol.
3. **Build durable recovery and refactor repair (slices 6-7).** Use the
  checkpointed journal-bound pointer promotion, planned-orphan cleanup,
  encrypted backups, and authenticated rollback-armed chain to add full
  recovery states and the fresh-process recovery manager before enabling the
  refactored transaction.
4. **Harden the external installer and prove Gate A (slices 8-9).** Reuse the
   atomic `.env` protocol, then run the final source, Windows, Docker, Podman,
   recovery, CI, and independent-review gates.

Sub-increments may be implemented and reviewed within these outcomes, but they
do not create new Gate A slices or change a slice state unless they satisfy the
state definitions above.

## Next-Session Resume Point

Use the checkpointed authenticated and pointer-selected `rollback_armed` state
to add full recovery states, fresh-process idempotent recovery, verified
rollback, cleanup-pending retention, and cross-protocol scanning. Retry
slice 4's successful revocation-aware fixed-host and
Docker/rootless-Podman containment proof only in a context able to satisfy the
cache-only revocation policy. Do not enable repair or mutation. Then complete
group 3's slices 6-7 recovery and transaction refactor and group 4's slice 8
installer hardening plus slice 9 final Gate A proof.

## Scope Control

The nine Gate A slices are frozen to the approved August 20 design. A newly
discovered edge case is recorded under its existing parent slice. Adding a
top-level outcome requires an explicit project-lead scope decision and an
update to the approved design before implementation.

No top-level Gate A requirement has been added since approval. The only design
text change after `ae6342e` is the `e049e32` compatibility refinement that
permits legitimate vendor-executable hard links only while exact held-handle,
identity, hash, and Authenticode checks remain stable. That change narrows an
overly broad rejection rule; it does not add a gate.

Gate B staged-byte/archive and hash-locked build-provenance work, Gate B preview
package validation, and Gate C/Task-100 signing and managed-endpoint
qualification remain outside this burn-down.

## Post-Gate-A Sequence

Gate A source acceptance and the PR #67 merge decision unlock Task-096 before
Gate B package integration. Task-096 adds native state-driven Start/Open/Stop/
Restart controls. Backlog Task-102 then adds native first-run setup and asset
handling while provider-key entry remains in the browser Setup Wizard. Task-087
Gate B resumes only after those launcher surfaces stabilize, so the normal
release-package path integrates the intended front door once. Task-097 then
qualifies that integrated package across Docker CPU/GPU and Podman CPU/GPU.

Planning estimate from `7b96a6b`: one substantive Gate A implementation/proof
checkpoint and approximately 1-3 additional PR #67 commits, including likely
review corrections and evidence reconciliation. Windows revocation or runtime
recovery findings can increase that count. Gate B, Task-096, Task-102, and
Task-097 are not included in that estimate.

## Update Rules

- Update **Implementation Head** and the affected row after each committed
  implementation checkpoint.
- Change a row's state only when its definition is met; record prerequisite
  progress in the evidence or remaining-work cell without overstating closure.
- Keep current summaries in `current-tasks.md` and `task-backlog.md` short and
  link here instead of copying the implementation ledger.
- Keep detailed test counts, reviewer findings, commands, and historical CI
  evidence in the main Task-087 implementation log.
- Record any approved scope change in **Scope Control** so moving requirements
  are visible rather than implicit.
