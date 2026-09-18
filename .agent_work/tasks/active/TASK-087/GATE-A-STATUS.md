# TASK-087 Gate A Status

**As Of**: September 18, 2026
**Branch**: `feature/task-087-windows-launcher-prototype`
**Implementation Head**: `8a6dd47`
**Validated Exact Head**: `4ced15d`
**Remote Exact-Head Status**: CI/CD run `35362357713`, Task-087 run
`35362357721`, and Trivy passed at `4ced15d`; the main-only build was neutral as
designed.
**Local Checkpoint**: Committed checkpoint `8a6dd47` extends the authenticated
forward stream with exact certificate temp names and stable created/verified
identities, then stages both candidates under the protected root with
`CREATE_NEW`, restrictive DACL, flush, same-handle readback, and no-follow reopen
verification. It requires the exact rollback-armed pointer to be current before
creating a file and safely resumes write/pointer failure windows. The selected
recovery/storage ring passes `197/197`; focused static/security gates pass.
Certificate apply and execution/cleanup integration remain absent, so forward
mutation remains disabled.
The preserved WIP state and corrected failures are recorded in the
[`September 17 recovery-front-door handoff`](../../../context/status/TASK-087-RECOVERY-FRONT-DOOR-WIP-2026-09-17.md).
**Current Gate A Checkpoint**: Provider `.env` update/reconciliation is
implemented at `d8818bd`; fresh-process rollback resumption is implemented at
`032db8b`; and native terminal cleanup is implemented at `4ff6967`. Local
evidence is `21/21` focused plus `568/568` broad for provider hardening,
`15/15` focused plus `89/89` manager and `368/368` recovery-ring tests for the
fresh manager, and `8/8` focused plus `376/376` recovery-ring tests for native
cleanup. Checkpoint `095c04d` implements the retained-existing-container half
of native rollback runtime availability. Its evidence is `8/8` focused,
`13/13` generation-9 integration, and `296/296` affected broad tests.
Checkpoint `6bc37b3` adds the fail-closed certificate replacement plan and
durable candidate summaries; `69/69` focused and `458/458` complete recovery-
ring tests pass, including native Windows ACL cases outside the filesystem
sandbox. Focused formatting, typing, lint, complexity/line-length, Bandit,
compilation, Python 3.11 grammar, and diff checks pass. Checkpoint `6d2ade4`
adds the hashes-only rollback-runtime recreation authority; `233/233` affected
tests and the expanded `466/466` complete recovery ring pass. Checkpoint
`da09dff` then durably binds the selected provider and Windows-root fingerprint
required to rebuild the original recovery plan; its focused recovery/provider
set passes `233/233`, and focused formatting, typing, lint, Bandit, compilation,
Python 3.11 grammar, and diff checks pass. Checkpoint `9b12645` adds the
read-only missing-container observation and authority-retention half of native
runtime availability. Its focused tests pass `224/224`; the broader clean
evidence is `566/566` non-native plus `96/96` native tests, and focused typing,
blocking lint, Bandit, compilation, Python 3.11 grammar, and diff checks pass.
Checkpoint `351c9a9` completes exact prior-profile recreation. Post-format
focused/adjacent evidence passes `386/386`, and the complete selected recovery,
runtime-target, provider-child, dynamic-load, and command-version ring passes
`840/840`. Strict typing, blocking lint, formatting, compilation, Python 3.11
grammar, and diff checks pass. Bandit found no new issue; the full touched-source
run contains only the unchanged nine-finding baseline. Two initially misplaced
test assertions caused `231/233` with `NameError` and were corrected before
`234/234` passed. Two newly introduced test-only `assert` findings were removed,
and a PowerShell quoting error that prevented the first grammar command from
parsing any file was superseded by a clean eight-file Python 3.11 grammar run.
Checkpoint `fd1ef6b` connects that boundary to runtime availability for both
Docker and Podman. Focused/adjacent tests pass `146/146`, and the broad selected
recovery/runtime ring passes `845/845`; strict typing, blocking lint, Bandit,
formatting, compilation, Python 3.11 grammar, and diff checks pass. The first
mypy run found one branch-local variable redeclaration, and the first Black
command used an unsupported option; both were corrected and superseded by clean
runs.
Checkpoint `852a72c` adds the certificate-restoration port, its authenticated
pure authority/classifier, exact retained-host-temp owner, and contained
Docker/Podman observe, stage, replace, remove, and cleanup operations. Focused
authority/orchestration tests pass `94/94`; command-plan tests pass `29/29`;
host-owner/pure tests pass `20/20`; native adapter/integration tests pass
`107/107`; backend/adapter tests pass `78/78`; and the post-residue focused set
passes `108/108`. The complete replacement evidence is `734/734` non-native
tests plus `177/177` native tests outside the filesystem sandbox. Black, strict
mypy, blocking Flake8, compilation, Python 3.11 grammar, diff, and focused
Bandit checks pass. The initial two command-plan failures, strict-mypy errors,
an invalid PowerShell grammar invocation, patch-context/layout errors, and the
ACL-blocked combined pytest teardown were corrected or superseded by those
clean replacement runs. The full touched-source Bandit run reports only the
unchanged existing backend baseline; the new restoration modules are clean.
Checkpoint `1a390b9` adds the production runtime-restart port. Focused and
adversarial tests pass `146/146`; the split broad replacement evidence passes
`536/536` non-native plus `189/189` Windows-native tests. Black, normal mypy for
all six touched lower-level modules, strict isolated mypy for the new boundary,
blocking Flake8, medium/high Bandit outside the unchanged backend safe-loader
baseline, compilation, Python 3.11 grammar, and diff checks pass. The initial
`2/140`, transition-code expectation, and mypy seam failures were corrected and
superseded by those clean runs; no failed check is carried. Rollback verification
and transaction integration remain.
Checkpoint `515c1f5` closes the rollback-verification authority/schema
prerequisite. Focused authority/recovery tests pass `237/237`, and the broader
non-native recovery ring passes `351/351`. Strict and normal mypy, Black,
blocking/unused-code Flake8, Bandit, and diff checks pass. The initial missed
fixture, unreachable test-helper assertions, stale Flake8 invocation, one
pre-existing unused local, and one overly broad cleanup patch were each corrected
and superseded by clean replacement runs; no failed check is carried. The native
rollback-verification adapter remained open at that checkpoint.
Checkpoint `f298a3e` completes that native adapter for Docker and Podman. It
adds fixed bounded in-container readiness and keyless provider TLS probes,
read-only exact `.env` and certificate observations, complete runtime/container/
all-volume comparison, readiness-equivalence enforcement, sanitized failures,
and owner cleanup on every path. Focused tests pass `144/144`; the complete
selected recovery/runtime-target ring passes `764/764`. Black, strict and normal
mypy, blocking/unused-code Flake8, focused Bandit outside the unchanged backend
safe-loader/assert baseline, compilation, Python 3.11 grammar, and diff checks
pass. Two pytest attempts were blocked only by ACL-inaccessible shared/workspace
basetemps; the exact native test then passed `1/1` and the complete focused set
passed `144/144` in fresh external temp roots. Strict mypy's initial object-
narrowing finding was fixed without weakening exact-type rejection. Black's
check/diff multiprocessing pipe denial was superseded by a clean single-worker
format run. No failed product check is carried.
Checkpoint `2266f84` adds the production native recovery composition owner and
the missing unpredictable certificate-restore temp-name source. It binds the
generation, pointer, DPAPI backup, environment restore, runtime availability,
certificate restore, runtime restart, terminal verification, and cleanup ports
to one retained protected root. Recovery from `rollback_armed` no longer
requires a provider mini-journal that cannot exist before provider apply; that
path carries no candidate identity and succeeds only for the authenticated
exact original/absence state. Focused evidence passes `37/37`. The broad
recovery/environment/runtime-target ring passes `876` in the combined process,
with one expected skip; its 13 shared-temp ACL setup errors were superseded by
`13/13` isolated elevated native passes, for all `890` selected cases accounted
for. Black, strict/normal mypy, blocking/unused-code Flake8, Bandit, compilation,
Python 3.11 grammar, and diff checks pass. No product failure is carried.
Checkpoint `6ff351c` adds the retained package-root lease bridge through the
native target authority, owned observation backend, and immutable resolved-
target owner. The callback is serialized with every authenticated plan input,
is bracketed by complete target captures, and is explicitly non-mutating.
Focused/adjacent evidence passes `302/302`; Black, strict mypy, blocking and
unused-code Flake8, compilation, Python 3.11 grammar, diff, and focused Bandit
checks pass. The first Black and lint runs found one formatting issue, two
missing test annotation imports, and two stale source imports; all were fixed
and superseded by clean reruns. The full touched-source Bandit run contains
only the unchanged backend strict-loader/assert baseline. No failed product
check is carried.
Checkpoint `d1494f6` builds the ordered repair transaction context on that
bridge. It duplicates and identity-matches the package-root lease, retains one
protected recovery root, acquires the environment mutex before scanning and
the target mutex after scanning, preserves abandoned-lock evidence, and holds
all four owners through confirmation cleanup. Provider recovery fails closed
before target-lock acquisition; a pending repair is retained without mutation.
Focused tests pass `16/16`; the affected broad ring passes `421/421`, and the
intentional native protected-DACL proof passes `1/1` in an isolated external
temp root. Black, strict mypy, blocking/unused-code Flake8, Bandit, compilation,
Python 3.11 grammar, and diff checks pass. A genuine private exception-chain
leak found by the new assertions was fixed by leaving the private handler
before raising the sanitized confirmation error. The shared-temp ACL cleanup
failure and an over-broad line-length lint invocation were superseded by the
isolated native pass and repository gate commands; no failed product check is
carried.
Live Windows
trust, Docker, and rootless-Podman evidence is pending a supported context and
the required runtime-readiness confirmation.
**Historical Checkpoint Ledger**: Slices 2-3 exact-target confirmation wiring
complete.
The latest fixed-host retry returned only `chain_unverified` for both approved
hosts, so slice 4 remains partial. Slice 5 has independently reviewed
protected-state/DPAPI and secure-absence foundations. Its pure byte-transform/
state-classification prerequisite is committed, independently reviewed, and
exact-head validated at `0efeff7`. Independently reviewed checkpoint `1c45445`
adds journal-gated native temp staging and passed exact-head CI/CD run
`35005869321`, Task-087 run `35005869200`, and Trivy. Durable journal storage
and promotion orchestration remain open. A reviewed native boundary now uses
`ReplaceFileW` for an exact existing destination or non-overwriting write-
through `MoveFileExW` for exact absence and reconciles every result from exact
post-call state. Documentation
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
Independently reviewed and exact-head validated checkpoint `b12280d` accepts
only the exact authenticated three- or four-generation chain, validates the
intermediate `backup_verified` and `rollback_armed` authority, derives both
expected backup receipts only from durable records, and freshly reverifies both
exact encrypted blobs under one held protected-root interval. It makes
generation 3 current before appending and selecting generation 4
`rollback_started` at most once. A generation-4 retry appends nothing and only
verifies or repairs the exact started pointer. Focused tests pass `58/58`, the
adjacent recovery ring passes `227/227`, and the complete launcher suite passes
`1792/1792`. CI/CD run `35148213698`, Task-087 run `35148213864`, and Trivy
passed; the main-only build is neutral as designed. No restore, cleanup, `.env`
replacement, certificate write, repair, or runtime mutation is enabled.
Pushed checkpoint `a37cf8a`, built through `ec2e2d5`, `5b337a7`, `30e7529`,
`cc5183a`, and `51f0673`, adds the strict generation-6 created-state schema,
native zero-byte restore-temp creation/verification, authenticated discovery
and package-bound cross-protocol classification, and mandatory scan evidence
after package/`.env` lock acquisition but before target-lock acquisition.
Provider-environment recovery blocks target acquisition; repair recovery is
retained only as read-only owner evidence. At that checkpoint, generation-6
orchestration remained unwired, and no restore, cleanup, `.env` replacement,
certificate write, repair, or runtime mutation was enabled.
Independently reviewed and exact-head validated checkpoint `57e280e` consumes
only the authenticated generation-5 plan through the narrow zero-byte storage
port. It requires matching caller-held package-root trust, records exact temp
identity or secure absence in generation 6, appends at most once, and
reverifies present-state identity before exact pointer repair on retry. It adds
no runtime call site, restore content, `.env` replacement/removal, completed-
transaction cleanup, certificate write, repair activation, or runtime mutation.
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
| 5 | Windows security proof | **PARTIAL** | Independently reviewed checkpoint `2edcb8e` resolves Local AppData through the Windows Known Folder API; creates only `TowerScout\Recovery\v1`; requires each state directory to have a protected, exact current-user/SYSTEM full-control DACL; retains and revalidates its handle-bound hierarchy; and adds UI-forbidden, current-user-only, purpose-separated DPAPI. Earlier checkpoints `2d37e66`, `f7d21a9`, and `16604c8` provide the handle/file-ID, owner, DACL, reparse, hard-link, supported cloud/OneDrive, secured cross-session mutex, and ordered `.env`/target-lock foundations. Checkpoint `14b77e4` retains package-root trust, binds canonical absence evidence to that root identity, and rechecks the exact `.env` child through a no-follow native open. Checkpoint `0efeff7` adds the pure planner with bounded strict UTF-8/BOM/NUL policy, exact two-setting changes that preserve unrelated bytes/newline form, immutable original/candidate hashes, and exact original/candidate/absent/third-state classification; focused/full launcher validation, independent review, and exact-head workflows pass. Independently reviewed and exact-head validated checkpoint `1c45445` adds a private journal-gated staging boundary: unpredictable same-directory `CREATE_NEW`, exact protected current-user/SYSTEM DACL, zero-byte created-state receipt before write, complete bounded writes, `FlushFileBuffers`, same-handle readback, close, and no-follow reopen identity/DACL/hash verification before the verified receipt. Its Windows-native smoke uses an isolated pytest temp only. Checkpoint `5e83e46` adds the pure exact promotion classifier and native `ReplaceFileW`/non-overwriting `MoveFileExW` observe/apply/reconcile boundary. Checkpoint `30e30ef` makes all four provider mini-journal generations durable/current and reconciles apply across restart. Checkpoint `d531f82` reconciles exact planned/created residue and treats applied provider chains as terminal scan evidence. Checkpoint `121db54` restores or removes only the exact applied candidate through a held/no-follow boundary and verifies the result before generation 8. Checkpoint `4ff6967` adds exact authenticated terminal artifact cleanup and cleaned-state revalidation without listing or globbing. | Exercise all slice 5 primitives through the integrated transaction. |
| 6 | Recovery manager | **IMPLEMENTED / REVIEW PENDING** | The authenticated journal, pointer protocol, exact backup/restore chain, fresh-process resumption, terminal cleanup, retained/recreated runtime availability, certificate restoration, volume-preserving restart, and terminal verification authority are checkpointed through `515c1f5`. Checkpoint `f298a3e` adds the terminal native verifier. Checkpoint `2266f84` composes every native rollback port under one retained protected root, reconstructs certificate identity from authenticated state, and safely supports post-arm failure before a provider stream exists. Checkpoint `6ff351c` exposes the retained package-root only through the exact target owner and brackets each callback with complete target revalidation. Checkpoint `d1494f6` retains the identity-matched package-root lease, protected root, recovery scan, and ordered environment/target mutexes through confirmation. Checkpoint `b2f6458` adds the authenticated retained-present/exact-absent fresh-process front door and clean-rescan requirement; `226/226` focused, `849/849` broad non-native, and `245/245` isolated native tests pass with focused static/security gates. Checkpoint `ee76805` admits recovery after the single-instance lock and before ordinary startup; its focused set passes `60/60`. Checkpoint `9d7f533` adds the separate durable forward journal, exact rollback anchor, and authenticated provider-stream ownership needed to recover a partially executed repair. | Require exact-head workflows and final review, then exercise recovery through the integrated launcher transaction in slices 7 and 9. |
| 7 | Transaction refactor | **PARTIAL** | Checkpoint `9d7f533` defines and persists the strict forward state sequence from certificate staging through commit/cleanup, with exact provider-generation linkage and fresh-process discovery. Checkpoint `8a6dd47` binds unpredictable protected-root certificate temp names plus exact created/verified identities and stages both candidates through durable flushed/reopened verification only after the exact rollback pointer is armed/current. It does not yet apply certificates, execute provider/runtime transitions, commit, or clean. The older prototype transaction remains a behavior reference only. | Implement certificate apply and the cleanup owner, then refactor `repair.py` to consume the immutable resolved target, forward journal, and recovery manager; remove process-memory-only backup and unchecked rollback; enforce pre-write/pre-restart/terminal revalidation. |
| 8 | Provider installer hardening | **IMPLEMENTED / REVIEW PENDING** | Historical checkpoint `3990bc0` closed provider dependency/wheel reproducibility and version verification. Independently reviewed checkpoint `7a0c35a` makes the installed `site-packages` inventory deterministic and provider-only. Checkpoint `d8818bd` adds a protected, exact atomic `.env` protocol that changes only `PODMAN_COMPOSE_PROVIDER`, avoids persistent plaintext backup/output, authenticates the provider mini-journal, and reconciles planned/created/verified/applied residue across restart. Focused provider tests pass `21/21`, the affected ring passes `568/568`, and exact-head workflows passed. | Complete final source review and exercise the provider path as part of the integrated transaction/evidence set. |
| 9 | Gate A source validation and review | **VALIDATION CONTINUES** | Every completed increment has focused tests and independent review. Secure-absence checkpoint `14b77e4` passed its exact-head gates. Pure-planner checkpoint `0efeff7` passes `47/47` focused and `1536/1536` launcher tests plus static checks and independent source review. Staging checkpoint `1c45445` passes `24/24` focused tests, including real Windows ctypes and retained-native-handle smokes, and `169/169` adjacent tests plus focused static/security checks and independent review. Checkpoint `8bb6b33` passes `26/26` focused journal, `152/152` adjacent, and `155/155` isolated late-launcher tests plus focused static/security checks and CLEAN/PASS corrected-diff independent review. Its exact-head CI/CD run `35010304611`, Task-087 run `35010304675`, and Trivy passed. Documentation checkpoint `e86c41c` passed exact-head CI/CD run `35011029262`, Task-087 run `35011029309`, and Trivy; both main-only builds skipped as designed. Independently reviewed checkpoint `53bed46` passes `20/20` focused, `164/164` adjacent, and `167/167` isolated late-launcher tests plus focused static/security checks and CLEAN/PASS review with no actionable Low-or-higher findings. Its exact-head CI/CD run `35013069183`, Task-087 run `35013069124`, and Trivy passed; the main-only build was neutral as designed. Documentation checkpoint `2e0f90e` passed exact-head CI/CD run `35014300773`, Task-087 run `35014300816`, and Trivy. Independently reviewed checkpoint `4a96dd2` passes `18/18` focused, `182/182` adjacent, and `185/185` isolated late-launcher tests plus focused static/security checks, a real Windows round trip, and two CLEAN/PASS reviews with no actionable Low-or-higher findings. Its exact-head CI/CD run `35016174147`, Task-087 run `35016174145`, and Trivy passed; the main-only build was neutral as designed. Independently reviewed checkpoint `221612c` passes `19/19` focused, `192/192` adjacent, and `195/195` isolated late-launcher tests plus focused static/security checks and final CLEAN/PASS review. Its exact-head CI/CD run `35019327044`, Task-087 run `35019327058`, and Trivy passed; the main-only build was neutral as designed. Independently reviewed checkpoint `95ca37d` passes `32/32` focused, `206/206` adjacent, and `209/209` isolated late-launcher tests plus a real Windows replacement round trip, focused static/security checks, and final CLEAN/PASS review. Its exact-head CI/CD run `35021545053`, Task-087 run `35021545062`, and Trivy passed; the main-only build was neutral as designed. | After slices 2-8 are integrated, run the final broad/adversarial set, fresh-process recovery, isolated Docker CPU then approved rootless-Podman CPU mutation/recovery, OneDrive and two-session Windows proofs, all-volume verification, exact-head workflows, and final independent review. |

**Current-head correction for slice 6**: Checkpoint `1a390b9` supplies the
runtime-restart native port. Checkpoint `515c1f5` binds exact prior readiness/
provider state and derives the complete terminal authority from the authenticated
chain. Checkpoint `f298a3e` supplies the native rollback-verification adapter,
including exact local/runtime proof and bounded readiness/provider probes. The
remaining slice-6 work is fresh-process exercise through transaction integration.

**Current-head correction for slices 5-6**: The generation-6 zero-byte restore-
temp storage primitive and package-bound cross-protocol scan are now
checkpointed through `a37cf8a`. Any earlier row text that lists those primitives
as wholly open is superseded by this correction. Checkpoint `57e280e` now
orchestrates generation 6 through exact zero-byte creation or secure absence,
with identity reverification and exact pointer repair on retry. Content write/
verification, actual restore, cleanup, native destination replacement, and end-
to-end recovery/transaction integration remain open.

Checkpoints `1eb3363` and `d9f6563` supersede the content-write portion of that
correction. They add strict generation-7 authority and stage only the exact
freshly authenticated original bytes into the recorded generation-6 temp,
followed by held-handle and reopen verification. Complete exact crash residue
is accepted without another write; partial or mismatched residue is preserved
and blocks. Generation 7 appends at most once and retry repairs only its exact
pointer. Exact-head CI/CD run `35238335037`, Task-087 run `35238334999`, and
Trivy pass; the main-only build is neutral as designed. Actual `.env`
replacement/removal, certificate restore, cleanup, recovery/transaction
integration, and runtime mutation remain open and disabled.

Pushed implementation checkpoint `1b85a93` defines the strict authenticated
generation-8 `environment_restored` record and extends unique-chain validation
through that state. It binds the generation-7 predecessor, package-root
identity, exact restored presence/absence, content hash/size, original file
attributes/security-descriptor hash, and present-state destination identity.
Canonical/redacted round-trip and drift rejection pass `44/44` focused tests;
the adjacent journal/storage set passes `143/143`, and the broader Windows
recovery selection passes `280/280`. This checkpoint performs no destination
operation and grants no `.env`, certificate, repair, cleanup, or runtime
mutation authority. Exact-head workflows and independent review remain open.

Pushed checkpoint `16a8224` closes the pre-apply authority gap for originally
absent `.env`: `backup_preparing` now authenticates an immutable replacement
plan whose original state exactly matches the encrypted environment backup and
durably binds its candidate hash and size before any backup name or write.
That lets later fresh-process recovery distinguish the transaction-produced
candidate from an unrelated file without persisting candidate plaintext.
Recovery/provider regressions pass `343/343`; strict typing, configured lint,
Bandit, Black, compilation, and diff checks pass. No destination operation or
runtime mutation is enabled. Exact-head workflows and independent review are
pending.

Pushed checkpoint `6637c0d` authenticates the original `.env` stable identity
through the encrypted backup and generation-1 authority, rejects backup
persistence if that identity drifts, and adds a pure restore classifier. The
classifier authorizes only an exact original, an exact durably recorded
candidate, or secure absence; identity, content, size, attributes, or security-
descriptor drift is a preserved blocking third state. A candidate without a
future durable applied identity is never authorized. Affected tests pass
`54/54`, the broader recovery/provider ring passes `361/361`, and focused
static/security checks pass. No destination operation or runtime mutation is
enabled. Exact-head workflows and independent review are pending.

Pushed checkpoint `39127a5` makes the already journal-bound candidate temp the
durable forward/recovery authority by recording its exact file attributes and
security-policy fingerprint with its stable identity, hash, and size. Native
staging now requires those facts at creation, after the same-handle write, and
after no-follow reopen; journal continuity rejects either metadata field
drifting between created and verified states. Focused Windows tests pass
`171/171`, and the broad launcher set passes `1930/1930` with only the real
host-helper module excluded because Windows antivirus blocks the unchanged
PowerShell helper before execution. The unfiltered run otherwise passed 1,931
tests and produced four identical antivirus-policy failures. Static/security
checks pass. No promotion, destination replacement, or runtime mutation is
enabled. Exact-head workflows and independent review are pending.

Committed checkpoint `5e83e46` adds a pure exact promotion classifier, the
native no-follow observe/apply/reconcile boundary, and authenticated
`environment_applied` journal schema. Existing destinations use `ReplaceFileW`
and must retain the original attributes and owner/DACL policy while adopting
the verified candidate identity/content; originally absent destinations use a
non-overwriting write-through `MoveFileExW`. Apparent API errors are accepted
only when exact post-call state proves completion, unchanged state is retryable,
and every third state is preserved and blocks. The implementation corrects the
security fingerprint to bind owner, DACL presence/protection, and exact DACL
bytes rather than unstable self-relative descriptor layout. Focused validation
passes `171/171`, an elevated real-Windows replace/move proof passes, the final
review ring passes `108/108` with the expected unelevated native-policy skip,
and the broad launcher suite passes `1959/1959` with the unchanged antivirus-
blocked host-helper module excluded. Black, strict mypy, configured Flake8,
Bandit, compilation, and diff checks pass. No production call site or applied-
generation append exists yet; mutation remains disabled. Push, exact-head
workflows, and independent review remain pending.

Committed checkpoint `30e30ef` makes the complete provider environment apply
authority durable. The immutable plan now records the exact original presence,
identity, hash, size, attributes, and owner/DACL policy fingerprint. A storage-
backed staging adapter appends and reauthenticates planned, created, and
verified generations, and the held-root promotion orchestrator requires the
verified generation to be current before applying, appends `environment_applied`
exactly once, and repairs only its exact pointer after a fresh-process restart.
Focused validation passes `249/249`; the broad launcher ring passes `1973/1973`
with only the unchanged antivirus-blocked host-helper module excluded. Strict
mypy, Black, configured Flake8, Bandit, compilation, and diff checks pass.
There is still no installer/repair call site, and runtime mutation remains
disabled. Push, exact-head workflows, and independent review remain pending.

Pushed checkpoint `d531f82` adds restart reconciliation for exact planned and
created provider residue, including truncating and rewriting only the recorded
partial temp and removing only an exact zero-byte restrictive-DACL orphan by a
held handle. Applied provider journals are terminal scan evidence, allowing
later transactions without concealing pending work. The Python 3.11 collection
failure found at the preceding exact head was corrected before push. PR checks
at `d531f82` pass for Python 3.11/3.12, security, frontend, Docker frontend,
Task-087 contracts/e2e/host-helper, and Trivy; the main-only build skipped as
designed.

Pushed checkpoint `121db54` adds the native exact environment-rollback boundary
and durable generation-8 orchestration. It reloads the authenticated terminal
provider stream under the recovery root hold, requires the same target token
and package identity, cross-checks original and candidate authority, makes
generation 7 current before mutation, and appends generation 8 only after exact
post-state proof. Existing originals use `ReplaceFileW`; originally absent
state removes only the exact applied candidate through a held handle. API
errors reconcile only from exact state, third-state substitutions are
preserved, and restart re-verifies before repairing only the exact pointer.
Focused recovery/journal tests pass `92/92`; the corrected affected native ring
passes `443/443`; and the broad launcher/Windows integration set passes
`2003/2003`. Strict mypy, Black, blocking Flake8, Bandit, compilation, Python
3.11 grammar over `191` files, and diff checks pass. Exact-head workflows and
independent review remain pending.

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

**Slice 9 validation ledger continuation**: Independently reviewed and exact-
head validated checkpoint `b12280d` passes `58/58` focused recovery tests,
`227/227` adjacent recovery tests, and `1792/1792` complete launcher tests.
Black, strict mypy, focused blocking Flake8, medium/high Bandit, compilation,
editor diagnostics, secret review, and indexed diff checks pass. Two
independent reviews returned `PASS` with no actionable finding. Exact-head
CI/CD run `35148213698`, Task-087 run `35148213864`, and Trivy passed; the main-
only build was neutral as designed. This checkpoint accepts only the exact
authenticated three- or four-generation chain, derives both expected backup
receipts only from durable records, freshly reverifies both exact encrypted
blobs under one held protected-root interval, and appends and selects generation
4 `rollback_started` at most once. Retry repairs only its exact pointer. It does
not restore or clean data, replace `.env`, write certificates, authorize repair,
or mutate runtime state.

**Slice 9 validation ledger continuation**: Independently reviewed and exact-
head validated checkpoint `56ba458` passes `89/89` focused recovery tests,
`238/238` adjacent recovery tests, and `1802/1802` complete launcher tests.
Black, strict mypy, blocking Flake8, medium/high Bandit, compilation, editor
diagnostics, secret review, and indexed diff checks pass. Final independent
review returned `CLEAN/PASS` with no blocking or material finding. Exact-head
CI/CD run `35151950273`, Task-087 run `35151950269`, and Trivy passed; the
main-only build was neutral as designed. This checkpoint reads both exact
encrypted backups through held-handle verification under one protected-root
interval, authenticates them against the journal stream, matches their complete
summaries to generation 1, and appends and selects generation 5
`environment_restore_temp_planned` at most once. It records one unpredictable
temp name only when the original `.env` existed; secure absence records no temp
name. Retry repairs only the exact planned pointer without another append or
name. It creates or restores no file and performs no cleanup, `.env`
replacement, certificate write, repair, or runtime mutation.

**Slice 9 validation ledger continuation**: Pushed and independently reviewed
checkpoint `a37cf8a` passes `100/100` focused mutex/transaction-owner tests and
`1838/1838` complete launcher tests. Black, configured Flake8, strict mypy,
Bandit, compilation, editor diagnostics, and `git diff --check` pass. The
review found no defect in the new scan integration; one observation concerned
an unchanged mutex cleanup helper whose concrete close contract already
normalizes failures. GitHub reports the Task-087, frontend, security, and Trivy
checks pass. Exact-head CI/CD run `35157843681`, Task-087 run `35157843639`,
and Trivy passed; the main-only build is neutral as designed. It enables no
recovery action or mutation.

**Slice 9 validation ledger continuation**: Independently reviewed checkpoint
`57e280e` passes `3/3` focused generation-6 tests, `32/32` complete recovery
backup-storage tests, and `1841/1841` complete launcher tests. Black, source
configured Flake8, strict mypy, Bandit, compilation, diagnostics, and diff
checks pass. Two independent reviews found no actionable defect. Exact-head
CI/CD run `35159400390`, Task-087 run `35159400276`, and Trivy passed; the main-
only build is neutral as designed. It creates or reverifies only the exact
planned zero-byte temp and persists generation 6; all later recovery action and
runtime mutation remain disabled.

**Slice 9 validation ledger continuation**: Independently reviewed checkpoints
`1eb3363` and `d9f6563` pass `15/15` native recovery-storage tests, `95/95`
integrated generation-7 tests, and `1854/1854` complete launcher tests. Black,
configured Flake8, strict mypy, Bandit, compilation, diagnostics, and diff
checks pass. Separate storage and orchestration reviews returned `CLEAN/PASS`.
Exact-head CI/CD run `35238335037`, Task-087 run `35238334999`, and Trivy pass;
the main-only build is neutral as designed. This checkpoint stages and attests
exact original environment bytes only in the recorded private temp and enables
no `.env` replacement/removal or later recovery/runtime mutation.

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
pointer repair, backup, recovery, cleanup, and cross-protocol scanning remained
open at that checkpoint.
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
write failure. Independently reviewed and exact-head validated checkpoint
`b12280d` adds fresh-process admission by appending and selecting generation 4
`rollback_started` at most once, with exact started-pointer repair on retry.
Independently reviewed and exact-head validated checkpoint `56ba458` then adds
fresh-process generation-5 `environment_restore_temp_planned`: both exact
backups are read and authenticated under one held root, complete summaries must
match generation 1, and retry appends neither another generation nor another
temp name. Environment restore-temp creation/verification, remaining recovery
states and action, cleanup-pending retention, and cross-protocol scanning
remain.
Independently reviewed and exact-head validated checkpoint `a37cf8a` adds strict
generation-6 schema/native zero-byte temp storage plus authenticated package-
bound cross-protocol discovery and mandatory scan evidence at the retained
transaction-lock boundary. Cross-protocol scanning is no longer open as a
standalone primitive. At that checkpoint, generation-6 orchestration, content
write/verification, actual restore, cleanup-pending action, transaction
integration, and provider `.env` hardening remained.
Independently reviewed and exact-head validated checkpoint `57e280e` adds the
generation-6 orchestration boundary. It accepts only the authenticated five- or
six-generation chain under matching caller-held package-root trust, creates and
records the exact planned zero-byte temp or secure absence, and reverifies the
recorded identity before exact pointer repair on retry. Content write/
verification, actual restore, cleanup-pending action, transaction integration,
and provider `.env` hardening remain.
The
branch has accumulated substantial
implementation, test, review, and documentation activity since reviewed
lifecycle head `6e0f744`; the slice states above, not commit count or line
count, determine completion.

## September 17 Current-Head Supersession

- Checkpoints `2ac5fd2`, `f3185e0`, and `2d95a82` add the remaining rollback
  state transitions through runtime availability, certificate restoration,
  runtime restart/verification, rollback completion, cleanup pending, and
  cleaned. Those orchestration ports remain deliberately injected; the native
  production adapters are still required.
- Checkpoint `d8818bd` completes the provider `.env` mutation/reconciliation
  implementation. Its exact head passed all PR jobs.
- Checkpoint `032db8b` adds the fresh-process recovery manager and idempotent
  resumption from generations 3-19. Its exact-head CI/CD run `35272301670`,
  Task-087 run `35272301696`, and Trivy passed.
- Exact-head validated checkpoint `4ff6967` adds the native terminal cleanup
  boundary. It derives
  exact artifact authority only from the authenticated terminal chain, never
  lists or globs, preserves journals and their pointer, persists cleanup-
  pending on partial failure, and revalidates absence from cleaned. Its local
  focused/recovery-ring evidence and exact-head workflows pass.
- Checkpoint `095c04d` adds read-only native rollback-runtime availability for
  the retained exact-container path. It binds the target token, package-root
  identity, authenticated runtime/endpoint/provider evidence, exact container,
  and all eight ordered volumes while the caller's package-root lease remains
  held. It fails closed without issuing a runtime command when the exact target
  cannot be recaptured. Missing-container exact recreation remains open.
- Checkpoint `6bc37b3` adds the exact certificate replacement plan and extends
  authenticated generation 1 with both candidate hashes, sizes, and fixed
  regular-file modes. The plan accepts only one selected Windows root, appends
  it to one bounded system bundle, redacts contents from representations, and
  persists the summaries before backup names, blobs, or mutation. Production
  certificate storage/apply and rollback restoration remain open.
- Checkpoint `6d2ade4` adds hashes-only, generation-1 rollback-runtime recovery
  authority for the exact package/runtime/endpoint/provider, original Compose
  model and environment, prior image, profile/port, and all eight volume
  identities. The manager supplies that authenticated authority to the native
  availability port before it can act; both the retained-container adapter and
  journal continuity validation reject drift. Affected tests pass `233/233`,
  and the expanded recovery ring passes `466/466`, including native ACL cases
  outside the filesystem sandbox. The initial seven fixture-wiring failures and
  one zero-collection quoted-wildcard command were corrected; both are
  superseded by the passing runs. Static/security checks pass.
- Checkpoint `da09dff` adds the selected provider and lowercase SHA-256
  Windows-root fingerprint to the exact certificate plan and authenticated
  generation 1. Fresh-process recovery can now reconstruct the certificate
  identity used by the original target plan without storing certificate bytes
  or rerunning trust selection. Focused recovery/provider tests pass `233/233`;
  Black, strict mypy, blocking Flake8, Bandit, compilation, Python 3.11 grammar,
  and diff checks pass. The multi-file Black invocation that stalled without
  output was interrupted and replaced by passing isolated per-file checks.
- Checkpoint `9b12645` adds the read-only missing-container availability
  precondition. It reconstructs the plan from authenticated certificate
  identity without another trust-selection call, retains the native input/file/
  runtime/provider authorities, requires exact container absence, and binds the
  current/planned Compose models, pinned image, and all eight ordered volumes.
  It captures twice and re-derives the exact persisted rollback-runtime
  authority before returning a repeatedly attestable owner. Focused tests pass
  `224/224`; the clean broader evidence is `566/566` non-native tests plus
  `96/96` native tests outside the filesystem sandbox. Strict mypy, blocking
  Flake8, Bandit, compilation, Python 3.11 grammar, and diff checks pass. Two
  initial test commands named nonexistent modules and therefore collected zero;
  the corrected broad run then had six shared pytest-temp setup denials before
  test bodies. Exact file discovery plus the two clean replacement runs
  supersede those invocation/environment failures. Default Flake8 first hit a
  Windows multiprocessing pipe denial and, when serialized, only the known
  Black-88/default-Flake8-79 mismatch; the serial blocking-rule invocation is
  green. No runtime command was issued.
- Checkpoints `351c9a9` and `fd1ef6b` complete the missing-container runtime-
  availability source path. The absent owner revalidates exact absence, issues
  one volume-preserving prior-profile recreation, proves the original authority
  through four present captures, and transfers a normal target owner. The
  manager-facing port first accepts an existing exact target and otherwise uses
  that absent path, returning the correct retained/recreated evidence and
  closing every owner. Its focused/adjacent `146/146` and broad `845/845` tests
  plus static/security checks pass. The corrected mypy redeclaration and Black
  option failures are superseded by clean replacement runs.
- Checkpoint `852a72c` completes the production certificate-restoration port.
  Authenticated journal authority selects only already restored, restore exact
  original, remove exact candidate, or block. Native host originals remain
  held and revalidated while fixed Docker/Podman commands copy and atomically
  apply them; exact candidate removal and staged-residue cleanup are equally
  bounded. Its split broad evidence passes `734/734` non-native plus `177/177`
  native tests, and focused static/security checks pass. All observed command,
  typing, grammar, patch-layout, and pytest-teardown failures were corrected or
  superseded by clean replacement evidence; no failed check is being carried.
- Checkpoint `1a390b9` completes the production runtime-restart port. A retained
  old target permits only fixed Docker/Podman Compose
  `up -d --no-deps --force-recreate towerscout`; the transition retires old
  observation authority and a new complete capture must preserve the
  authenticated runtime and all eight volumes while changing exact container
  evidence. Retry accepts only that exact recreated state or exact absence
  recoverable through the reviewed prior-profile path. Focused/adversarial
  evidence passes `146/146`; split broad evidence passes `536/536` non-native
  plus `189/189` Windows-native tests. Static/security checks pass outside the
  unchanged safe-loader baseline. All observed assertion, typing, and command-
  design failures were corrected and superseded; no failed check is carried.
- Checkpoints `515c1f5`, `f298a3e`, and `2266f84` complete rollback-
  verification authority, its Docker/Podman native verifier, and composition
  of every rollback port under one protected-state root. The composed manager
  also handles failure after rollback arming but before a provider stream can
  exist, only while the original `.env` state remains exact.
- Checkpoint `6ff351c` exposes the retained package-root trust only through the
  exact resolved-target owner. The native callback runs while every target
  authority is leased and between complete pre/post captures; it cannot be
  used for an intentional mutation transition. Focused/adjacent tests pass
  `302/302`, all focused static gates pass, and no failed product check is
  carried.
- Checkpoint `d1494f6` retains the identity-matched package-root authority,
  protected recovery root, authenticated scan, and environment-then-target
  mutex pair through confirmation. Provider recovery blocks before target-lock
  acquisition. Focused tests pass `16/16`, the affected broad ring passes
  `421/421`, and the isolated native DACL proof passes `1/1`; all focused static
  gates pass and the discovered exception-chain leak was fixed before commit.
- No live Docker, Podman, certificate-store, or runtime mutation was run for
  these source checkpoints. The runtime-readiness confirmation required before
  live evidence remains outstanding.

## Remaining Outcome Sequence

1. **Integrate production recovery (slice 6).** Exercise fresh-process recovery
   through the complete native adapters and refactored transaction boundary.
2. **Refactor the transaction (slices 5 and 7).** Make `repair.py` consume the
   immutable resolved target and durable recovery manager, remove process-
   memory-only backup/unchecked rollback, and retain the required pre-write,
   pre-restart, and terminal revalidation stages.
3. **Close trust and integration proof (slices 4 and 8).** Obtain the successful
   revocation-aware fixed-host Windows proof, exercise the hardened provider
   path, and repeat one-root Docker/rootless-Podman containment after runtime
   readiness is confirmed.
4. **Run final Gate A evidence (slice 9).** Run the broad/adversarial source,
   restart recovery, OneDrive/two-session Windows, all-volume, Docker/Podman,
   exact-head CI, documentation, and final review gates.

Sub-increments may be implemented and reviewed within these outcomes, but they
do not create new Gate A slices or change a slice state unless they satisfy the
state definitions above.

## Next-Session Resume Point

Continue from certificate-staging checkpoint `8a6dd47`. Add certificate apply
and authenticated cleanup primitives, then refactor `repair.py`
around the immutable target, durable forward journal, and rollback manager.
Preserve forward mutation-off until the integrated path is complete and
reviewed. Retry slice
4's revocation-aware fixed-host and Docker/rootless-Podman containment proof
only in a supported context and only after runtime readiness is explicitly
confirmed. Finish with the complete slice 9 evidence set and exact-head checks.

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

Planning after `d1494f6` remains based on fixed acceptance criteria rather than
commit count. Remaining work is transaction/recovery integration, successful
Windows trust and live runtime proof, final exact-head workflows and review, and
the PR #67 decision. Gate B, Task-096, Task-102, and Task-097 are outside that
Gate A estimate.

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
