# Current Tasks - Sprint 09

**Sprint Period**: August 8-August 21, 2026; active-task continuation retained
through the current Task-087 Gate A work
**Last Updated**: September 17, 2026
**Focus**: Task-101 is complete. Task-087 is the active implementation task.
Its canonical detailed
[`Gate A burn-down`](./tasks/active/TASK-087/GATE-A-STATUS.md) fixes the approved
nine-slice scope and distinguishes complete, partial, not-started, and
validation states. The September 14 checkpoint closes slices 2-3: confirmation
now consumes and retains the native exact target, shows only its public summary,
times out and cleans up safely, and exposes ordered revalidation hooks. Slice 4
remains partial: cache-only revocation was restored during independent review,
and the current workstation now fails closed for Azure because cached
revocation status is offline/unknown. Earlier network-disabled Docker and
rootless-Podman checks prove one-root transport containment only. Windows
security remains partial, but the protected Local AppData and current-user
DPAPI foundation is now independently reviewed with focused/native proof.
Secure `.env` absence ownership is independently reviewed and checkpointed.
The pure, unwired `.env` byte-transform/state-classification prerequisite for
atomic replacement is committed, independently reviewed, and exact-head
validated. Independently reviewed implementation checkpoint `1c45445df82e`
adds private, journal-gated, same-directory native candidate staging with
restrictive ACL, identity, flush/readback, and no-follow reopen verification.
It passed exact-head CI/CD run `35005869321`, Task-087 run `35005869200`, and
Trivy; the main-only build skipped as designed. Documentation checkpoint
`42180b10e7f` then passed CI/CD run `35006846090`, Task-087 run `35006846025`,
and Trivy, with the main-only build skipped as designed. Independently reviewed
and exact-head validated checkpoint `8bb6b33` adds strict canonical encoding,
DPAPI-backed generation authentication, and fail-closed unique-chain/pointer
classification for the environment-temp prelude. Checkpoint `53bed46` adds
protected-root-owned persistence/enumeration orchestration, and checkpoint
`4a96dd2` adds native protected-DACL generation enumeration/create/read with
flush/reopen verification. Pointer repair now has a pure authenticated
transition/restart-classification model plus create-only protected transition-
generation persistence, fresh-process authenticated reload, and exact planned
pointer-temp creation with durable identity binding. Independently reviewed and
exact-head validated checkpoint `299ae96` promotes only that authenticated temp
after exact source and prior-destination verification and requires exact post-
move evidence. Independently reviewed and exact-head validated checkpoint
`53b618b` removes only the exact empty orphan authorized by an authenticated
`POINTER_TEMP_PLANNED` record through verified held-handle deletion. Backups,
full recovery states, `.env` replacement, transaction refactoring, provider-
installer completion, and final proof remain. Independently reviewed and exact-
head validated checkpoint `d6ce415` adds purpose-separated encrypted exact-
state environment and fixed-certificate backup envelopes bound to the journal
stream. Independently reviewed and exact-head validated checkpoint `1ecfd5e`
adds strict singleton `backup_preparing` intent: it authenticates both envelopes
against the exact stream, records two independent unpredictable blob names and
nonsecret prior-state summaries, persists one immutable journal generation,
and returns only after complete authenticated reread. Independently reviewed
and exact-head validated checkpoint `21aba57` reloads that durable singleton
under the same held protected root, creates only its two exact planned DPAPI
ciphertext blobs with protected DACL and full flush/identity/byte/no-follow
reopen verification, and preserves every partial or ambiguous artifact.
Independently reviewed and exact-head validated checkpoint `92acf29`
reauthenticates both original sealed backups, freshly reverifies those two exact
blobs under one held-root interval, and persists an authenticated
`backup_verified` generation with their identities, ciphertext hashes, and
sizes. Independently reviewed and exact-head validated checkpoint `deee6ab`
freshly reverifies both exact authenticated blobs under one held-root interval
and appends and reauthenticates generation 3 `rollback_armed` without accepting
caller-supplied receipt authority. Independently reviewed and exact-head
validated checkpoint `7b96a6b` reloads exactly that authenticated chain,
freshly reverifies both exact blobs under one held-root interval, and repairs
the metadata pointer to the exact generation-3 `rollback_armed` tip. Activation
is idempotent when current, and failed pointer writes are safely retryable;
restore, cleanup, `.env` replacement, certificate writes, repair, and every
runtime mutation remain disabled.
Independently reviewed and exact-head validated checkpoint `b12280d` adds
fresh-process rollback admission from that armed state. It accepts only the
authenticated three- or four-generation chain, validates the intermediate
`backup_verified` and `rollback_armed` authority, derives both expected backup
receipts only from durable records, and freshly reverifies both exact blobs
under one held-root interval. It makes generation 3 current before appending
and selecting generation 4 `rollback_started`; a retry from generation 4
verifies and repairs its pointer without a duplicate append. Restore, cleanup,
`.env` replacement, certificate writes, repair, and every runtime mutation
remain disabled.
Independently reviewed and exact-head validated checkpoint `56ba458` reads and
authenticates both exact encrypted backups under one held protected-root
interval, matches their complete summaries to generation 1, and appends and
selects generation 5 `environment_restore_temp_planned` at most once. An
originally present `.env` is bound to one unpredictable same-directory temp
name; secure absence records no temp name. Retry repairs only the exact planned
pointer without another generation or name. It creates or restores no file and
enables no cleanup, `.env` replacement, certificate write, repair, or runtime
mutation.
Exact-head validated checkpoint `a37cf8a`, built through `ec2e2d5`, `5b337a7`, `30e7529`,
`cc5183a`, and `51f0673`, adds the strict generation-6 created-state schema,
native zero-byte restore-temp creation/verification, authenticated discovery
and package-bound cross-protocol classification, and mandatory scan evidence
between package/`.env` and target lock acquisition. Provider-environment
recovery blocks target acquisition; repair recovery is retained only as
read-only owner evidence. The exact head passes `1838/1838` launcher tests,
focused static/security checks, CI/CD run `35157843681`, Task-087 run
`35157843639`, and Trivy; the main-only build is neutral as designed. No
restore, cleanup, `.env` replacement, certificate write, repair, or runtime
mutation is enabled.
Independently reviewed and exact-head validated checkpoint `57e280e` wires only
generation 6 `environment_restore_temp_created`. Under caller-held package-root
trust, it accepts only the authenticated generation-5 or generation-6 chain,
creates and records the exact planned zero-byte temp for an originally present
`.env`, records secure absence without a storage call, and on retry reverifies
the recorded identity before repairing only the exact generation-6 pointer.
CI/CD run `35159400390`, Task-087 run `35159400276`, and Trivy passed; the
main-only build is neutral as designed. Restore content, `.env` replacement or
removal, completed-transaction cleanup, certificate writes, repair activation,
and runtime mutation remain disabled.
Independently reviewed checkpoints `1eb3363` and `d9f6563` define and implement
generation 7 `environment_restore_temp_verified`. A fresh process reauthenticates
the exact environment backup, writes its original bytes only to the recorded
generation-6 temp through a non-truncating `OPEN_EXISTING` handle, flushes and
verifies the same handle, then closes/reopens and verifies identity, DACL,
size, and hash before appending generation 7. Complete exact crash residue is
reverified without another write; partial or mismatched residue is preserved
and blocks. Secure absence makes no storage call. Local validation passes
`1854/1854` launcher tests plus all focused static/security gates and two
independent reviews. Exact-head CI/CD run `35238335037`, Task-087 run
`35238334999`, and Trivy pass; the main-only build is neutral as designed.
`.env` replacement/removal and all later recovery or runtime mutation remain
disabled.
Pushed checkpoint `1b85a93` now defines the authenticated generation-8
`environment_restored` state contract and strict eight-generation continuity.
It binds exact restored presence/absence, content, original metadata, and the
present-state destination identity to generation 7. Focused, adjacent, and
broader recovery tests pass `44/44`, `143/143`, and `280/280`. It performs no
destination operation and grants no mutation authority; exact-head workflows
and independent review remain pending.
Pushed checkpoint `16a8224` additionally binds the immutable environment
candidate hash and size into authenticated `backup_preparing` authority after
requiring the plan's original state to equal the encrypted backup. This closes
fresh-process classification for an originally absent `.env` without storing
candidate plaintext. Recovery/provider regressions pass `343/343`; exact-head
workflows and independent review remain pending. No mutation is enabled.
Pushed checkpoint `6637c0d` carries exact original `.env` identity through the
encrypted backup and generation-1 authority, rejects identity drift before
backup-blob creation, and adds a pure fail-closed restore classifier. Only the
exact original, an exact future journal-bound candidate, or secure absence can
be acted on; every metadata/content/identity drift blocks. Affected and broader
tests pass `54/54` and `361/361`. No destination operation is enabled; exact-
head workflows and independent review remain pending.
Pushed checkpoint `39127a5` extends candidate temp authority with exact file
attributes and a stable owner/DACL policy fingerprint, requiring exact native
facts at creation, after write, and after no-follow reopen. Focused Windows tests pass
`171/171`; the broad launcher set excluding only the antivirus-blocked host-
helper module passes `1930/1930`. No destination promotion is enabled; exact-
head workflows and independent review remain pending.
Committed checkpoint `5e83e46` adds the pure exact promotion classifier, a
no-follow native `ReplaceFileW`/non-overwriting `MoveFileExW` boundary with
post-call reconciliation, and the authenticated `environment_applied` schema.
Focused tests pass `171/171`, elevated real-Windows replacement/move passes,
and the broad launcher ring passes `1959/1959` with only the unchanged
antivirus-blocked host-helper module excluded. Production journal orchestration
and every repair/runtime call site remain disabled; push, exact-head workflows,
and independent review remain pending.
Committed checkpoint `30e30ef` durably records the exact original `.env`
authority, appends and reauthenticates all staging generations, requires the
verified generation to be current before apply, persists `environment_applied`
exactly once, and repairs only its exact pointer after restart. Focused tests
pass `249/249`; the broad launcher ring passes `1973/1973` with only the
unchanged antivirus-blocked host-helper module excluded. No installer/repair
call site exists, so runtime mutation remains disabled; push, exact-head
workflows, and independent review remain pending.
No repair or mutation is enabled. Gate B preview integration and Task-100
signing remain separate. Earlier independently reviewed checkpoint `2edcb8e`
adds the protected Local AppData/current-user DPAPI
foundation. Earlier checkpoint `0882017` connects the retained inputs through
Windows trust and native observation to a revalidated, still-held exact target
and consumes that owner in production confirmation. Earlier checkpoint
`caf3f1c` retains the package and Windows process environment, runtime and
endpoint, acceleration evidence, and final exact-plan inputs. Earlier
checkpoint `17d813f` retains the authenticated managed Podman provider and its
base CPython dependency closure.

**Current Release State**:

- Fork-side `v0.1.2` is the immutable pilot package.
- Iterative unsigned fork packages use immutable `v0.1.3-preview.N` GitHub
  prereleases and are never marked `Latest`.
- `v0.1.3-rc.N` is reserved for the signed production-shaped candidate created
  under Task-100.
- Task-101 is complete; alert `#76` closed as fixed without dismissal. Its
  reconciliation and lifecycle evidence remains in the completed-task record.
- Task-087 implementation head `515c1f5` adds authenticated exact-state authority
  for terminal rollback verification after the native volume-preserving restart.
  `50f6524` is the validated exact head: CI/CD run `35290085769`, Task-087 run
  `35290085763`, and Trivy passed. The native rollback-verification adapter,
  transaction integration, and live trust/runtime proof remain; PR #67 remains
  Draft.
  Gate A remains open and mutation remains disabled. Detailed
  status and evidence are maintained in the
  [`Gate A burn-down`](./tasks/active/TASK-087/GATE-A-STATUS.md), not duplicated
  in this release-state summary.
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

**Status**: IN_PROGRESS / IMPLEMENT - Gate A is materially advanced and remains
open. The current implementation head is `515c1f5`; `50f6524` is the validated
exact head. Provider `.env` mutation/reconciliation, fresh-process rollback
resumption, all durable rollback states, native terminal cleanup, and retained-
container native runtime availability are implemented. Exact certificate
replacement bytes and their durable candidate summaries are now bound before
backup persistence. Stage-stable runtime/image/Compose and all-volume recovery
authority is also bound before mutation and enforced at runtime availability.
The absent-target owner now reconstructs and twice revalidates the same
Compose/image/all-volume authority without another trust-selection call, then
revalidates absence before one fixed volume-preserving recreation and requires
four exact present captures to recover the original authority. The manager-
facing port now selects the retained or exact recreated path and closes all
owners. Native certificate restoration now derives exact authority from the
authenticated stream, retains and revalidates original bytes across contained
Docker/Podman copy operations, atomically restores originals or removes exact
candidates, and reconciles engine failures only from exact post-state. Its
replacement broad evidence passes `734/734` non-native plus `177/177` native
tests; focused static/security checks pass. The initial
`231/233` test-placement failures, two newly introduced Bandit findings, and a
non-executing grammar-command quoting error were all corrected and superseded
by clean runs; its later mypy redeclaration and unsupported Black option were
also corrected before checkpointing. Certificate-restoration command-plan,
typing, grammar, patch-layout, and combined pytest-teardown failures were also
corrected or superseded by clean replacement runs. Native runtime restart now
uses only fixed volume-preserving service force-recreation, retires the old
target authority, and proves the exact new container against the original
runtime and all-volume authority. Its focused/adversarial evidence passes
`146/146`, and its split broad evidence passes `536/536` non-native plus
`189/189` Windows-native tests. All observed assertion, transition-code, and
typing failures were corrected and superseded by clean runs. Remaining
implementation is native rollback verification and the `repair.py` transaction
refactor. Live
Windows trust and Docker/rootless-Podman proof remains pending a supported
context and runtime-readiness confirmation. The chronological ledger follows.
Slices 1-3
are complete. The September 14 checkpoint connects the
retained exact-target facade to bounded typed confirmation and adds ordered
revalidation hooks. Slice 4 remains partial: the independently reviewed native
path limits authorization to one eligible Windows root and a bounded exact
intermediate snapshot, but the supported fixed-host proof remains open because
cache-only revocation currently fails closed with offline/unknown status.
Earlier Docker/rootless-Podman checks prove transport containment only. Slices
5 and 8 are partial; slice 5's protected Local AppData/current-user DPAPI
foundation and secure-absence owner are independently reviewed and
checkpointed. Its pure `.env` byte-transform/state-classification prerequisite
is committed, independently reviewed, and exact-head validated. Independently
reviewed checkpoint `1c45445` adds private journal-gated restrictive temp
staging with native Windows DACL, identity, complete-write, flush/readback, and
no-follow reopen proof. Its exact-head CI/CD and Task-087 workflows pass.
Durable journal storage, native promotion/replacement, indeterminate-result
classification, and cleanup remain open. Slice 6 is now partial: independently
reviewed and exact-head validated checkpoint `8bb6b33` adds strict DPAPI-
protected generation/pointer codecs and unique-chain selection for the
environment-temp prelude. The selector authenticates every sealed candidate
internally. Independently reviewed and exact-head validated checkpoint
`53bed46` adds only root-owned persistence/enumeration orchestration over an
injected storage port. No
pointer repair, backup, or recovery action existed at that checkpoint. The next
increment implemented the native generation-file adapter, passed two independent
source/security reviews, was checkpointed at `4a96dd2`, and is exact-head
validated. Checkpoint `221612c` adds pointer-aware authenticated load and pure
missing/stale pointer repair orchestration through an injected port and is
exact-head validated. Checkpoint `95ca37d` adds native pointer replacement and
exact success-path verification and is independently reviewed and exact-head
validated. Independently reviewed and exact-head validated checkpoint `ebb9d69`
adds exact same-call completed-move reconciliation after an ordinary API error.
Exact-head validated checkpoint `31f63f2` adds the pure authenticated pointer-
transition and restart-classification model. Independently reviewed and exact-
head validated checkpoint `5252c7a` adds create-only protected transition-
generation persistence and fresh-process authenticated reload. Independently
reviewed implementation checkpoint `7341997` creates and fully verifies the
exact planned pointer temp and durably binds its stable identity; docstring-only
exact head `dd0d42d` accurately states that boundary and is exact-head
validated. Independently reviewed and exact-head validated checkpoint `299ae96`
promotes only that authenticated temp after exact source/prior-destination proof
and requires exact completed-move evidence. Independently reviewed and exact-
head validated checkpoint `53b618b` adds only authenticated planned-state,
zero-byte pointer-temp orphan cleanup by verified held handle. Backups, full
recovery states, and fresh-process recovery action remain open. Independently
reviewed and exact-head validated checkpoint `21aba57` adds create-only
protected persistence for the two exact `backup_preparing` ciphertext names,
with durable authority reloaded under the same root hold and every partial or
ambiguous artifact preserved. Independently reviewed and exact-head validated
checkpoint `92acf29` adds strict `backup_verified` journal state, exact held-
root blob rereads, and immutable generation append plus authenticated reread.
Independently reviewed and exact-head validated checkpoint `deee6ab` adds fresh
held-root reverification of both exact authenticated blobs and immutable
generation 3 `rollback_armed` append plus authenticated reread. Independently
reviewed and exact-head validated checkpoint `7b96a6b` freshly reverifies both
exact blobs under the same root hold and repairs a missing or stale pointer to
the exact armed tip, with idempotent already-current behavior and safe retry
after pointer-write failure. Independently reviewed and exact-head validated
checkpoint `b12280d` adds fresh-process admission from that exact armed state:
it reauthenticates the chain, reverifies both blobs, makes generation 3 current
before append, and persists and selects generation 4 `rollback_started` at
most once. Retry repairs only the started pointer. Restore, cleanup, `.env`
replacement, certificate writes, repair, and runtime mutation remain disabled.
Independently reviewed and exact-head validated checkpoint `56ba458` then adds
generation 5 `environment_restore_temp_planned`. It authenticates both exact
backups under one held root and records either one unpredictable restore-temp
name for an originally present `.env` or a no-temp secure-absence plan. Retry
repairs only the exact planned pointer without another generation or name. No
file creation, restore, cleanup, `.env` replacement, certificate write, repair,
or runtime mutation is enabled.
Independently reviewed and exact-head validated checkpoint `a37cf8a` adds the strict
generation-6 schema and native zero-byte restore-temp storage primitive, then
makes authenticated package recovery scanning mandatory under the retained
package/`.env` lock before target-lock acquisition. Provider pending blocks;
repair pending is retained only as evidence. Recovery action and all package or
runtime mutation remain disabled.
Independently reviewed and exact-head validated checkpoint `57e280e` consumes
only the authenticated generation-5 plan through that narrow storage port and
persists generation 6 at most once. Present-state retry verifies the exact
recorded temp identity before pointer repair; secure absence creates no temp.
No restore content, `.env` replacement/removal, completed-transaction cleanup,
certificate write, repair activation, or runtime mutation is enabled.
Independently reviewed checkpoints `1eb3363` and `d9f6563` add strict generation
7 schema/continuity and exact restore-temp content staging. The original bytes
are freshly authenticated from the encrypted backup, written only through the
recorded generation-6 identity, flushed, reread, reopened, and verified before
generation 7 is appended. Retry accepts only exact complete residue and repairs
only the generation-7 pointer; partial or mismatched artifacts remain preserved.
Exact-head CI/CD run `35238335037`, Task-087 run `35238334999`, and Trivy pass;
the main-only build is neutral as designed. `.env` replacement/removal and all
later mutation remain disabled.
Pushed checkpoint `1b85a93` adds only the strict generation-8
`environment_restored` schema, canonical codec, predecessor/metadata
continuity, and present/absent shape validation. Focused, adjacent, and broader
recovery tests pass `44/44`, `143/143`, and `280/280`. Native destination
classification/apply, generation-8 orchestration, and every later mutation
remain open. Exact-head workflows and independent review are pending.
Pushed checkpoint `16a8224` binds the candidate hash/size required for exact
present/absent/candidate/third-state recovery classification into generation 1
after matching the immutable plan to the authenticated original backup.
Recovery/provider regressions pass `343/343`; no destination operation is
enabled and exact-head workflows/independent review remain pending.
Pushed checkpoint `6637c0d` binds the original file identity and adds the pure
exact-original/candidate/absence/third-state restore decision. Affected tests
pass `54/54`, the broader recovery/provider ring passes `361/361`, and all
focused static/security checks pass. No destination operation is enabled and
exact-head workflows/independent review remain pending.
Pushed checkpoint `39127a5` records and reverifies candidate file attributes
and owner/DACL policy fingerprint alongside its stable identity/hash/size. Focused
Windows tests pass `171/171` and the broad launcher set, excluding only the
externally antivirus-blocked host-helper module, passes `1930/1930`. No
destination promotion is enabled; exact-head workflows and independent review
remain pending.
Pushed checkpoint `5e83e46` implements the exact native destination
promotion/reconciliation boundary and authenticated applied-state schema.
Focused promotion/recovery tests pass `171/171`; elevated native replacement/
move passes; `108/108` final review tests pass with the expected unelevated
policy skip; and the broad launcher ring passes `1959/1959`. It remains unwired
from durable journal orchestration and production repair, so mutation stays
disabled; independent review remains pending.
Pushed checkpoint `30e30ef` adds the durable staging adapter and held-root
promotion orchestration. It authenticates every immutable generation before
returning a receipt, makes generation 3 current before destination apply,
appends generation 4 exactly once after exact completion, and handles a fresh-
process retry by re-verifying applied state and repairing only the exact
pointer. Focused and broad tests pass `249/249` and `1973/1973`; all focused
static/security checks pass. Product call sites and runtime mutation remain
disabled; independent review remains pending.
Pushed checkpoint `d531f82` reconciles planned/created provider residue across
restart, removes only the exact authorized zero-byte orphan, resumes the exact
partial temp, and treats applied provider journals as terminal scan evidence.
Its exact-head Python 3.11/3.12, security, frontend, Docker frontend, Task-087,
and Trivy checks pass; the main-only build skips as designed.
Pushed checkpoint `121db54` reloads and cross-checks the authenticated terminal
provider stream, restores or removes only its exact applied candidate through a
native held/no-follow boundary, verifies exact original state, and appends
generation 8 at most once. Focused recovery tests pass `92/92`, the affected
native ring passes `443/443`, and the broad launcher/Windows set passes
`2003/2003`; focused static/security and Python 3.11 grammar checks pass.
Exact-head workflows and independent review remain pending.
Slice 7 is not started; slice 9 continues incrementally. Mutation is disabled
and PR #67 remains Draft.
**Type**: B/C (Runtime Support / Setup UX / TLS Trust)
**Priority**: HIGH
**Remaining Estimate**: Rebaseline after `515c1f5` against the fixed acceptance
criteria rather than commit count. The rollback-verification native adapter,
recovery/transaction integration, successful Windows trust/live-runtime proof,
final exact-head review, and the PR #67 decision still precede Task-096.
**Task File**:
`.agent_work/tasks/active/TASK-087-host-side-tls-repair-control-plane.md`
**Canonical Gate A Burn-Down**:
[`TASK-087/GATE-A-STATUS.md`](./tasks/active/TASK-087/GATE-A-STATUS.md)

**Current Scope And Gates**:

- Use the [fixed Gate A burn-down](./tasks/active/TASK-087/GATE-A-STATUS.md)
  for present status, evidence pointers, remaining criteria, and the next
  outcome sequence.
- Implement only the approved August 20 source-remediation design. Mutation
  remains disabled until the exact target, Windows trust/security, durable
  recovery, and transaction requirements are integrated and reviewed.
- Preserve the visible Python/Tkinter launcher, Google/Azure and Docker/rootless-
  Podman boundaries, all eight named volumes, supported OneDrive behavior, and
  the independent Task-086 fallback.
- Keep historical package/runtime evidence in the Task-087 file. It proves only
  the exact bytes and environments previously tested and does not close the
  current Gate A source findings.
- Keep Gate A source acceptance, Gate B artifact/preview integrity, and
  Gate C/Task-100 signing and managed-endpoint qualification separate. PR #67
  remains Draft.
- After Gate A source acceptance and the PR #67 merge decision, select
  Task-096 before Gate B. Task-096 owns native launcher Start/Open/Stop/Restart;
  backlog Task-102 then owns native first-run setup. Resume Task-087 Gate B
  only after those launcher surfaces are stable so the normal package is built
  around the intended front door once.
- Source checkpoint `f0a9d81` implements the independently reviewed native
  Windows-store trust provider under slice 4 while keeping it unwired. Source
  checkpoint `7f354bc` binds that native result into target-plan ownership and
  discards caller-asserted certificate identity. Independently reviewed
  checkpoint `c84998c` removes certificate identity from the retained
  input-owner contract entirely; the public production handoff accepts it only
  from its internal fixed Windows-trust wrapper before assembly. Reviewed and
  pushed checkpoint `ebd53c9` corrects the Docker source adapter to use the real
  retained PE/Authenticode runtime owner and jointly revalidates the exact
  Docker runtime/endpoint pair. Independently reviewed and pushed checkpoint
  `6c51441` adds the separately authenticated Docker Compose executable, binds
  both Docker executables to one policy and installation directory, and emits
  only redacted target identities. Independently reviewed and pushed checkpoint
  `e59f150` jointly retains and revalidates the authenticated Podman runtime,
  package-selected rootless endpoint, machine configuration, and identity key.
  Independently reviewed and pushed checkpoint `c0639c7` authenticates the exact
  managed-provider catalog bytes and wheel-derived installed inventory;
  corrective checkpoint `454af79` keeps the build-inspector policy pin in sync.
  Independently reviewed checkpoint `7a0c35a` reconciles the deterministic provider-only
  installed `site-packages` inventory with retained verified wheels, a self-reported compatible
  CPython 3.12.10 installer input, exact wheel-byte materialization, no embedded
  packaging bootstrap or wrapper, and bytecode suppression across the current
  PowerShell Podman-provider path. The future native command adds `-I -B` but
  remains unwired. The external
  installer does not authenticate that ambient Python; the retained native
  owner must establish interpreter trust before any provider use.
  Checkpoint `caf3f1c` adds the retained package/process environment and
  acceleration authorities plus the final exact-input composer. Checkpoint
  `db7aee8` connects those inputs through Windows trust and native observation
  to one revalidated, still-held exact target. Test-only checkpoint `9993b4d`
  repairs Linux package imports in the four new runtime/target test modules;
  both Python 3.11 and 3.12 GitHub unit jobs pass at that exact branch head.
  The September 14 checkpoint makes confirmation consume that owner and adds
  ordered stage-specific revalidation. Independent review reconciled three
  findings: invalid ordering now invalidates the transaction, cache-only
  revocation is enforced, and candidate intermediates must belong to the exact
  bounded Windows-`CA`/server snapshot. Slices 2-3 close here; slice 4 remains
  open pending a successful revocation-aware fixed-host and repeated container
  containment proof.

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
12. [ ] After Gate A source acceptance and the PR #67 merge decision, select
  Task-096 and add native state-driven Start/Open/Stop/Restart controls without
  PowerShell, CMD/BAT wrappers, shell text, the dormant helper, or runtime
  socket exposure.
13. [ ] Select backlog Task-102 after Task-096 and add native first-run package,
  asset, runtime, and readiness setup. Keep provider-key entry in the existing
  browser Setup Wizard and retain scripts only as support fallbacks.
14. [ ] Resume Task-087 Gate B after Tasks 096/102 stabilize the launcher:
  complete staged-byte/archive verification, the explicit hash-locked Python
  3.12 provenance-v2 build, and normal release-package integration.
15. [ ] Complete Task-097 qualification against the integrated front-door
  package for Docker CPU/GPU and Podman CPU/GPU.
16. [ ] Test each published `v0.1.3-preview.N` through the actual GitHub download
  path on an approved unmanaged clean Windows machine without security
  exclusions or bypass instructions, refining until package satisfaction.
17. [ ] Keep Tasks 091-093 behind the stable unsigned package/runtime-shape
  boundary; Task-091 prepares the owner-runnable harness before Task-100.
18. [ ] Keep production signing and representative managed-endpoint validation
  scheduled as Task-100 after the ADR-019 satisfactory-package decision.

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
