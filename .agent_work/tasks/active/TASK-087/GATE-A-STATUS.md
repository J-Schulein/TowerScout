# TASK-087 Gate A Status

**As Of**: September 15, 2026
**Branch**: `feature/task-087-windows-launcher-prototype`
**Implementation Head**: `4a96dd2e81aa6740b67aa335ff7d51fc6a4bfa18`
**Validated Exact Head**: `4a96dd2e81aa6740b67aa335ff7d51fc6a4bfa18`
**Local Candidate**: Documentation reconciliation only; no uncommitted source
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
and Trivy. The local candidate adds only the root-owned pure orchestration port;
the native file adapter and pointer protocol remain open. Independently reviewed
checkpoint `53bed46` contains that orchestrator and passed exact-head CI/CD run
`35013069183`, Task-087 run `35013069124`, and Trivy; the main-only build was
neutral as designed. Documentation checkpoint `2e0f90e` passed exact-head CI/CD
run `35014300773`, Task-087 run `35014300816`, and Trivy. A local candidate now
implements only the native generation-file adapter; pointer and recovery work
remain open. Independent source/security review returned `CLEAN/PASS` with no
actionable Low-or-higher findings. Final exact-diff review also returned
`CLEAN/PASS`. Implementation checkpoint `4a96dd2` passed exact-head CI/CD run
`35016174147`, Task-087 run `35016174145`, and Trivy; the main-only build was
neutral as designed.
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
| 6 | Recovery manager | **PARTIAL** | Independently reviewed and exact-head validated checkpoint `8bb6b33` defines redacted immutable stream/generation/pointer models for the environment-temp prelude, strict canonical JSON, current-user-DPAPI protection/authentication through the existing protected-state boundary, actual predecessor-ciphertext digest links, exact staging-record continuity, and fail-closed unique-chain/pointer classification. The selector accepts sealed generations and authenticates every candidate internally. Independently reviewed and exact-head validated checkpoint `53bed46` adds a synchronous protected-root storage lease plus pure list/read/create orchestration that authenticates the complete chain before and after create, rejects malformed same-stream names and duplicate file identities, and supports restart-style load through an injected port. Independently reviewed and exact-head validated checkpoint `4a96dd2` adds bounded native enumeration plus protected-DACL `CREATE_NEW`, complete write/flush, same-handle verification, no-follow reopen, stable identity/path/local-volume/regular-file/single-link/DACL/size/byte verification, and an isolated real-Windows round trip. No pointer mutation or recovery action exists. | Implement durable same-volume pointer updates and repair, encrypted exact-state backups, full journal states, fresh-process idempotent recovery, verified rollback, cleanup-pending retention, and cross-protocol scanning. |
| 7 | Transaction refactor | **NOT STARTED** | The older prototype transaction and historical live evidence remain available as behavior references only. | Refactor `repair.py` to consume the immutable resolved target and recovery manager, remove process-memory-only backup and unchecked rollback, and enforce pre-write/pre-restart/terminal revalidation. |
| 8 | Provider installer hardening | **PARTIAL** | Historical checkpoint `3990bc0` closed provider dependency/wheel reproducibility and version verification. Independently reviewed checkpoint `7a0c35a` makes the installed `site-packages` inventory deterministic and provider-only by replacing pip-added metadata with the exact retained wheel inventory, prevents wrapper/bootstrap drift, and suppresses bytecode across the current PowerShell provider path. Its ambient Python compatibility probe is not authentication. | Reuse the protected atomic `.env` contract, change only `PODMAN_COMPOSE_PROVIDER`, remove persistent whole-file plaintext backup/output, and add crash/orphan reconciliation. |
| 9 | Gate A source validation and review | **VALIDATION CONTINUES** | Every completed increment has focused tests and independent review. Secure-absence checkpoint `14b77e4` passed its exact-head gates. Pure-planner checkpoint `0efeff7` passes `47/47` focused and `1536/1536` launcher tests plus static checks and independent source review. Staging checkpoint `1c45445` passes `24/24` focused tests, including real Windows ctypes and retained-native-handle smokes, and `169/169` adjacent tests plus focused static/security checks and independent review. Checkpoint `8bb6b33` passes `26/26` focused journal, `152/152` adjacent, and `155/155` isolated late-launcher tests plus focused static/security checks and CLEAN/PASS corrected-diff independent review. Its exact-head CI/CD run `35010304611`, Task-087 run `35010304675`, and Trivy passed. Documentation checkpoint `e86c41c` passed exact-head CI/CD run `35011029262`, Task-087 run `35011029309`, and Trivy; both main-only builds skipped as designed. Independently reviewed checkpoint `53bed46` passes `20/20` focused, `164/164` adjacent, and `167/167` isolated late-launcher tests plus focused static/security checks and CLEAN/PASS review with no actionable Low-or-higher findings. Its exact-head CI/CD run `35013069183`, Task-087 run `35013069124`, and Trivy passed; the main-only build was neutral as designed. Documentation checkpoint `2e0f90e` passed exact-head CI/CD run `35014300773`, Task-087 run `35014300816`, and Trivy. Independently reviewed checkpoint `4a96dd2` passes `18/18` focused, `182/182` adjacent, and `185/185` isolated late-launcher tests plus focused static/security checks, a real Windows round trip, and two CLEAN/PASS reviews with no actionable Low-or-higher findings. Its exact-head CI/CD run `35016174147`, Task-087 run `35016174145`, and Trivy passed; the main-only build was neutral as designed. | After slices 2-8 are integrated, run the final broad/adversarial set, fresh-process recovery, isolated Docker CPU then approved rootless-Podman CPU mutation/recovery, OneDrive and two-session Windows proofs, all-volume verification, exact-head workflows, and final independent review. |

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
DACL and flush/reopen verification; pointer repair, backup, recovery, cleanup,
and cross-protocol scanning remain.
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
3. **Build durable recovery and refactor repair (slices 6-7).** Review and
  use the checkpointed native generation adapter to add durable pointer repair,
  backups, and the fresh-process journal/recovery manager before enabling the
  refactored transaction.
4. **Harden the external installer and prove Gate A (slices 8-9).** Reuse the
   atomic `.env` protocol, then run the final source, Windows, Docker, Podman,
   recovery, CI, and independent-review gates.

Sub-increments may be implemented and reviewed within these outcomes, but they
do not create new Gate A slices or change a slice state unless they satisfy the
state definitions above.

## Next-Session Resume Point

Implement durable pointer update/repair on the reviewed protected-DACL
generation-storage foundation before any production staging or destination
promotion is wired.
Add native ACL-preserving promotion, indeterminate-result classification, and
exact cleanup only through that protocol. Retry
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
