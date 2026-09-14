# TASK-087 Gate A Status

**As Of**: September 14, 2026
**Branch**: `feature/task-087-windows-launcher-prototype`
**Implementation Head**: `db7aee877a67107a52c4add9371040f4f3b0fa73`
**Validated Code/Test Head**: `9993b4db7c7b7edafeb850f1e33e6c6f7229408c`
**Current Checkpoint**: Slices 2-3 exact-target confirmation wiring complete.
Slice 4 remains partial because restored cache-only revocation fails closed on
this workstation with offline/unknown status.
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
| 4 | Windows trust proof | **PARTIAL** | The reviewed Windows-root eligibility and exact-root selection contracts remain. The September 14 review remediation creates a bounded exact Windows-`CA` plus server-intermediate snapshot, supplies it as an additional build store, rejects every candidate whose intermediate fingerprint is outside that snapshot, retains one exclusive filtered root store, restores cache-only chain revocation, disables AIA/root auto-update, and applies SSL hostname policy. The current workstation now fails closed for Azure with offline/unknown cached revocation status; Google also fails closed. Earlier disposable network-disabled Docker and rootless-Podman checks showed exactly one selected PEM crossed the boundary, but that selection predates restored revocation and therefore proves transport containment only, not current end-to-end trust success. No certificate bytes or identity were stored as evidence. | Obtain a successful fixed-host proof with current revocation enforcement in a supported Windows context, then repeat the one-selected-root Docker and rootless-Podman containment proof from those same reviewed bytes. |
| 5 | Windows security proof | **PARTIAL** | `2d37e66` implements handle/file-ID, owner, DACL, reparse, hard-link, and supported cloud/OneDrive path controls. `f7d21a9` and `16604c8` implement secured cross-session mutexes and ordered `.env`/target lock ownership. | Add protected Local AppData state, current-user DPAPI, secure absence proof, and ACL-preserving atomic `.env` replacement; then exercise the completed primitives together. |
| 6 | Recovery manager | **NOT STARTED** | The approved journal/recovery contract and adversarial scenarios are documented. | Implement the versioned write-ahead journal, encrypted exact-state backups, authenticated startup reconciliation, fresh-process idempotent recovery, verified rollback, and recovery-pending retention. |
| 7 | Transaction refactor | **NOT STARTED** | The older prototype transaction and historical live evidence remain available as behavior references only. | Refactor `repair.py` to consume the immutable resolved target and recovery manager, remove process-memory-only backup and unchecked rollback, and enforce pre-write/pre-restart/terminal revalidation. |
| 8 | Provider installer hardening | **PARTIAL** | Historical checkpoint `3990bc0` closed provider dependency/wheel reproducibility and version verification. Independently reviewed checkpoint `7a0c35a` makes the installed `site-packages` inventory deterministic and provider-only by replacing pip-added metadata with the exact retained wheel inventory, prevents wrapper/bootstrap drift, and suppresses bytecode across the current PowerShell provider path. Its ambient Python compatibility probe is not authentication. | Reuse the protected atomic `.env` contract, change only `PODMAN_COMPOSE_PROVIDER`, remove persistent whole-file plaintext backup/output, and add crash/orphan reconciliation. |
| 9 | Gate A source validation and review | **VALIDATION CONTINUES** | Every completed increment has focused tests and independent review. Test-only checkpoint `9993b4d` repaired Linux import portability in four runtime/target test modules without changing production bytes. At that exact branch head, all applicable checks passed in CI/CD run `34650679798`, Task-087 run `34650679809`, and external Trivy job `103431962097`; both Python unit-matrix jobs passed and the PR-only build skipped as designed. | After slices 2-8 are integrated, run the final broad/adversarial set, fresh-process recovery, isolated Docker CPU then approved rootless-Podman CPU mutation/recovery, OneDrive and two-session Windows proofs, all-volume verification, exact-head workflows, and final independent review. |

## Progress Interpretation

Gate A is materially advanced but remains open. Group 1's exact-runtime and
exact-target outcomes are complete. The Windows-trust implementation is
review-remediated, but its successful
fixed-host proof remains open because the current workstation correctly fails
closed on unavailable cached revocation. The durable mutation and recovery half
also remains. The branch has accumulated substantial
implementation, test, review, and documentation activity since reviewed
lifecycle head `6e0f744`; the slice states above, not commit count or line
count, determine completion.

## Remaining Outcome Sequence

1. **Finish slice 4.** Obtain a successful current fixed-host Windows trust
   proof with cache-only revocation,
   then repeat Docker/rootless-Podman one-root containment. Keep mutation disabled.
2. **Finish Windows mutation foundations (slice 5).** Complete DPAPI-backed,
   ACL-preserving atomic `.env` handling by reusing the already reviewed path
   and mutex controls.
3. **Build durable recovery and refactor repair (slices 6-7).** Implement the
   fresh-process journal/recovery manager before enabling the refactored
   transaction.
4. **Harden the external installer and prove Gate A (slices 8-9).** Reuse the
   atomic `.env` protocol, then run the final source, Windows, Docker, Podman,
   recovery, CI, and independent-review gates.

Sub-increments may be implemented and reviewed within these outcomes, but they
do not create new Gate A slices or change a slice state unless they satisfy the
state definitions above.

## Next-Session Resume Point

Obtain slice 4's successful fixed-host revocation-aware proof and repeat its
Docker/rootless-Podman containment test. Do not enable repair or mutation.
After Group 1 closes, complete group 2's slice 5 DPAPI/ACL-preserving atomic `.env` foundations,
group 3's slices 6-7 recovery and transaction refactor, and group 4's slice 8
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
