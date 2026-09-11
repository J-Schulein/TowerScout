# TASK-087 Gate A Status

**As Of**: September 11, 2026
**Branch**: `feature/task-087-windows-launcher-prototype`
**Implementation Head**: `caf3f1c6f1af697f4d5161769226edd81844708d`
**Draft PR**: [#67](https://github.com/J-Schulein/TowerScout/pull/67)
**Overall State**: IN_PROGRESS / Gate A source implementation
**Gate A Exit**: NOT MET
**Runtime Mutation**: Disabled; the new security path remains inert and unwired

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

## Fixed Gate A Burn-Down

| ID | Approved slice | State | Material evidence already completed | Remaining before this slice is complete |
| ---: | --- | --- | --- | --- |
| 1 | Contracts and models | **COMPLETE** | Immutable target/plan contracts, redacted summaries, mutation-off default, Windows-path portability, and adversarial contracts are checkpointed from `7ad221d` through `0eebe7b`. | Keep the contracts stable while later integration consumes them. |
| 2 | Runtime resolver | **BUILT BUT UNWIRED** | Runtime/Compose authentication, exact CPython dependency and dynamic-load policy, provider-child containment, held ownership, rootless Podman resolution, package configuration, and Docker named-pipe capture are implemented and independently reviewed. Key checkpoints include `1970f76`, `2d37e66`, `e18fb3a`, `d40bb7f`, `f423da4`, `30acb79`, `a4e7015`, `81f82b3`, `8076823`, `dd1af9c`, `2d885cc`, and `eaa2116`; the stable production target-plan assembler hands its exact retained second capture to the native bridge. Independently reviewed checkpoints `7f354bc` and `c84998c` bind fresh native Windows trust and remove caller-supplied certificate identity. Reviewed checkpoints `ebd53c9` and `6c51441` retain and jointly revalidate the Docker runtime, named-pipe endpoint, and authenticated sibling Compose executable. Reviewed checkpoint `e59f150` retains the authenticated Podman runtime, package-selected rootless endpoint, machine configuration, and identity key. Reviewed checkpoint `c0639c7` binds the exact provider-catalog bytes in package policy, authenticates the pinned wheels, reconstructs the exact allowed installed distribution inventory, and rejects metadata, load-surface, and Python customization-hook drift. Corrective checkpoint `454af79` synchronizes the build inspector's package-policy digest and adds a regression preventing pin drift. Independently reviewed checkpoint `7a0c35a` reconciles the deterministic provider-only `site-packages` inventory: a self-reported compatible CPython 3.12.10 installer input, retained verified wheels, exact wheel-byte materialization, no embedded packaging bootstrap, no wrapper, and no `.pth`/`.pyc`. The current PowerShell path suppresses provider bytecode; the future native `-I -B` command remains unwired. The installer does not establish Python trust. Independently reviewed checkpoint `17d813f` retains the catalog, wheels, exact installed files and directories, generated entry point, venv interpreter/configuration, authenticated base CPython executable and dependency closure, rejects adjacent interpreter path/startup overrides, and joins that provider owner to the retained Podman runtime/endpoint. Native provider-extension execution admission remains deferred until this source attestation is explicitly consumed by the execution boundary. Independently reviewed checkpoint `caf3f1c` adds retained package/environment and fixed-native Windows process-environment owners, deterministic acceleration/overlay construction, endpoint-bound read-only Docker NVIDIA-runtime/Podman CDI attestation under one coherent retained snapshot, and a final retained composer that populates every exact `TargetResolutionPlanInputs` field from two identical complete captures. It remains source-only. | Connect its exact target ahead of confirmation. |
| 3 | Target resolver | **BUILT BUT UNWIRED** | `0704974` defines the normalized target and revalidation contract; `215d520` defines immutable observation commands; `0674805` strictly normalizes Docker/Podman Compose, container, image, and all eight volume observations; `dd1af9c` executes those plans through the authenticated native boundary while retaining exact owners; `2d885cc` bridges that native authority into the bound resolver; and `eaa2116` adds independently reviewed stable plan assembly and ownership transfer. | Connect the assembled exact target ahead of confirmation, then wire exact-target confirmation and stage-specific revalidation into the transaction. |
| 4 | Windows trust proof | **PARTIAL** | Pure Windows-root eligibility and exact-root selection contracts exist in `trust_policy.py`, with bounded/redacted target fields. Checkpoint `f0a9d81` adds a fixed-host WinHTTP/Crypt32 provider that filters Current User/Local Machine `ROOT`, confines Windows `CA` and server certificates to intermediate use, rebuilds best/alternate paths under exclusive eligible roots, enforces cached revocation and SSL hostname policy, and returns only the selected root. Its focused fake-native tests, independent review, and local read-only Windows-store enumeration pass. Independently reviewed checkpoint `7f354bc` derives the target certificate identity from that root on both stable plan captures. Under independently reviewed checkpoint `c84998c`, the public production handoff accepts certificate identity only from its internal trust wrapper. | Obtain a successful fixed-host proof on a supported Windows execution context (the current sandboxed Schannel probe fails before returning a server chain), and prove only the selected root reaches the container. |
| 5 | Windows security proof | **PARTIAL** | `2d37e66` implements handle/file-ID, owner, DACL, reparse, hard-link, and supported cloud/OneDrive path controls. `f7d21a9` and `16604c8` implement secured cross-session mutexes and ordered `.env`/target lock ownership. | Add protected Local AppData state, current-user DPAPI, secure absence proof, and ACL-preserving atomic `.env` replacement; then exercise the completed primitives together. |
| 6 | Recovery manager | **NOT STARTED** | The approved journal/recovery contract and adversarial scenarios are documented. | Implement the versioned write-ahead journal, encrypted exact-state backups, authenticated startup reconciliation, fresh-process idempotent recovery, verified rollback, and recovery-pending retention. |
| 7 | Transaction refactor | **NOT STARTED** | The older prototype transaction and historical live evidence remain available as behavior references only. | Refactor `repair.py` to consume the immutable resolved target and recovery manager, remove process-memory-only backup and unchecked rollback, and enforce pre-write/pre-restart/terminal revalidation. |
| 8 | Provider installer hardening | **PARTIAL** | Historical checkpoint `3990bc0` closed provider dependency/wheel reproducibility and version verification. Independently reviewed checkpoint `7a0c35a` makes the installed `site-packages` inventory deterministic and provider-only by replacing pip-added metadata with the exact retained wheel inventory, prevents wrapper/bootstrap drift, and suppresses bytecode across the current PowerShell provider path. Its ambient Python compatibility probe is not authentication. | Reuse the protected atomic `.env` contract, change only `PODMAN_COMPOSE_PROVIDER`, remove persistent whole-file plaintext backup/output, and add crash/orphan reconciliation. |
| 9 | Gate A source validation and review | **VALIDATION CONTINUES** | Every completed increment has focused tests and independent review. At exact head `454af79`, all applicable checks passed in CI/CD run `34630327246`, Task-087 run `34630327259`, and external Trivy job `103365410429`; the PR-only build skipped as designed. | After slices 2-8 are integrated, run the final broad/adversarial set, fresh-process recovery, isolated Docker CPU then approved rootless-Podman CPU mutation/recovery, OneDrive and two-session Windows proofs, all-volume verification, exact-head workflows, and final independent review. |

## Progress Interpretation

Gate A is materially advanced but is not near exit. The exact-runtime and
exact-target foundation is approaching end-to-end integration. The durable
mutation and recovery half remains. The branch has accumulated substantial
implementation, test, review, and documentation activity since reviewed
lifecycle head `6e0f744`; the slice states above, not commit count or line
count, determine completion.

## Remaining Outcome Sequence

1. **Finish trust-backed exact-target wiring (slices 2-4).** The native
   observation executor, authority factory, owned exact-target bridge,
   authenticated production plan assembler, and reviewed Windows trust
   provider and retained managed-provider/Podman join are checkpointed. The
   final retained input owner is checkpointed from the package,
   process-environment, runtime/endpoint, and acceleration authorities. Next,
   connect its exact target ahead of confirmation and wire stage-specific
   revalidation.
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
