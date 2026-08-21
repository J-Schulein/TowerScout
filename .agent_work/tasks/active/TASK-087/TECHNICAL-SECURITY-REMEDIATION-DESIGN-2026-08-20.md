# Task-087 PR #67 Technical/Security Remediation Design

**Date**: August 20, 2026
**Task**: `TASK-087`
**Draft PR**: [#67](https://github.com/J-Schulein/TowerScout/pull/67)
**Reviewed Head**: `6e0f744eb85a98aad913ede78c84adf6636016d5`
**Base**: `9276084d91807906c53e00060670692b27e38483`
**External Review SHA-256**:
`f2f116573ae5b90b122b4275514b49216cdfac354eba43ef192ff541a2d6f253`
**Disposition**: Approved for Gate A IMPLEMENT by the project lead on August 21,
2026. The approval covers the dependency-ordered source remediation in this
design; live runtime mutation, Gate B preview work, PR merge, release, and
Task-100 signing retain their separate gates.

## Objective

Resolve the independently confirmed source and package-integrity gaps reported
against PR #67 without reviving the dormant browser/helper path, weakening
endpoint protections, requiring administrator access, changing a user's runtime
defaults, deleting named volumes, or pulling Task-100 signing work into
Task-087.

This design supersedes the current implementation details wherever they permit
mutable runtime selection, post-confirmation target discovery, best-effort
rollback, process-memory-only recovery, session-local serialization, unsafe
Windows staging, pre-copy package validation, ambient Python selection, or a
persistent plaintext root `.env` backup. It does not invalidate the historical
functional evidence for the exact bytes and environments that were tested.

## Evidence And Independent Disposition

The review was read in full twice and each finding was checked against the
reviewed source. The review is useful outside input, not an authority. The
project's independent disposition is:

| Finding | Independent disposition | Gate |
| --- | --- | --- |
| 1. Mutable runtime/provider/daemon selection | Agree with the source-level core. Runtime, Compose provider, endpoint, environment, and executable identity must be resolved once and authenticated. Requiring a fixed hash for every vendor auto-update is stronger than necessary when a verified publisher and stable file identity are available. | A: source merge |
| 2. Confirmation omits actual mutation target | Agree; blocker. The complete runtime, Compose, container, image, mount, volume, and planned configuration identity must exist before confirmation and be revalidated before mutation/restart. | A: source merge |
| 3. Rollback ignores failures and deletes backup | Agree; blocker. Every restoration step must be checked and backups retained until prior state is independently verified. | A: source merge |
| 4. No durable crash recovery | Agree; high. A write-ahead journal and protected recovery data must survive process termination and restart. | A: source merge |
| 5. Candidate may not be Windows-store trusted | Agree; high. The TLS context and selected root must derive only from filtered Windows stores and server-auth trust. | A: source merge |
| 6. Native Podman path does not bind rootless local machine | Agree; high. Windows Podman normally uses a local-machine remote connection, so the correction binds that approved rootless loopback/WSL connection rather than rejecting all remote-mode mechanics. | A: source merge |
| 7. Serialization is session-local | Agree; medium. Add a cross-session target mutation lock while retaining the existing UI guard. | A: source merge |
| 8. Windows staging/replacement is not handle/ACL safe | Agree; medium. Use protected user-local recovery storage, handle-based identity, and an ACL-preserving atomic `.env` update while supporting legitimate OneDrive/cloud locations. | A: source merge |
| 9. Validation precedes copy | Agree. These artifacts are validation-only rather than previews, but no new artifact should rely on the assembler until staged bytes and the final archive are verified. | B: next artifact / unsigned preview |
| 10. Build toolchain is self-asserted | Partly agree. An explicitly approved exact-patch Python 3.12 environment, hash-locked wheels, and provenance v2 are required before preview. Organization-controlled builder authentication, signing, timestamping, and post-sign manifests remain Task-100. | B now; C under Task-100 |
| 11. Provider installer retains full `.env` backup | Agree with the low-severity underlying debt. It predates PR #67 but its installer/library is present in release and full-validation package paths. Correct it in Gate A before normal-user use without deleting unknown existing backups automatically; Gate B repeats the packaged-installer non-regression proof. | A: source; B: package re-test |

No finding is solved merely by signing `TowerScoutLauncher.exe`. Conversely,
Task-100's later signing and representative managed-endpoint work is not a
prerequisite for correcting these source defects.

## Non-Negotiable Boundaries

The remediation shall:

- keep the visible package-local Python/Tkinter launcher;
- keep the browser unable to issue host operations;
- add no listener, helper process, hidden worker, or dormant-helper import;
- invoke no PowerShell, `cmd.exe`, shell text, or execution-policy bypass from
  the launcher;
- require no administrator access, Windows trust-store mutation, antivirus
  exclusion, or endpoint-policy weakening;
- never change the Docker context, Podman default connection, Podman machine
  mode, or Compose provider automatically;
- never expose an engine socket to the application container;
- never issue `down -v`, `--volumes`, volume deletion, or destructive cleanup;
- preserve all eight named volumes and the Task-086 manual fallback; and
- keep validation artifacts, unsigned previews, signed candidates, and cdcai
  publication as separate identities and gates under ADR-018/019.

## Confidence And Execution Strategy

**Design confidence**: 84% (medium-high).

The requirements and source gaps are clear. The remaining uncertainty is in
Windows handle/DACL/DPAPI behavior across OneDrive locations and real
cross-session locking, plus Docker Desktop and rootless-Podman endpoint/plugin
introspection across supported installations. Implementation therefore uses
proof-first increments for those platform seams before refactoring the live
transaction. No live runtime mutation belongs in the proof stage.

## Architecture

### 1. Immutable Resolved Target

Replace the current name-and-string-only `RepairTarget` with an immutable
`ResolvedRepairTarget`. It is internal and may contain sensitive local identity;
its `repr`, journal, logs, and evidence must expose only fixed categories and
hashes/tokens. Its separately constructed confirmation summary may expose only
the explicit bounded fields defined below; it never uses the object's default
representation.

The target binds:

- package root final path identity, volume serial/file ID, release/source
  identity, and exact security-relevant package-file identities;
- runtime product, canonical executable handle identity, SHA-256, version,
  Authenticode status/publisher policy result, and selected local endpoint;
- Docker context/config identity or Podman connection/machine/user-socket
  identity and rootless result;
- Compose implementation/provider identity and integrity decision;
- exact ordered Compose files and their file identities/hashes;
- normalized pre-change and planned post-change Compose-model hashes;
- project, service, selected CPU/GPU profile, provider, loopback port, and fixed
  certificate destinations;
- actual container ID/name, daemon image ID, matching repository digest, and
  Compose working-directory/config-file labels;
- all eight named-volume identities and mount destinations, including the
  config volume mounted at `/app/webapp/config`; and
- the privately selected Windows-store CA fingerprint and candidate content
  hash.

Security-relevant executable, identity-key, Compose-file, catalog, and manifest
handles are held with write/delete sharing denied from resolution through the
last use; a revalidation failure aborts rather than reopening by name. Target
tokens use a domain-separated, versioned, fixed-field-order binary encoding with
each canonical UTF-8 field length-prefixed before SHA-256. Plain string
concatenation, display values, locale-dependent case folding, and raw local
paths are not token inputs.

This protects against path/config replacement and ordinary processes that lack
permission to mutate the bound files or daemon. It does not claim safety from a
process running as the current user with Docker/Podman daemon authority, or
after compromise of administrator/SYSTEM, Windows trust policy, a permitted
publisher, or the OS. Those conditions are outside the launcher transaction's
trust boundary and require support/rebuild rather than continued mutation.

The public confirmation shows a transaction target token containing at least
128 displayed bits, runtime
product/version, sanitized local endpoint label, project/service, short
container and image identities, profile, provider, port, config-volume label,
normalized Compose-model token, and fixed certificate destinations. It does not
show a local path, full endpoint, certificate subject/fingerprint, provider key,
or environment content. The target token cryptographically binds the hidden
fields so the displayed authorization still refers to the exact internal plan.

### 2. Resolution, Lock, Confirmation, And Revalidation Sequence

1. Resolve the package through a directory handle and inspect the runtime using
   fixed read-only commands.
2. Resolve an initial endpoint/project/config-volume identity sufficient to
   derive the target-scoped lock name.
3. Acquire the cross-session mutation lock, then resolve the complete target
   again under the lock. If the lock key or any identity changed, release and
   require a fresh preview.
4. Select one CA through the Windows-only trust path and derive the complete
   pre/post plan without writing anything.
5. Display the sanitized exact-target summary and typed confirmation. A bounded
   confirmation timeout releases the lock without mutation.
6. Immediately before the first write, revalidate every executable, endpoint,
   package file, Compose model, container, image, mount, volume, and candidate
   identity.
7. Before restart, require the exact planned post-change model and the same
   runtime/endpoint/provider/volume identities.
8. Hold the live mutex while the process executes through verified success,
   verified rollback, or durable recording of `recovery_blocked`. After a
   process death, the abandoned-mutex result plus authenticated journal—not a
   nonexistent live lock—blocks further mutation until recovery.

No actual container or mount discovery may first occur after confirmation.

### 3. Trusted Runtime And Compose Execution

Runtime resolution must not use the package/current directory or ambient
`PATH`/`PATHEXT`. Use a fixed resolver that enumerates supported vendor install
records/locations, opens the candidate, verifies its product/leaf name and
trusted Authenticode publisher policy, records SHA-256 and stable file identity,
and supports legitimate system-wide or user-local official installations. A
static catalog hash may be required for TowerScout-managed artifacts; official
vendor auto-updates may use the accepted publisher plus recorded hash and stable
identity. Unknown, unsigned, ambiguous, replaced, or policy-mismatched binaries
fail closed.

Before Gate A, commit a package-bound runtime policy with exact product IDs,
accepted publisher organizations/chain constraints, supported signature form
(embedded or catalog), timestamp/expiry rules, version policy, and any mandatory
hashes. Verify through Windows trust policy with bounded cache-only revocation;
revoked, untrusted, unknown-revocation, offline-indeterminate, expired-without-
valid-timestamp, or publisher-rollover results fail closed to Task-086. Publisher
rollover changes require normal reviewed policy/catalog update, never dynamic
acceptance from UI text or version output.

Every child receives an adapter-specific minimal environment containing only
required Windows/user/temp values and explicit verified runtime configuration.
Remove ambient `PATH`, `PATHEXT`, proxy/CA injection, `DOCKER_*`, `COMPOSE_*`,
`CONTAINER_*`, and other redirection variables unless a value is explicitly
constructed from the resolved target. Use only absolute executable paths and
fixed argument arrays with `shell=False`, closed stdin, bounded output, and
bounded timeout. The shared executor must stream stdout/stderr into fixed byte
budgets while the child runs and terminate the verified process tree on timeout
or overflow; `subprocess.run(..., capture_output=True)` followed by a size check
is not a bound. CA chains, candidate certificates, and generated bundles also
have fixed count/byte limits before they are retained or written.

Docker requirements:

- treat the selected context name as discovery/display metadata only; capture
  and revalidate its exact local Windows named-pipe endpoint;
- reject TCP, SSH, ambiguous, changed, or environment-selected daemons;
- pass the captured named-pipe endpoint directly (`--host` or an equivalently
  proven fixed adapter) on every Docker operation, so repointing the context
  name cannot redirect execution; and
- resolve and authenticate the exact Docker Compose executable before
  confirmation, then invoke that captured binary directly with the same fixed
  endpoint. Do not delegate through `docker.exe compose` unless a forced-plugin
  mechanism is proven to execute those exact bytes.

Podman requirements:

- add `TOWERSCOUT_PODMAN_MACHINE` to the launcher's allowlisted package
  identity, resolving it from the verified package `.env`/template rather than
  process environment or UI input;
- enumerate connections and bind one approved running local WSL machine's
  loopback user socket explicitly;
- require machine inspection to report `Rootful=false`, then require endpoint-
  bound `podman --url <captured-uri> --identity <captured-key> info` to report
  `Host.Security.Rootless=true`, the expected non-root user socket/store, and
  matching machine/user identity;
- treat the connection name as metadata only. Bind the canonical URI, identity-
  key file identity/hash, machine identity, user, port, and socket privately;
- reject the ambient root connection, rootful/unknown state, non-loopback
  machine, arbitrary remote service, ambiguity, or changed endpoint;
- pass the captured URI/key explicitly on every Podman engine operation without
  changing the user's default connection or machine mode; and
- reject Docker Desktop Compose. The Python interpreter must be authenticated
  separately under the runtime policy. A TowerScout-managed provider must have
  a package-bound independently authenticated catalog, pinned wheel artifacts,
  and installer inputs that reproduce the installed distributions, importable
  module, generated entry point, provider executable hash, and stable file
  identity. Prefer invoking the verified interpreter and module directly; the
  launcher must reject command-script wrappers. An adjacent install receipt
  records evidence but is never a trust root. Invoke the captured provider with
  the captured `podman.exe` path and an adapter-specific constructed endpoint/
  key mechanism; do not call `podman compose` or allow provider-child endpoint
  rediscovery. If the provider cannot prove endpoint propagation, fail closed to
  Task-086. Any external catalog entry must have non-empty accepted hash or
  publisher evidence; name/version-only entries are invalid.

The current workstation fact that `podman-machine-default` is rootless while
the ambient default points to the root socket is a required negative test, not
permission to change that default. The currently discovered Docker Desktop
Compose provider must be rejected for Podman.

### 4. Normalized Compose And Persistent-Volume Policy

Bind both the requested mode (`off`, `auto`, or `on`) and the effective exact
acceleration/overlay decision before confirmation. Preserve the canonical
behavior: `off` is CPU; `on` requires a CUDA package plus Docker GPU or Podman
CDI readiness and fails closed otherwise; `auto` uses the engine-specific
overlay only when the existing package-approved auto-overlay gate and capability
checks permit it, otherwise it selects the documented CPU fallback. A CPU
package with `on`, Podman `on` without CDI, or an engine/overlay mismatch fails.

The resulting exact ordered configuration set is:

- Docker CPU: `compose.yaml`;
- Docker GPU: `compose.yaml` plus `compose.gpu.yaml`;
- Podman CPU: `compose.yaml`; and
- Podman GPU: `compose.yaml` plus `compose.gpu.podman.yaml`.

Invoke Compose with explicit project directory, project name, config files,
environment file, and resolved endpoint/provider. Generate a normalized model
for the exact current `.env` bytes and a second model for the planned two-setting
CA update. Keep raw models and environment values in memory only; persist or
display hashes.

The policy permits only the expected `towerscout` service, fixed image digest,
loopback port, healthcheck, restart policy, selected GPU overlay, and the eight
named volumes at their fixed destinations. Reject unexpected services, build
directives in a runnable release package, bind mounts, privileged/host namespace
settings, unapproved devices/capabilities/security options, external config or
secret sources, changed config paths/working directory, or any other material
model difference.

Inspect the daemon's actual image ID/repository digest, Compose labels, mounts,
and volume objects. The config mount must be the exact expected named volume,
never a bind mount. For each of all eight volumes, bind the endpoint/store plus
exact name, driver, scope, options, Compose labels, mount destination, and
creation/opaque engine metadata where exposed; do not pretend Docker and Podman
share a portable numeric volume ID. Require those engine-specific identities to
remain unchanged before mutation, before restart, and at terminal verification.

The target includes a stage-specific transition plan rather than requiring an
impossible permanent container ID. Before mutation, the original container ID
must match. After the authorized stop, only the expected service absence is
allowed while the captured endpoint, image, Compose model, and all eight volume
identities remain. After restart or recovery recreation, a new container ID is
accepted only when its project/service labels, exact image, effective Compose
model, mounts, port, profile, endpoint, and eight volume identities all match
the bound plan. Any other disappearance or replacement is target drift.

The existing eight Compose volumes remain non-external so normal first-run
setup is not broken. Consequently, an independently daemon-authorized actor can
delete or replace a volume after the last pre-restart inspection, and Compose
may recreate an empty same-name volume. The launcher cannot prevent that
out-of-boundary daemon mutation. It must inspect immediately before restart and
compare the exact engine-specific identities again at terminal verification. A
replacement produces `container_or_volume_mismatch`, retains protected recovery
state, and permits neither `repair_succeeded` nor `repair_rolled_back`. The
launcher must not attempt to reconstruct externally deleted data; Task-086 or
support remains the explicit recovery path.

### 5. Windows-Only CA Selection

Do not use `ssl.create_default_context()` or OpenSSL default paths. Enumerate
Windows `ROOT` certificates as trust anchors, filter to certificates trusted
for TLS server authentication (including explicitly all-purpose trust), and use
Windows `CA` entries only as chain intermediates rather than accepted roots.
Use eligible Windows `ROOT` records as the only trust anchors.
Verify the fixed Google or Azure hostname and chain. The server-provided chain
may supply intermediates, and Windows `CA` entries may supplement missing
intermediates, but neither may terminate trust. Require the selected anchor's
exact DER fingerprint to match the server-auth/all-purpose-eligible Windows
`ROOT` set; forbid partial-chain anchoring. Fail closed when the chain/root is
missing, ambiguous, wrong-purpose, unsuitable, or cannot be inspected through a
supported Windows API. Export only the selected root to the container, never
the leaf or intermediates.

Do not alter the Windows store. Keep PEM, subject, fingerprint, chain, and raw
socket errors out of UI, journal, logs, and repository evidence.

### 6. Cross-Session Mutation Lock

Retain `OperationGuard` and the current local launcher-instance mutex for UI
behavior, but add two secured cross-session mutexes using the same domain-
separated, versioned, length-prefixed encoding defined for target tokens:

- `Global\\TowerScoutEnv-v1-<sha256(parent-volume + parent-file-id + .env)>`
  uses the resolved package-parent handle plus canonical leaf name, so it is
  stable across atomic `.env` replacement; and
- `Global\\TowerScoutRepair-v1-<sha256(endpoint + project + config-volume)>`
  uses the canonical captured endpoint and engine-specific config-volume tuple.

Create both with an explicit DACL granting the current user and SYSTEM only;
neither requires administrator privilege. The launcher always acquires the
package/`.env` mutex first, derives and acquires the target mutex second, then
revalidates both keys and the exact `.env` snapshot. It holds both through final
verification or durable recovery state. The external provider installer uses
the same package/`.env` mutex and holds it from crash reconciliation through
final verification. It never acquires the target mutex, so the order cannot
cycle. External writers that ignore the lock remain covered by immediate byte/
identity checks and cannot be overwritten after drift.

After acquiring the package/`.env` mutex, both actors scan the common protected
state root for every authenticated repair journal and provider mini-journal
bound to that package-parent/`.env` identity. Neither may begin a new mutation
while either protocol is pending. Each actor may reconcile its own protocol;
when the other protocol is pending it fails closed with the corresponding
sanitized recovery-pending result until that owning path completes recovery.
Only after all applicable records are terminal and cleanup-safe may the actor
continue. This cross-protocol scan also runs after an abandoned mutex, so losing
the live lock on process death cannot let one transaction overwrite the other's
uncommitted `.env` state.

Two package copies targeting the same daemon/project/config volume must
conflict; identical project names on distinct verified endpoints need not.
Access denial or global-object failure is a fail-closed
`repair_lock_unavailable`, never a silent fallback to `Local\\`. An abandoned
target mutex with an authenticated armed journal resumes recovery. An abandoned
pre-arm mutex with no armed journal permits retry only after target revalidation;
an invalid or ambiguous journal blocks mutation.

### 7. Protected Durable Recovery

Use the Windows Known Folder API to locate per-user Local AppData rather than
trusting an environment variable. Store state under a versioned TowerScout
directory with a protected current-user/SYSTEM DACL. Resolve Local AppData and
the recovery root by handle; require a fixed local volume and reject remote,
cloud-backed, name-surrogate, or unexpected-owner/broad-writer state. Do not
store recovery secrets under the package or a OneDrive-synchronized tree.

Encrypt and integrity-protect the journal and backup blobs with current-user
DPAPI (`CryptProtectData`, UI forbidden, not machine scope). Persist no plaintext
durable recovery copy of `.env`, CA bytes, local path, endpoint, container/volume
identifier, certificate detail, provider key, or raw output. Metadata uses
schema/version, fixed enums, sequence, target token, hashes/file identities,
existence flags, and opaque blob names. Backups include the exact prior `.env`
bytes plus security metadata and the exact prior certificate/bundle bytes or
absence markers.

Any transient plaintext CA transfer file uses an unpredictable planned name in
the protected local staging directory, restrictive DACL, `CREATE_NEW`, bounded
content, and delete-on-close where the engine adapter permits it. The journal
records planned parent/name/hash, then the created zero-byte file ID/DACL, then
the flushed/reopened verified content. Death before the created-state record may
clean only an exact zero-byte restrictive-DACL planned-name file; any nonempty or
mismatched identity is preserved and blocks recovery. Later states remove only
the recorded identity. The same planned/created/verified ordering governs
same-directory `.env` temporary files.

Write-ahead states are:

```text
backup_preparing -> backup_verified -> rollback_armed
  -> certificate_temp_planned -> certificate_temp_created
  -> certificate_temp_verified -> certificates_applied
  -> environment_temp_planned -> environment_temp_created
  -> environment_temp_verified -> environment_applied
  -> runtime_stopping -> runtime_stopped -> runtime_starting
  -> runtime_started -> success_verifying -> committed -> cleaned
committed -> recovery_cleanup_pending -> cleaned

rollback_armed/.../success_verifying
  -> rollback_started -> environment_restore_temp_planned
  -> environment_restore_temp_created -> environment_restore_temp_verified
  -> environment_restored -> rollback_runtime_available
  -> certificate_restore_temp_planned -> certificate_restore_temp_created
  -> certificate_restore_temp_verified -> certificates_restored
  -> rollback_runtime_restarting
  -> rollback_runtime_restarted -> rollback_verifying -> rollback_verified
  -> cleaned
rollback_verified -> recovery_cleanup_pending -> cleaned

any post-arm unresolved transition -> recovery_blocked -> rollback_started
any pre-arm write failure -> aborted_without_mutation
```

Each transition is a new immutable DPAPI-protected generation containing a
strictly increasing sequence, previous-generation digest, schema, and state.
Create it with the protected DACL, write and `FlushFileBuffers`, reopen, decrypt,
authenticate, and validate the chain. Only then update a metadata-only current-
generation pointer through a same-volume temp, `FlushFileBuffers`, and
`MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`. Retain the previous authenticated
generation until the new generation and pointer reread successfully. Do not
assume a write-through flag on `ReplaceFileW`.

If a pointer update is indeterminate, startup selects only the highest complete
authenticated hash-chained generation and repairs the pointer; conflicting
valid chains or any decrypt/auth/schema/target failure enter a separate
`journal_invalid` hold and are never auto-recovered. `rollback_armed` must be the
active durable generation before the first mutation. Pre-arm failure aborts
without mutation. Ambiguous post-arm state advances monotonically to
`recovery_blocked`; that state is durable and retryable only into rollback, not a
terminal success. `success_verifying` may commit only after all intended state
is reverified. `committed` and `rollback_verified` advance directly to `cleaned`
when cleanup succeeds. Cleanup failure first advances to
`recovery_cleanup_pending`, then to `cleaned` only after a verified retry; it
blocks another repair for that target while retaining encrypted data. The
forward and rollback certificate/`.env` temp states use the same planned-name,
created zero-byte identity/DACL, flushed-content verification, and exact orphan-
classification rules.

Rollback is mandatory, checked, and idempotent. It must:

- revalidate the complete stage-appropriate target and all volumes without
  guessing;
- restore `.env` only if current bytes are either the transaction-produced
  bytes or already the original bytes, never over an unrelated user edit;
- retain the verified existing container when available, or recreate the exact
  prior Compose profile/image with the restored environment and same named
  volumes before certificate restoration; if neither path can provide verified
  volume access, enter `recovery_blocked` without an ad hoc container or guess;
- restore/remove each certificate through that verified runtime according to
  the backup and verify exact content/absence, mode, destination, and volume;
- restart the exact prior Compose profile again after restoration, without
  volume deletion;
- verify actual container/image/mount/volume identity, prior certificate/env
  state, and the captured prior runtime/readiness condition. The pre-repair
  provider category is a sanitized `repairable_tls_failure`; after rollback,
  the same category or `success` is equivalent because external trust can
  improve. Network-unavailable/other external probe drift is reported as
  `provider_recheck_indeterminate` but cannot negate an otherwise exact local-
  state rollback or falsely claim provider success; and
- delete backup data only after `rollback_verified` or `committed` is durable.

The UI must distinguish `repair_rolled_back` from
`repair_recovery_pending`. A generic exception must never claim safe rollback;
it records/loads the journal outcome and directs the user to the fixed recovery
action or Task-086. Task-086 is never invoked automatically.

### 8. Windows Filesystem And `.env` Safety

Support legitimate OneDrive/cloud or junction-based package locations by
binding their resolved handle identity rather than rejecting every ancestor
reparse point. Hold a package-root handle, record final path plus volume/file
ID, and require mutable configuration and sensitive-data leaf files to remain
regular, single-link, contained, and stable. A verified vendor executable may
retain legitimate hard links only while a held handle denies write/delete
sharing and its file identity, content hash, and accepted Authenticode result
remain unchanged; this narrow executable exception covers supported vendor
install layouts without weakening mutable-file policy. Reject symlink/mount-
point/junction leaf redirects, other hard links, unexpected owners, permissive
writable ACLs, path escapes, or identity churn.

The checked-in Windows path policy defines accepted owners by path category
(current user, SYSTEM, Administrators, or TrustedInstaller as applicable) and
rejects write/delete/owner/DACL rights granted to broad principals such as
Everyone, Users, Authenticated Users, Guests, or Anonymous. It does not reject
ordinary inherited read access and does not claim defense against a malicious
process running under the same SID. Cloud support uses an explicit reviewed
numeric allowlist of Microsoft cloud-placeholder reparse tags—never a wildcard
or range—requires hydration/open by handle, and requires stable final volume/
file identity. Unknown tags and all critical-leaf name-surrogate symlink,
junction, or mount-point tags fail closed.

Keep certificate staging in protected Local AppData. For `.env`, create a
same-directory `CREATE_NEW` temporary file with a restrictive DACL and no write/
delete sharing. Durably record its unpredictable name, intended parent/file
identity, and expected content hash in the encrypted journal before creation.
Persist the created zero-byte file ID/DACL state before writing; then write and flush it,
reopen without following a name-surrogate reparse point, and persist verified
bytes/identity. Revalidate the destination immediately before replacement.

Parse `.env` under a fixed size limit as strict UTF-8 with optional preserved
BOM and no NUL. Reject duplicate or malformed `REQUESTS_CA_BUNDLE` and
`SSL_CERT_FILE` settings. Replace only the exact value spans, preserving every
unrelated byte and existing per-line CRLF/LF/trailing-newline form; when a target
is absent, append with the existing newline convention (CRLF for an empty file).

Use `ReplaceFileW` without ignore-ACL flags for an existing file and a same-
volume write-through move for a previously absent file. Treat every API error as
indeterminate rather than “no mutation”: reopen destination and temp by handle
and classify exact original, exact candidate, absent, or third state using
hashes, file IDs, DACL, owner, and attributes. Roll back only a known candidate;
clean a temp only when its exact identity is known. A third/ambiguous state is
preserved as `repair_recovery_pending` and never blindly retried or overwritten.
The same classification runs after an apparent success. Startup removes only
the exact journal-bound orphan temp identity. Delete only journal-recorded
identities, never a glob.

### 9. Validation-Package Staged-Byte Authority

For both validation assemblers, copied staged bytes are the sole provenance
authority:

1. create a protected staging root;
2. copy the base and/or launcher into staging;
3. validate the copied base and obtain its manifest from the staged tree;
4. inspect and verify provenance of the copied launcher;
5. derive every manifest/provenance field from those staged objects;
6. apply the intended overlay and run full-tree safety checks;
7. generate then immediately verify internal checksums;
8. create the ZIP and independently verify its inventory/content against the
   staged tree/checksums;
9. generate the adjacent sidecar from that exact archive; and
10. transactionally move the versioned directory/ZIP/sidecar set into the final
    destination;
11. reopen the final identities and repeat directory-tree/internal-checksum,
    ZIP-inventory/content, and exact sidecar parse/re-hash comparison; then
12. create one public-safe `ARTIFACT-SET-COMMITTED.json` binding schema,
    package kind/version, relative output names, directory-tree/checksum hash,
    ZIP hash, and sidecar hash. Flush and atomically rename that marker last.

Consumers and later publication tooling reject a set without a valid marker and
recheck its bindings. The next assembler invocation reconciles its exact
transaction record and removes only matching uncommitted crash-left identities;
it never globs another artifact. ZIP verification rejects absolute/traversal,
reserved/device, duplicate, Unicode-normalization-conflicting, and Windows case-
colliding member names before extraction or commitment.

Source-side validation may remain a fail-fast optimization but is never
evidence. Do not carry a pre-copy manifest or provenance object into the final
package record.

### 10. Preview Build Integrity Versus Task-100

Before any new validation artifact or unsigned preview uses a rebuilt launcher:

- select and record one exact CPython 3.12 Windows AMD64 patch/artifact, use it
  in a dedicated no-system-site-packages environment, and never use a floating
  `3.12` alias or fall back to ambient `python`;
- verify interpreter implementation/version/architecture, the explicitly
  approved vendor-signature or controlled-build provenance result, and runtime-
  file identity;
- install only from a reviewed hash-locked wheel set with `--require-hashes`,
  preferably from a verified local wheel cache;
- disable user-site/ambient package injection, run `pip check`, and verify the
  exact installed distribution inventory; and
- emit provenance v2 binding source/spec/driver hashes, build-lock and selected
  wheel hashes, installed distributions, Python identity, PyInstaller and
  bootloader identity, executable hash, complete output-tree inventory/hash,
  and public-safe builder characteristics.

The interpreter artifact is a blocking Gate-B decision, not an ambient-host
fact. Python.org identifies
[`3.12.10`](https://www.python.org/downloads/release/python-31210/) as the last
3.12 release with Windows binary installers, while the current
[`3.12.14`](https://www.python.org/downloads/release/python-31214/) security
release is source-only. Therefore the locally available signed 3.12.10
executable is not automatically approved merely because it exists. Before
Gate-B artifact implementation, compare it with all security fixes through the
current 3.12 patch and record either its scoped security/integrity acceptance or an
independently verified controlled newer 3.12 artifact, along with exact artifact
hashes and compatibility evidence. Gate B stays closed until that decision is
explicit.

The package inspector must use a reviewed allowlist/inventory for executable
and loadable `.exe`, `.dll`, and `.pyd` files, not merely reject a short suffix
list. Historical provenance v1 artifacts retain their historical meaning but
cannot be reused for new artifact or preview publication.

Gate B proves drift detection, a reconstructable input record, and verified
output identity for an unsigned preview. It is not a claim that the builder or
publisher is organization-authenticated. Task-100 still owns the accepted clean
rebuild in the organization-controlled Windows job, signed-file boundary, signer/key
custody, timestamp, post-sign manifests/checksums, extracted signature
verification, `v0.1.3-rc.N`, and representative managed-endpoint acceptance.
Do not promote or sign a prior preview executable as the candidate.

### 11. Podman Provider `.env` Update

Remove the persistent root `.env.backup.<timestamp>` behavior. Under a scoped
shared package/`.env` mutex, read the exact original bytes or record an absent-
original sentinel. For an absent file, derive the candidate only from the
authenticated package `.env.example`; for an existing file, change only
`PODMAN_COMPOSE_PROVIDER` under the same size/UTF-8/BOM/NUL/duplicate and exact-
unrelated-byte-preservation contract. Reject reparse/ACL ambiguity. The existing external
PowerShell installer implements the same atomic/security contract through
reviewed .NET/Win32 calls; the Python launcher does not invoke it. Reread/verify
the final bytes and leave no plaintext backup or temporary file after success.
On a post-replace verification failure, restore the in-memory original
atomically, or remove a transaction-created file only when the recorded prior
state was absent and the current identity/hash still equals the candidate. An
unrelated concurrently created/changed file is preserved and fails closed.
A protected metadata-only mini-journal records the target token, original and
candidate hashes, then a `temp_planned` name/parent/hash generation before
`CREATE_NEW`, a `temp_created` actual zero-byte file-ID/DACL generation before
writing, and a `temp_verified` generation after flush/readback. It contains no
`.env` bytes or local path and uses the same authenticated immutable-generation/
pointer durability protocol. Death between create and `temp_created` may remove
only a zero-byte exact planned-name file with the expected restrictive DACL;
anything else is preserved and reported ambiguous. A crash otherwise leaves the
complete old file, a journal-bound private temp, or the complete prevalidated
candidate. The next invocation for the same target token/package-root identity
reconciles hashes, removes only the exact orphan temp identity, and verifies/
commits the old-or-candidate outcome before another update. Any third state
fails closed without overwriting it.

Do not print or return a backup path. Do not automatically delete pre-existing
`.env.backup.*` files because their ownership/purpose is unknown; provide only
sanitized manual review guidance for files matching the old installer pattern.
This rule is separate from any intentional application-internal configuration
backup contract.

## Sanitized Error Matrix

| Category | Mutation | Recovery data | Public action |
| --- | --- | --- | --- |
| `runtime_identity_invalid` / `runtime_replaced` | None | None | Retry with an approved installed runtime |
| `runtime_output_limit` / `runtime_timeout` | None before apply; recover after apply | Preserve if armed | Runtime output/time exceeded the fixed safe bound |
| `runtime_endpoint_rejected` / `podman_rootless_required` | None | None | Select the supported local runtime state; no default is changed |
| `compose_provider_rejected` | None | None | Configure an approved integrity-bound provider |
| `compose_model_rejected` / `target_changed` | None before apply; recover after apply | Preserve if armed | Refresh and reconfirm; never run changed input |
| `container_or_volume_mismatch` | None before apply; recover after apply | Preserve if armed | Use support/Task-086; no volume is deleted |
| `windows_trust_unavailable` / `trusted_ca_ambiguous` | None | None | Use Task-086 support selection; no trust store is changed |
| `repair_busy` / `repair_lock_unavailable` | None | Unchanged | Use the active launcher or retry later |
| `abandoned_prearm` | None by contract | Preserve unarmed record until target revalidation | Retry only after verified no-mutation state |
| `journal_write_failed_prearm` / `backup_unavailable` | None | Preserve exact authenticated generation | No mutation began; retry after storage is safe |
| `journal_write_failed_postarm` / `unexpected_post_arm_failure` | May have occurred | Preserve and advance to `recovery_blocked` when possible | `repair_recovery_pending`; retry recovery only |
| `journal_invalid` / `backup_invalid` | No new repair | Quarantine exact bytes; never auto-clean | Authentication/decrypt/schema failed; use support/Task-086 |
| `recovery_target_unavailable` / `recovery_target_changed` | No new mutation | Preserve | Restore the same target or use support; never guess |
| `staging_security_unavailable` / `environment_path_unsafe` | None | Preserve ambiguous identity if created | The package cannot be mutated safely |
| `environment_changed` / `staging_ambiguous` | Do not overwrite | Preserve | Resolve the unrelated edit/identity through support |
| `certificate_apply_failed` / `certificate_verify_failed` | Roll back if armed | Preserve | Repair did not apply; recovery verifies prior state |
| `environment_replace_indeterminate` | Classify original/candidate/absent/third state | Preserve until classification | Never assume API failure meant no write |
| `runtime_stop_failed` / `runtime_start_failed` | Roll back if armed | Preserve | Restore the exact prior runtime plan |
| `provider_verification_failed` / `readiness_failed` | Roll back if armed | Preserve | Restore local state; report only sanitized probe category |
| `provider_recheck_indeterminate` | Local rollback may be exact | Preserve until the local terminal state is durable | Report external probe uncertainty without claiming provider success |
| `repair_rolled_back` | Original state verified | Delete only after terminal record | Repair failed; prior state was restored |
| `rollback_restore_failed` / `rollback_verification_failed` | Stop bounded retry | Preserve | Recovery remains pending; never claim safe rollback |
| `rollback_restart_failed` / `rollback_readiness_failed` | Restored files retained | Preserve | Runtime needs manual recovery; volumes were not requested for deletion |
| `recovery_cleanup_pending` | Terminal state verified | Retain encrypted remnants | Retry cleanup before another repair |
| `package_integrity_failed` / `build_identity_failed` | Publish nothing | Remove only verified staging identity | Rebuild from the controlled inputs |

`recovery_blocked` is an internal authenticated journal state. Its only public
status is `repair_recovery_pending`; it is never grouped with `journal_invalid`
and never described as rollback success. State sequence and previous-digest
links are monotonic. No failure path moves backward, overwrites an unrelated
generation, or deletes the last authenticated backup.

Public confirmation exposes only the approved fields in Section 1: sanitized
endpoint labels and truncated/tokenized container, image, and config-volume
identities, never their raw or complete values. Errors, logs, and repository
evidence contain no local path, raw/full endpoint or runtime identity,
environment value, key, certificate detail, PEM, raw exception, or raw child
output.

## Implementation Plan

Implementation is deliberately dependency-ordered and split into reviewable
increments. Each increment begins with failing contract/adversarial tests and
keeps mutation disabled until its prerequisite is complete.

1. **Contracts and models**: add immutable identity/plan models, public-summary
   redaction, and failing tests for every reviewer attack/failure scenario.
2. **Runtime resolver**: trusted executable discovery, Authenticode/integrity
   policy, minimal environment, captured Docker named-pipe or rootless Podman
   URI/key endpoint, and directly invoked Compose-provider identity.
3. **Target resolver**: ordered Compose configuration, normalized pre/post
   policy, actual image/container/mount/all-volume binding, candidate binding,
   and target token/confirmation.
4. **Windows trust proof**: Windows-store-only server-auth chain selection and
   negative environment-injected-root tests.
5. **Windows security proof**: handle identity, supported reparse behavior,
   DACL, DPAPI, atomic replacement, and cross-session mutex primitives in
   isolated temporary fixtures.
6. **Recovery manager**: write-ahead journal, encrypted backups, fresh-process
   recovery, strict idempotent rollback, and sanitized UI states.
7. **Transaction refactor**: make `repair.py` consume the immutable target and
   recovery manager; remove `allow_failure` rollback and process-only backup.
8. **Provider installer hardening**: reuse the atomic `.env` primitive and
   remove persistent plaintext backup behavior.
9. **Gate-A source validation and review**: run focused/full tests, exact-head
   workflows, isolated Docker then approved rootless-Podman recovery tests,
   OneDrive and cross-session tests, and independent technical/security
   re-review before source-gate acceptance.
10. **Gate-B artifact integrity**: close the exact Python 3.12 patch/artifact decision,
   validate staged copied bytes, independently verify archives, add the
   hash-locked build driver and provenance v2, and tighten loadable inventory.
11. **Gate-B artifact/preview validation**: verify the rebuilt executable,
    staged directory, archive, sidecar, and commit marker at one exact head; for
    preview acceptance, complete the separate normal-user package/download
    evidence and independent artifact re-review.

Expected source map:

- add `launcher/towerscout_launcher/runtime_identity.py`;
- add a reviewed package-bound runtime/publisher policy and provider integrity
  contract;
- add `launcher/towerscout_launcher/windows_security.py`;
- add `launcher/towerscout_launcher/recovery.py`;
- refactor `models.py`, `discovery.py`, `repair.py`, `coordination.py`, and
  `app.py`;
- harden `scripts/podman-compose-providers.v1.json` and the shared provider
  installer/library without invoking PowerShell from the launcher;
- refactor `launcher/package_validation.py`, `build.cmd`,
  `build_provenance.py`, `inspect_build.py`, and build locks/driver;
- add focused unit/fresh-process/Windows package tests; and
- update only documentation whose actual behavior changes.

## Validation Plan

### Automated source and adversarial tests

- package/CWD/PATH runtime hijack, executable/plugin/provider replacement,
  unsigned/wrong/catalog-signed publisher, timestamp/expiry, revoked/unknown-
  offline status, reviewed rollover, and file-ID changes;
- child timeout and stdout/stderr overflow while streaming, process-tree
  termination, and oversized CA chain/candidate/bundle rejection;
- all ambient Docker/Podman/Compose/CA redirection variables and wrong/remote
  endpoint cases, including a Docker context repointed under the same name and
  a replaced/reordered Docker Compose plugin;
- explicit captured Docker named pipe and rootless Podman URI/identity key,
  including connection-name repointing, key replacement, machine
  `Rootful=false` plus endpoint `Rootless=true`, provider-child endpoint tracing,
  and rejection of this host's ambient root connection;
- rejected provider command-script wrappers, empty/name-version-only catalog
  evidence, forged receipts, and replaced interpreter/module/generated entry
  point;
- Docker/Podman `off`, `on`, `auto` with GPU, and `auto` CPU-fallback paths,
  including CPU-package `on`, missing Podman CDI, and engine-overlay mismatch;
- modified Compose files/env/model after confirmation, extra service, build,
  privileged setting, bind mount, wrong actual image, wrong config mount, or any
  missing/changed engine-specific named-volume field in Docker and Podman inspect
  fixtures;
- injected non-Windows CA, SSL environment injection, wrong-purpose root,
  ambiguous/missing chain, CA-only/partial-chain anchor, unsupported Windows
  chain API, server intermediate absent from Windows `CA`, and proof that only
  the selected eligible Windows `ROOT` enters the container;
- second process/session, second package aimed at the same target, abandoned
  lock, and distinct endpoint/project behavior;
- launcher and provider crashes with each protocol pending in turn, proving that
  both scan the common state root under the shared `.env` mutex and neither can
  begin mutation until the other protocol reaches a safe terminal state;
- root/package/file swaps, symlink/junction/hard-link leaf attacks, permissive
  ACL, stable OneDrive/cloud path, and identity churn;
- abrupt fresh-process termination after every journal, certificate, `.env`,
  Compose, verification, commit, and rollback boundary;
- abrupt termination at every rollback certificate and `.env` temp planned,
  created, and verified boundary, including ambiguous orphan classification;
- every restore nonzero/timeout/wrong-byte/absence/readiness failure, ensuring
  backup retention and all eight volume identities;
- original-container deletion followed by successful exact prior-profile
  recreation, plus recreation failure that retains protected recovery without
  creating an ad hoc volume helper;
- stage-specific identity after stop-before-up and after legitimate new-
  container creation, rejecting every other container/image/mount drift;
- Docker and Podman removal or replacement of one bound volume after the last
  pre-restart inspection, proving the transaction cannot report success or a
  completed rollback and retains protected recovery state;
- generic non-`RepairError` after mutation, proving the UI reports recovery
  truth rather than "failed safely";
- staged-copy tampering of launcher/base, final-destination mutation, sidecar/
  commit-marker mismatch, unsafe/duplicate/Unicode-normalization/Windows-case-
  colliding ZIP members, and crash-left uncommitted-set recovery, with no
  consumable partial output;
- substituted interpreter/wheel/loadable inventory and provenance-v2 mismatch;
  and
- provider `.env` Unicode/CRLF/secret preservation, exact one-setting change,
  authenticated-template absent-file creation and restoration to absence,
  duplicate/concurrent-file rejection, process termination at temp plan/create/
  write/flush/replace/final verification, exact orphan reconciliation,
  replacement/restore faults, no backup/temp residue after reconciliation, and
  no sensitive output.

Fault hooks exist only as constructor-injected test adapters; no packaged
environment variable, CLI flag, or hidden runtime switch may enable them.

### Non-regression contracts

- no listener, browser-issued operation, helper import, launcher-issued
  PowerShell/cmd/shell, execution-policy change, administrator requirement,
  Windows-store mutation, runtime-default/machine-mode change, or socket mount;
- the separately invoked existing PowerShell provider installer is hardened and
  tested without adding any launcher invocation of it;
- no command includes `down -v`, `--volumes`, volume removal, or user-provided
  arguments;
- Task-086 remains present, independent, and usable; and
- validation artifacts remain nonpublishable while preview/Task-100 identities
  remain distinct.

### Local and CI gates

- focused launcher, package, provider-installer, runtime-hardening, Task-098/101,
  and agent-work tests;
- broad unit suite using repository Python 3.12, with the Defender-blocked
  PowerShell host-helper subset left to its existing authoritative Windows CI
  job and no local bypass;
- a Windows launcher-build job using the exact approved Python 3.12 patch/
  artifact and hash-lock contract, build inspection, provenance-v2 verification,
  staged-directory/archive verification, and secret scan;
- exact-head CI/CD and all three Task-087 jobs;
- isolated Docker CPU mutation/crash/recovery before Podman;
- approved rootless Podman CPU mutation/crash/recovery using the explicitly
  bound connection and approved provider;
- non-mutating real-provider normalized-model and endpoint checks for both GPU
  overlays; live GPU/CDI mutation and recovery remain Task-097 scope rather than
  a Gate-A claim;
- actual OneDrive-synchronized package and two-session Windows lock proof;
- all eight engine-specific volume identities before/after every live failure
  injection; and
- quick/canonical `.agent_work` validators plus `git diff --check`.

Docker Desktop and Podman are currently available, but no runtime mutation is
authorized by this design checkpoint. Live validation requires a separately
stated isolated target/scope/recovery check after implementation approval.

## Gate Exit Criteria

### Gate A - PR #67 source re-review and merge eligibility

- Findings 1-8 and Finding 11 have implemented contracts and adversarial tests.
- Exact target is resolved before confirmation and revalidated at mutation and
  restart.
- Durable fresh-process rollback is verified; no failed restore deletes its
  backup or overclaims safety.
- Windows-store-only CA selection, explicit local Docker/rootless-Podman target,
  all-volume preservation, and non-regression boundaries pass.
- Required exact-head workflows pass and the independent reviewer rechecks the
  corrected source.

Passing Gate A does not by itself authorize merge; PR #67 stays Draft until the
remaining project review and release decision is explicit.

### Gate B - new validation artifact or unsigned preview

- Finding 9 and the preview portion of Finding 10 pass on staged copied bytes,
  the exact archive, and the explicitly approved exact-patch/hash-locked Python
  3.12 build.
- The exact packaged provider installer repeats Finding 11's no-backup,
  crash-reconciliation, no-temp-residue, and no-sensitive-output tests.
- For preview acceptance, a new normal-user package is assembled through the
  release path; no existing `Task-087-validation-*` artifact is renamed or
  reused.
- For preview acceptance, package/integrity/docs and actual approved clean
  unmanaged Windows download gates under ADR-019 pass.

### Gate C - Task-100 signed candidate

- Organization-controlled rebuild, approved signing/timestamping, signed-file
  boundary, post-sign inventory/checksums, extracted signature verification,
  representative managed-endpoint qualification, and `v0.1.3-rc.N` remain
  wholly under Task-100 after the satisfactory-package decision.

## Approval Boundary

This checkpoint completed ANALYZE/DESIGN after its governance and static
validation passed. Per the repository's specification-driven workflow, the
project lead explicitly approved moving Task-087 into IMPLEMENT for this
remediation plan on August 21, 2026. That approval starts Gate A source work
only; it does not authorize live runtime mutation, Gate B artifact/preview work,
PR merge, publication, or Task-100 signing.
