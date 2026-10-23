This is the proposed local revision for independent review in PR 116. The shared description below is identical to the intended cdcai body. Neither this revision nor this packet has been uploaded. Do not merge the rehearsal into fork main; independent acceptance and separate destination authorization remain required.

---

## Proposal

Adopt the curated TowerScout application, Windows Docker/Podman CPU/CUDA runtime,
release controls and maintenance material into cdcai. This revision corrects
PR 116's certificate rejection, dependency/Host contracts, dataset restore/export,
upload ownership, logging and notice findings. The flagged deferred host-helper
scripts and their PowerShell suite/self-test are removed from the proposed source
and active CI. Supported manual repair, launch, stop and stale-session cleanup
remain. Earlier checkpoints preserve the removed implementation.

The historical presentation website remains removed. The approved additional
application grant and exact security exceptions remain settled. The remaining
rights and historical advisor-credit decisions are separately identified below.
This source proposal does not resume the deferred launcher redesign or establish
deployment readiness.

## Exact source

| Item | Identity |
| --- | --- |
| Receiving base and sole parent | `87ca90089473e1855f98968f75a17b5f8d0dd1cd` |
| Proposed head | `dad6f4c709d41c6fa696e1c09de3e6cf0c5a2717` |
| Proposed tree | `01f286393936d58f563db0ff1195fecf17c2770c` |
| Previous PR 116 review checkpoint | `52182f0ea12f2951e91413725058b764b70e828f` |
| Source provenance | `724e619fcca6535d09f83dc1d897b41f2e230ae3` |
| Candidate files | 406 |
| Delta from receiving base | 505 paths (362 added, 33 modified, 110 deleted; renames counted as add/delete) |
| Delta from previous review | 61 paths (10 added, 46 modified, 5 deleted; renames counted as add/delete) |
| Delta from incoming source provenance | 702 paths (35 added, 130 modified, 537 deleted; renames counted as add/delete) |

There is one new adoption commit over the receiving base. Private planning and
development-fork ancestry are excluded. Both author and committer use the
approved commit-only GitHub noreply identity. The local history guard passes.
The revision and packet are prepared locally; they have not been uploaded.

Review the complete source and changed-path indexes in the checksummed packet:
[source identity](candidate-identity.json), [source manifest](candidate-source-manifest.json),
[source archive](candidate-source.zip), [review delta](diff-reviewed-checkpoint.txt),
[receiving-base delta](diff-receiving-base.txt), [reproduction and limits](REPRODUCTION.md),
[test results](test-results.json), [trust evidence](TRUST-EVIDENCE.md) and
[historical dependency inventories](DEPENDENCY-EVIDENCE.md).
The packet's `SHA256SUMS.txt` covers these files and the proposed description.
Preserve those bytes in durable authorized evidence storage when publishing;
mutable PR comments alone are not the evidence archive.

## Material changes and review focus

| Surface | Result and limitation |
| --- | --- |
| Certificate policy | Correct both truncated SPKI hashes; enforce 64-digit lowercase unique hashes; test four real affected intermediate/cross-signed certificates. Reject before import promotion or provider requests. Secure pip bootstrap, system/application CA pins and existing persistent-bundle recovery remain part of the adoption. |
| Dependencies and HTTP | Pin Werkzeug 3.1.9 and cachelib 0.17.0. Support localhost/IPv4 loopback; reject IPv6 literal hosts, hostile Host/Origin and same-site/cross-site browser requests. `/abort` is POST-only. These checks are neither authentication nor an XSS defense. Preserve the negative CUDA-tag fixture via a narrow scanner exception. |
| Dataset restore | Validate JSON shape, references and numeric/boolean/text fields; budget the ZIP directory before allocation and retain expansion limits. Escape rendered metadata and protect CSV flag/text fields. Failed restore retains server and browser review/export state; successful restore replaces tiles and detections. |
| Training export | Full tiles retain all selected above-threshold annotations, including outside-boundary detections. Unchecked/below-threshold annotations remain omitted; unlabeled tiles are not verified negatives. KML keeps its view-filtered contract. Manual boundary flags use rectangle intersection. No inference threshold or model bytes change. |
| Upload lifecycle and logging | Generated per-session image names prevent collisions and cross-session reads/deletes. Replacement deletes only the owner's previous image; failures delete only their new file. Reload and startup preserve inputs; abandoned-session files need deliberate owner retention/cleanup. Remove the active caller to the removed deletion route, Azure key logging and query-bearing 404 logs. |
| Trust import | Validate untrusted input in temporary container storage before durable placement; remove only owned failed staging/candidates. Preserve approved active trust and recovery backups. |
| Cancellation and documentation | Intentional abort bypasses network-error notification through the real wrapper. Packaged compatibility HTML uses working relative offline links. Support/CI guidance is release-neutral. |
| Source notices | Restore SyntheticData's full upstream MIT notice and adapted/vendored YOLO credits/modification notices; clarify THOP/certifi obligations and dataset/provider terms. Remove the unsupported blanket Apache assertion. The explicit 66-path application grant is unchanged; no completeness claim is made for unresolved rights or final-image source delivery. |
| Build and publication | Retain pinned Node/base inputs, generated immutable-source notices, weekly CI and scoped security-events permission. Serialize publishing repository-wide, pass registry tokens through environment/stdin, and record verify-policy identity and authority limits. Actual receiving settings and exact-digest stable promotion remain separate gates. |

The Windows job keeps its historical **Windows host-helper contracts** check
name for receiving required-check compatibility; its steps now exercise only
supported package/provider/runtime behavior. No repository setting was changed.

The 396-key baseline is unchanged. Four exact older residuals expire January 31,
2027 at 23:59:59 UTC; the separate eight-record util-linux exception expires
November 5, 2026 at 23:59:59 UTC. Resolved Expat is removed. These are bounded
acceptances, not fixes or permission to publish. The project owner and TASK-107
retain weekly/immediate-change review; expired, unused or unknown identities fail
closed. Publication expiry does not disable installed software.

## Validation

- **Windows: 838 passed, 74 skipped, zero failures/errors** in the maintained unit plus required adoption-integration selection.
- **Linux: 757 passed, 155 skipped, zero failures/errors** in the maintained unit plus required adoption-integration selection.
- Windows blocking lint, pip consistency, five Node contracts, parsed CSV/KML serialization and bundle/source agreement pass. The history guard passes.

The Windows run uses a fresh Python 3.12 environment with verified pip bootstrap
and fresh requirements installation. The Linux run uses an isolated test image
derived from a preserved CPU image with the selected dependency updates, Git,
Node and development tools; it is not a fresh final Linux production build.
Full inventories and per-case statuses are supplied. Results from different
checkpoints are not added together.

Docker and rootless Podman trust rehearsals pass for the corrected trust/import
files over preserved CPU images: four affected intermediates rejected before
durable storage, private-material rejection, negative TLS chain controls,
approved trust refresh/recreate and eight retained-volume sentinels. These are
scoped recovery proofs. Podman ran alongside existing Docker installations, so
it does not establish the separate supported Podman qualification profile.
Credential-free transport checks do not establish account/provider feature
workflows. New final images and all accepted host/device profiles remain pending.

The earlier 141-pass result describes the older head and developer environment
(Werkzeug 3.1.8/cachelib 0.15.4), not fresh dependency resolution. The initial
Windows sweep in this correction round exposed one obsolete test assertion and
19 blocked deferred-helper executions. The assertion is corrected; the helper
implementation/suite is now removed at the user's direction. That evidence is
preserved, not relabeled as a pass or solved by weakening endpoint protection.

## Remaining decisions and gates

1. Independent review must accept this exact head/tree and packet. Resolve the
   rights/provenance scope for project-controlled scripts/tests/docs outside the
   explicit application grant and the historical advisor-credit/privacy
   disposition. These do not reopen the approved application grant, model/data
   authority or website removal. Retained team/upstream credits are not a claim
   that every attribution question is settled.
2. Recheck receiving main and actual proposed-merge CI before adoption. All nine
   required destination check identities and receiving review/conversation
   policy remain applicable. Local/fork checks do not certify receiving settings.
   Environment protection, administrator bypass, package-write and review
   controls still need owner verification.
3. Complete dependency/native source, patches, recursive inputs, build/relink
   instructions, notices, durable SBOM/source access and final-version
   reconciliation. The 379 staged source files and 769 preserved native rows
   are preparation, not complete public corresponding-source delivery.
4. Qualify the actual Python 3.12/PowerShell 5.1 installation at the documented
   80-character package-root limit; verified-provider reuse/offline retry and
   relevant GPU toolkit/connection targeting cases remain targeted checks.
   An ordinary shorter-path environment is not that proof.
5. Build and scan exact final CPU/CUDA artifacts, obtain separate authorization
   for non-Latest validation publication, verify authoritative published hashes
   against exact browser downloads, and execute the accepted two-NVIDIA-host,
   four-profile matrix with real models/providers/persistence/recovery. Mocked
   models and health endpoints do not establish deployment readiness.
6. Before stable/Latest promotion, prepare and review promotion of the same
   qualified immutable digest. A fresh build from the same source is insufficient.
   Merge, dispatch, public updates, PR 4 supersession, settings and publication
   each retain their explicit authorization boundaries. About remains unexecuted.

The unsigned package supports environments permitting the documented
process-scoped wrappers. Signature-enforcing endpoints, CPU-only hardware,
Podman without Docker installed and rootful Podman remain unqualified.
Non-root/volume migration, broad dependency locking, baseline redesign,
geocoding/cache architecture, general executable discovery and legacy export
cleanup retain their deferrals. Review against the supported manual runtime,
not the removed helper implementation.

## Maintenance and rollback

The receiving maintainer owns documented advisory monitoring, expiring-policy
reviews, source/notice access, verified backups and future qualification. User
guides, release notes, support reporting and maintenance guidance travel with the
source. Preserve historical pilot evidence as historical; it does not certify
this candidate. Before merge the proposal can be revised or withdrawn. After
authorized deployment, use verified compatible artifacts and volume-preserving
recovery; do not recommend an older trust-affected image merely because it ran.
Owner handoff, private evidence custody and final acceptance remain incomplete.
