## Proposal

Adopt the curated TowerScout application, Windows Docker/Podman CPU/CUDA runtime,
release controls and maintenance guidance into cdcai. This revision incorporates
the bounded corrections investigated after J-Schulein/TowerScout#117. The
application grant, historical website removal, approved security exceptions and
existing architectural deferrals remain settled. Project-controlled supporting
code and documentation are covered by the confirmed AGPL-3.0-only scope; the
historical TowerScout Team acknowledgment is retained. Third-party, model, data
and provider terms remain separate.

The endpoint-protection-blocked host-helper scripts and their PowerShell suite
are removed from the candidate. Manual repair/launch/stop and safe stale-session
cleanup remain. The required **Windows host-helper contracts** name is preserved
for receiving-policy compatibility; it runs supported package/provider/runtime
checks. The simulated browser controller tests do not execute the removed helper.
The deferred launcher redesign is not resumed.

## Exact source and provenance

| Item | Identity |
| --- | --- |
| Receiving base / sole parent | `87ca90089473e1855f98968f75a17b5f8d0dd1cd` |
| Proposed head | `076183879ef7a249230ac79b55887bd0f11a11c8` |
| Proposed tree | `a58cbf71a870e252b287a2f018fdf1de99dca2c3` |
| Previous J-Schulein/TowerScout#117 head | `dad6f4c709d41c6fa696e1c09de3e6cf0c5a2717` |
| Historical J-Schulein/TowerScout#116 head | `52182f0ea12f2951e91413725058b764b70e828f` |
| Historical cdcai/TowerScout#4 source provenance | `724e619fcca6535d09f83dc1d897b41f2e230ae3` |
| Files | 409 |
| Delta from PR 117 | 65 paths: 3 added, 62 modified, no deletions |

One adoption commit sits on the receiving base. It is derived from the historical
cdcai/TowerScout#4 head with later corrections; it is not byte-identical to that
head or already accepted. Private planning and old development ancestry are
excluded. The source/history guard and both author/committer identity checks pass.
Prepared and internally checked; independent acceptance is pending. This new
revision/packet is local and has not been uploaded.

Review [source identity](candidate-identity.json), [all file hashes](candidate-source-manifest.json),
[source ZIP](candidate-source.zip), [review delta](diff-reviewed-checkpoint.patch),
[base delta](diff-receiving-base.txt), [per-case results](test-results.json),
[reproduction](REPRODUCTION.md), [claim reconciliation](PACKET-CORRECTIONS.md),
[source/dependency limits](DEPENDENCY-EVIDENCE.md) and [historical trust proof](TRUST-EVIDENCE.md).
`SHA256SUMS.txt` covers the packet. Preserve the prior commit-addressed fork
evidence at `e7dad5c26499c4b6922a48a4ce6e1a68d10232dd`, its evidence ref and sealed
packet; arrange a checksum-verified receiving-held copy before handoff.
Repository archival alone does not invalidate commit URLs, but deletion/privacy
changes or lost custody can make them inaccessible.

## Corrections and limits

- **Dependency/CI:** Puppeteer 25.16.0 and the matching lock graph resolve the
  reported development dependency audit failure. Zod is 4.6.7; ws is 8.22.0.
  Blocking audit and all nine check identities are retained. Existing
  Werkzeug/cachelib/Host corrections remain credited; localhost/IPv4 and browser
  origin controls are not authentication or an XSS defense.
- **Restore:** reject ZIP64 before ZipFile allocation; bound UTF-8 metadata to
  8 MiB alongside 1,000 members / 64 MiB per member / 512 MiB expanded total;
  reject duplicate adapted paths; project known fields, normalize annotations
  and redact provider credential queries before response, session or re-export.
  The known cdcai layout with contiguous ordered tiles and leading id-less tile
  pseudo-results is adapted. Mixed/ambiguous layouts are rejected. Failure
  preserves existing review inputs; success discards its consumed ZIP. Same-file
  retry and string-valued actionable errors are covered.
- **Manual review/exports:** use the completed run's boundary snapshot despite
  later drawing edits. Selected manual towers stay visible and KML-eligible in
  either mode without changing their stored membership flag. Restored datasets
  lack polygons: new manual membership is warned as unconfirmed/false. ML KML
  export uses stored membership in Find mode and all selected above-threshold
  results in Label mode. It does not intersect the current viewport. Full-tile
  training export retains selected above-threshold outside labels and warns
  about hidden selected ML annotations. Label mode resets the slider; guidance
  says to restore the desired threshold. KML descriptions escape both XML and
  viewer HTML contexts; CSV retains factual flags and formula protection.
- **Upload/privacy:** reject missing/invalid session image URL headers and
  malformed results before replacing the displayed image; show retry guidance.
  The public issue form requests public fixtures and minimal sanitized details,
  not private locations or raw log tails. No private reporting service is
  promised. Owned cleanup is not claimed crash-proof; abandoned uploads/reset
  residue and backup-aware cleanup are documented. TLS interruption may leave
  unvalidated input in temporary storage; durable promotion still validates.
- **Notices:** add dated notices for all twelve modified vendored YOLO runtime
  files, complete the integration-change inventory, attribute adapted defaults,
  restore the dataset paper citation, and cover all 67 application source paths.
  The approved supporting-code/documentation scope is explicit. Final-image
  native/Python/CUDA source, notices and relink inputs remain distribution gates.
- **Documentation/handoff:** correct stale helper, historical release/wiki,
  retention and all fourteen packet claims. The receiving-accessible maintainer
  register records owner roles, review cadence, triggers and hard expiries.
  Named receiving custodians and evidence handoff remain to be established.

## Second-pass corrections

The [closure record](SECOND-PASS-CLOSURE.md) and [exact local-review delta](diff-second-pass.patch)
address the additional review findings without reopening settled decisions:

- Restore requires extracted, regular tile images and distinct image/label/XML
  destinations before any session replacement. Reserved metadata and missing,
  duplicated or conflicting targets are rejected while preserving prior inputs.
  Existing JPEG/PNG/TIFF signature/structure and byte/pixel limits apply. Legacy
  provider files containing PNG/TIFF under .jpg names remain valid and unchanged.
- YOLO/XML training labels use stable tile/detection references. Equal label
  text does not select another detection, and empty/manual-only ML selections
  agree with contents.txt. Full-tile outside-boundary policy is unchanged.
- Thirty-six new cases cover failures, legacy/current archives, real ZIP
  contents, re-restore, manual selection and image compatibility/resource limits.
  The legacy export/concurrency deferrals remain explicit and unchanged.

## Validation

- Windows Python 3.12.10: **886 passed, 74 skipped**; no failures/errors.
- Linux Python 3.11.17: **805 passed, 155 skipped**; no failures/errors.
- Maintained unit plus required integration selection, blocking lint, pip check,
  six Node contracts, parsed CSV/KML serialization and byte-matched bundle pass.
- Earlier npm ci/audit/CommonJS, Docker frontend and five synthetic Puppeteer
  controller results are carried forward with unchanged-input hashes in
  [evidence reuse](EVIDENCE-REUSE.json); they were not rerun for this backend
  correction. Their original head identities remain visible. The registry audit
  must be repeated on authorized CI/upload. Historical browser tests used Edge
  on Windows, not the receiving Linux runner.

Python environments are preserved test environments, fully inventoried, not new
final production images. Linux Python 3.12, all nine exact-head remote checks,
full final CPU/CUDA builds/Trivy and real provider/model qualification are still
pending. Earlier failed assertion/mock/packaged-link runs are preserved privately;
their results are not relabeled or added to final totals. Prior scoped Docker/
Podman trust rehearsals are carried forward with byte-identity evidence; they
do not qualify the final artifact or a separate Podman-only deployment.

## Remaining gates and preserved decisions

Independent acceptance of this exact source/packet and separately authorized
fork CI come next; then the authorized cdcai proposal, actual receiving proposed-
merge checks and review policy. No remote action is implied by this packet.
The cdcai About description/homepage correction remains unexecuted. Historical
cdcai/TowerScout#4 is preserved pending separately authorized supersession.

The 396-key baseline is unchanged. Four renewed exact residuals expire
2027-01-31T23:59:59Z; eight separately approved util-linux records expire
2026-11-05T23:59:59Z. Weekly/immediate-fix, identity and exposure review remains
mandatory; new, unused and expired findings fail closed. No automatic extension
or publication permission follows from the existing acceptance. Reported
credential rotation/revocation remains credited; unrelated third-party coverage
is unconfirmed. No old credentials were tested or history purged.

Before artifact distribution: reconcile final-version recursive corresponding
source, patches/build/relink inputs, license payloads and durable SBOM/source
access; verify receiving environment/admin/package-write controls; build/scan
exact CPU/CUDA artifacts; obtain non-Latest publication approval; verify exact
browser-downloaded bytes/hashes and complete both NVIDIA Windows hosts' four
engine/device profiles with real models/providers/persistence/recovery.
Qualify the 80-character Podman path and provider reuse/offline/GPU targeting
cases. Stable/Latest promotion must use the same qualified digest and separate
approval. Source tests and health checks are not deployment qualification.

The unsigned wrapper support boundary remains unchanged. CPU-only hosts,
Podman without Docker installed, rootful Podman and signature-enforcing endpoints
remain unqualified. Non-root/volume migration, broad locking, baseline redesign,
geocoding/cache architecture and general executable discovery remain deferred.
Legacy metadata-flag inversion, repeated restored-manual duplication, shared ZIP
output, cross-tab mutation races and native Windows TIFF cleanup remain explicit
scoped follow-ups; do not claim lossless backup or universal cleanup. Use one
active upload/review/export at a time and retain original archives.
