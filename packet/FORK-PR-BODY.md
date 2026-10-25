Prepared R2 revision of J-Schulein/TowerScout#117 for adoption review.
The intended cdcai description below is identical; no public update is executed.

---

## Proposal

Adopt the curated TowerScout application, Windows Docker/Podman CPU/CUDA runtime,
release controls and maintenance guidance into cdcai. This revision incorporates
the bounded corrections investigated after J-Schulein/TowerScout#117. The
application grant, historical website removal, approved security exceptions and
existing architectural deferrals remain settled, except the demonstrated XML
scale/inversion defect corrected in this pass. Project-controlled supporting
code and documentation are covered by the confirmed AGPL-3.0-only scope; the
historical TowerScout Team acknowledgment is retained. Third-party, model, data
and provider terms remain separate.

The endpoint-protection-blocked listener/worker scripts and their PowerShell
suite are removed from the candidate. Disabled compatibility hooks are retained. Manual repair/launch/stop and safe stale-session
cleanup remain. The required **Windows host-helper contracts** name is preserved
for receiving-policy compatibility; it runs supported package/provider/runtime
checks. The simulated browser controller tests do not execute the removed helper.
The deferred launcher redesign is not resumed.

## Exact source and provenance

| Item | Identity |
| --- | --- |
| Receiving base / sole parent | `87ca90089473e1855f98968f75a17b5f8d0dd1cd` |
| Proposed head | `77cb258a03f2abf74054346b2e3964b2d907615b` |
| Proposed tree | `e5688fb8f9927dc2e8d52ebe3b109e270cc80cb3` |
| Previous J-Schulein/TowerScout#117 head | `076183879ef7a249230ac79b55887bd0f11a11c8` |
| Historical J-Schulein/TowerScout#116 head | `52182f0ea12f2951e91413725058b764b70e828f` |
| Historical cdcai/TowerScout#4 source provenance | `724e619fcca6535d09f83dc1d897b41f2e230ae3` |
| Files | 410 |
| Delta from PR 117 | 11 paths: 1 added, 10 modified, no deletions |

One adoption commit sits on the receiving base. It is derived from the historical
cdcai/TowerScout#4 head with later corrections; it is not byte-identical to that
head or already accepted. Private planning and old development ancestry are
excluded. The source/history guard and both author/committer identity checks pass.
Prepared and internally checked; independent acceptance is pending. This revised
source and evidence are prepared locally; the published fork still has the
previous head. Public update, receiving adoption and merge remain pending.

Review [source identity](candidate-identity.json), [all file hashes](candidate-source-manifest.json),
[source ZIP](candidate-source.zip), [review delta](diff-reviewed-checkpoint.patch),
[base delta](diff-receiving-base.txt), [per-case results](test-results.json),
[reproduction](REPRODUCTION.md), [claim reconciliation](PACKET-CORRECTIONS.md),
[source/dependency limits](DEPENDENCY-EVIDENCE.md) and [historical trust proof](TRUST-EVIDENCE.md).
[SHA256SUMS.txt](SHA256SUMS.txt) covers the packet.
The sealed R2 packet and its external checksum preserve this local checkpoint.
On an authorized upload, replace relative packet links with immutable evidence
commit links and verify their bytes. Preserve both earlier evidence commits
`7b532db985a310173615f5d4ca88e4c37868b70c` and
`e7dad5c26499c4b6922a48a4ce6e1a68d10232dd`, their refs and sealed packets;
arrange a checksum-verified receiving-held copy before handoff. Repository
archival alone does not invalidate commit URLs, but deletion/privacy changes
or lost custody can make them inaccessible.

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

The [historical closure record](SECOND-PASS-CLOSURE.md) preserves the prior
implementation evidence. Those earlier corrections remain credited:

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
  R2 closes only XML scale/inversion; other export/concurrency deferrals remain.

## R2 corrective pass and validation

The [R2 closure](R2-CORRECTION-CLOSURE.md) records the latest repairs and limits:

- Accept real-writer multi-generation archives and old duplicate READMEs without
  relaxing path, collision, metadata or expansion protections.
- Generate XML from actual image dimensions, including historical flipped flags
  and rectangular images; decode the writer's stored flag consistently.
- Preserve Azure's final unconfirmed-boundary warning; add narrow behavior tests
  for provider/list/escaping, actual indices, collisions and extraction ordering.
- **32 new Python cases pass on both platforms.** Maintained Windows Python
  3.12.10: **918 passed, 74 skipped**. Linux Python 3.11.17:
  **837 passed, 155 skipped**. No failures/errors.
- Blocking lint, pip checks, six Node contracts, parsed CSV/KML serialization,
  exact bundle reconstruction, fresh npm installation/audit (zero findings),
  CommonJS load, Docker frontend stage and five synthetic Edge browser checks pass.

Python environments are preserved, inventoried test environments, not new final
production images. Browser checks use local synthetic fixtures, not authenticated
providers or real models. Historical scoped Docker/Podman trust rehearsals are
carried with unchanged-input hashes in [evidence reuse](EVIDENCE-REUSE.json).

All nine remote checks completed successfully on the **previous** published head
`076183879ef7a249230ac79b55887bd0f11a11c8`: [CI pipeline](https://github.com/J-Schulein/TowerScout/actions/runs/40232515449)
and [frontend/Windows contracts](https://github.com/J-Schulein/TowerScout/actions/runs/40232528550).
Both Linux Python versions had 795 unit + 10 required integration passes and
155 skips. Black/mypy/Bandit returned 1 under the existing advisory configuration;
their status is distinct from required checks. [Historical CI](HISTORICAL-CI.json)
also records the prior CPU build; none of these runs credits the new head.

## Remaining gates and preserved decisions

Independent acceptance and all nine **new-head** remote checks remain pending.
The prepared fork/cdcai body is identical after the fork wrapper. Public upload,
PR update and test-only dispatch require applicable authorization; then check
the exact new SHA and perform the short delta review before separately authorized
cdcai opening. Receiving proposed-merge CI and review policy remain merge gates.
Local success does not imply release qualification or permission to publish.
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
Repeated restored-manual duplication, shared ZIP output, cross-tab mutation
races, noncontiguous-ID imagery-credit lookup and native Windows TIFF cleanup remain explicit
scoped follow-ups; do not claim lossless backup or universal cleanup. Use one
active upload/review/export at a time and retain original archives.
