# Revised PR 117 adoption review evidence

Source: `076183879ef7a249230ac79b55887bd0f11a11c8`. Tree: `a58cbf71a870e252b287a2f018fdf1de99dca2c3`. Sole parent: `87ca90089473e1855f98968f75a17b5f8d0dd1cd`.

This evidence-only branch must not be merged into adoption source or main.
[Download the sealed review packet](task106-pr117-final-corrected-review-packet.zip),
[verify its checksum](task106-pr117-final-corrected-review-packet.zip.sha256), and read the
[second-pass closure](packet/SECOND-PASS-CLOSURE.md) and
[reproduction instructions](packet/REPRODUCTION.md).

The sealed packet is the unchanged prepublication checkpoint. Its local-only
wording describes that checkpoint. The user subsequently authorized updating
J-Schulein/TowerScout#117 for independent review. The live PR uses immutable
links to these bytes and identifies the intended cdcai proposal.

Both additional restore-mapping and training-label-selection findings are
corrected. Windows: 886 passed / 74 skipped. Linux: 805 passed / 155 skipped.
All 36 new cases passed on both platforms. Earlier frontend/dependency/trust
results are explicitly distinguished with unchanged-input evidence.

The grant/supporting-code/docs scope and historical Team acknowledgment are
settled. Independent acceptance and updated-head remote CI remain pending at
publication. Source checks do not establish final artifact/deployment readiness.
Prior source `dad6f4c709d41c6fa696e1c09de3e6cf0c5a2717`, prior evidence `e7dad5c26499c4b6922a48a4ce6e1a68d10232dd`, sealed packets and
deferrals remain preserved. No cdcai PR, merge, release or settings change is
part of this update; the cdcai About correction remains unexecuted.
