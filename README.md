# PR 117 R2 adoption review evidence

Source `77cb258a03f2abf74054346b2e3964b2d907615b`, tree `e5688fb8f9927dc2e8d52ebe3b109e270cc80cb3`, sole parent `87ca90089473e1855f98968f75a17b5f8d0dd1cd`.
This evidence-only branch must not be merged into adoption source or main.

[Sealed packet](task106-pr117-r2-corrected-review-packet.zip) and [checksum](task106-pr117-r2-corrected-review-packet.zip.sha256).
[R2 closure](packet/R2-CORRECTION-CLOSURE.md),
[exact 11-file delta](packet/diff-reviewed-checkpoint.patch),
[per-case results](packet/test-results.json) and
[reproduction](packet/REPRODUCTION.md).

README round trips, actual image/XML dimensions and final Azure warning are
corrected. Windows: 918 passed / 74 skipped. Linux: 837 passed / 155 skipped.
All 32 added cases and 36 earlier correction cases pass on both platforms.
Fresh npm/audit/frontend/browser checks pass; historical trust and dependency
receipts retain their original scope. New-head remote CI is pending at this
publication checkpoint; the live PR records subsequent completed results.

The packet is the unchanged sealed local checkpoint. Local-only/pending wording
describes its preparation time, before the user authorized this PR update.
The live PR uses immutable links to these exact bytes and the intended cdcai body.
Prior source `076183879ef7a249230ac79b55887bd0f11a11c8`, prior evidence `7b532db985a310173615f5d4ca88e4c37868b70c`, all earlier packets and
settled grants/security decisions remain preserved. Only the XML scale/inversion
deferral is closed; other deferrals remain. Independent acceptance is pending.
No cdcai PR, merge, release or settings change is part of this update.
The cdcai About correction remains unexecuted.
