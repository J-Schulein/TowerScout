# R2 correction closure — October 25, 2026

Prepared local head `77cb258a03f2abf74054346b2e3964b2d907615b`, tree `e5688fb8f9927dc2e8d52ebe3b109e270cc80cb3`, one commit on
`87ca90089473e1855f98968f75a17b5f8d0dd1cd`. The prior published head `076183879ef7a249230ac79b55887bd0f11a11c8`,
its sealed packet and all intermediate checkpoints remain preserved.
Eleven paths change (one added, ten modified); the other 399 source files match.

| Finding | Correction and acceptance |
| --- | --- |
| 2.1 README round trip | Writer emits one canonical README. Restore ignores only the known root and old empty/README copies after all-name and expansion-budget validation. Actual writer exports survive repeated restores; other flattened collisions and traversal still fail without replacing prior state. |
| 3.5 XML dimensions | Read the actual image width/height for XML and both coordinate axes. Decode the writer's inverse metadata flag on restore. Three generations, both flags, id-less legacy layouts, historical flipped flags and duplicate READMEs, rectangular images, JPEG/PNG/TIFF-under-.jpg and manual boxes pass. Image bytes and normalized YOLO labels remain unchanged. |
| 4.5 Azure warning | Final successful Azure addition retains an eight-second warning when membership is unconfirmed; confirmed additions retain success. Real Google/Azure methods and real ErrorHandler with a small DOM/timer harness verify the final message, severity and stored membership. |
| 3.1 behavioral gaps | Guard manual list/address visibility, quote escaping, booleans/floats aliasing both existing label indices, adapted collisions/state preservation and metadata rejection before ZIP member reads. Ignored README alone exceeds each configured archive budget in targeted tests. Existing KML double-escaping serialization coverage remains. |
| 2.2 validation wording | Old head's nine completed remote checks are recorded in HISTORICAL-CI.json. New head has fresh local Windows/Linux/Node/browser/npm/frontend results, with new-head remote and receiving proposed-merge checks explicitly pending. |

All **32 added Python cases** pass on both platforms. Maintained selection:
Windows Python 3.12.10 **918 passed / 74 skipped**;
Linux Python 3.11.17 **837 passed / 155 skipped**.
Six Node contracts, parsed CSV/KML serialization, blocking lint, pip checks,
bundle reconstruction, fresh npm installation/audit/CommonJS, Docker frontend
and all five synthetic browser contracts pass. Supplemental global/debug
contracts and focused documentation checks pass. Deliberately removing manual
list visibility or quote escaping now fails the new assertions; the unchanged
candidate passes. Those mutation edits were confined to a disposable clone and
restored byte-for-byte (review-guard-results.json). Per-case statuses and environment
inventories are included. Models and authenticated provider workflows are not
exercised by these tests; skips are preserved and explained per case.

The pre-fix focused suite produced 21 expected failures and 11 passes on the
published source, plus the expected final Azure warning failure. These are
counterexamples, not 21 independent defects. The initial fixed selection had
200 passes; archive-budget assertions were strengthened afterward and all final
32 cases passed in the complete frozen-head runs. Raw baseline/fixed/final logs
and exact runner scripts remain private; they are not combined into final totals.

Only the demonstrated XML inversion/scale deferral is closed. Repeated manual
append, shared ZIP output, cross-tab concurrency, native Windows TIFF cleanup,
noncontiguous-ID imagery-credit lookup and broad architectural deferrals remain.
No universal/lossless backup, arbitrary archive repair or live-provider readiness
is claimed. The settled grant, historical Team acknowledgment, website removal,
396-key baseline and exact security exceptions remain unchanged. Unconfirmed
historical credential coverage is a separate owner follow-up. About remains
unexecuted. No public update, dispatch, cdcai PR, settings change or release was
performed. Independent acceptance and new-head remote checks remain outstanding.
