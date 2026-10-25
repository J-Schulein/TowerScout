# Second-pass correction closure

Current head `076183879ef7a249230ac79b55887bd0f11a11c8`, tree `a58cbf71a870e252b287a2f018fdf1de99dca2c3`; prior reviewed local checkpoint
`16ccc989ab188591d906ee7e8ede526b79d41950` remains preserved. No upload or remote change occurred.

| Finding | Implemented result | Acceptance evidence |
| --- | --- | --- |
| R1: restore file mappings | Check extracted regular image membership, distinct image/label/XML outputs, reserved paths, image signature/structure and existing resource budgets before session commit. | Missing/non-image/duplicate/case-alias/derived-label/XML-directory/reserved targets reject and preserve prior inputs. Current and id-less legacy two-tile archives restore/export/re-restore. |
| R2: label selection | Use tile/detection references for YOLO and XML; empty stable selection remains authoritative; explicit legacy absolute-id fallback is retained. | Equal labels within/across tiles, noncontiguous IDs, zero/partial selections, manual-only output, invalid indices and contents flags verified in real ZIP output. |
| Compatibility double-check | Validate actual content format, preserving the downloader's historical .jpg filenames for valid PNG/TIFF bytes; supported image extensions remain image entries on export. | Two alias cases fail on the intermediate candidate and pass after repair. JPEG, PNG and TIFF variants pass without transcoding. |
| Reproduction note | Short Windows checkout/long-path prerequisite added. | Distinct from the uncompleted 80-character package-root qualification. |

The final maintained runs contain all **36 new cases**: Windows Python 3.12.10
**886 passed / 74 skipped**; Linux Python 3.11.17
**805 passed / 155 skipped**. Per-case statuses and command
results are in test-results.json. Earlier source/checkpoint failures are preserved
privately and are not added to these totals. The first 34-case suite gives
32 expected failures and two passes on the pre-fix checkpoint; those include
contract edge cases, not 32 separate defects. Two later alias regressions expose
the intermediate extension-matching mistake and are included in the final 36.

Existing full-tile policy, model/threshold code, manual membership and all
documented deferrals remain unchanged. Image checks do not certify training
quality, arbitrary damaged-image recovery, final runtime images or live providers.
The application grant, supporting-code/docs scope, historical Team acknowledgment,
website removal and exact security exceptions remain settled. About remains
unexecuted. Independent acceptance and authorized exact-head CI remain pending.
