# Historical evidence carried forward

The following October 23 evidence concerns the preserved PR 117 checkpoint.
The corrected trust/import files are byte-identical in this revision; current
maintained trust tests also pass. These rehearsals were not rerun for this packet.

# Scoped trust and retained-volume evidence

Docker and rootless Podman each passed the corrected importer/trust-module
rehearsal over preserved CPU images. The image IDs and hashes of restricted raw
receipts are in [trust-results.json](trust-results.json); the raw receipts are
kept privately because they contain local trust/configuration details.

The four public incident intermediates/cross-signs are rejected on import before
durable placement. Their independently computed DER/SPKI hashes are included in
the candidate's fixture manifest. A synthetic input containing private material
is likewise rejected without persistent copying. Negative provider checks retain
the prior active configuration/trust. Approved import/explicit refresh, forced
container recreation and eight named-volume sentinels pass. Fourteen affected
chain fixtures are rejected by the TLS controls. Verified requests/aiohttp
transport controls reach Google (200) and Azure (401 without account credentials).
Those status codes prove transport scope only, not account/provider workflows.

Corrected source files were overlaid on preserved images; these are not newly
built final-candidate images. Podman was exercised while existing Docker apps
remained running, so this does not qualify the supported separate Podman profile.
Existing user installations were not migrated. Only isolated test containers
were stopped; their retained volumes and earlier evidence were preserved.
Final exact images, configured bundles, browser-download bytes and all accepted
host/device/provider/recovery cases still require qualification.
