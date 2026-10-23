# Revised source and evidence reproduction

Local-only proposed head `dad6f4c709d41c6fa696e1c09de3e6cf0c5a2717`, tree `01f286393936d58f563db0ff1195fecf17c2770c`, sole parent
`87ca90089473e1855f98968f75a17b5f8d0dd1cd`. The source ZIP contains 406 exact
committed blobs, with no per-entry comments/extra metadata. The manifest is
UTF-8 JSON, indent 2, all LF and one final LF. Hash its actual bytes; do not
reserialize it. The earlier manifest's CRLF hash remains historical.

Review `SHA256SUMS.txt`, then verify every archive member against the manifest.
`candidate.bundle` contains the one new commit with the receiving base as its
prerequisite. In a disposable clone already containing that base:

```powershell
git bundle verify <packet-directory>/candidate.bundle
git fetch <packet-directory>/candidate.bundle HEAD
git checkout --detach dad6f4c709d41c6fa696e1c09de3e6cf0c5a2717
git rev-parse 'HEAD^'
git rev-parse 'HEAD^{tree}'
git show -s --format=fuller HEAD
git diff --name-status 87ca90089473e1855f98968f75a17b5f8d0dd1cd HEAD
git diff --binary 87ca90089473e1855f98968f75a17b5f8d0dd1cd HEAD
python scripts/check_adoption_history.py
```

Both author and committer must be the separately approved account/noreply
identity. Inherited receiving history is not anonymized. Privacy review of the
exact new blobs and packet must be repeated immediately before any authorized
upload; this local packet grants no upload permission.

Use a new supported Windows Python 3.12 environment, Node 22 and Git. Bootstrap
pip with `python scripts/bootstrap-pip.py`, then install `webapp/requirements.txt`
and `requirements-dev.txt` using that environment. Keep TLS verification enabled.
The Windows test environment was freshly installed; its complete freeze is in
`windows-python-freeze.txt`. The Linux test environment derives from a preserved
CPU image, updated with selected requirements/development tools, Git and Node;
see `linux-python-freeze.txt`. Neither environment is the final release image.

Maintained selection, with no helper exclusion flag or hidden failure filter:

```text
python -m pytest tests/unit/ tests/integration/test_end_to_end.py::test_current_app_boot_and_core_route_surface tests/integration/test_geocoding_integration.py -q -p no:cacheprovider --junitxml review.xml
python -m flake8 webapp/ --jobs=1 --count --select=E9,F63,F7,F82 --show-source --statistics
python -m pip check
python tests/frontend/verify_export_serialization.py
node tests/frontend/test_setup_wizard_validation_contract.js
node tests/frontend/test_detection_cancel_recovery_contract.js
node tests/frontend/test_task106_export_selection.js
node tests/frontend/test_task106_restore_safety.js
node tests/integration/test_task_064_provider_state_manager.js
node webapp/build.js
git diff --exit-code -I "Build Date" -- webapp/js/towerscout.js
```

Each platform's executed commands and every collected test status/skip reason
are in `test-results.json`. Windows tests construct real CPU/CUDA control ZIPs,
verify all internal/external hashes, notices and offline links, and exercise
launch/stop with an isolated fake engine. They are package-contract evidence,
not real model/device/provider or final package qualification.

The full browser suite, fresh production builds/security scans, Linux Python
3.12 matrix and receiving proposed-merge checks were not executed here. Formatting,
type-check, broad integration and SARIF reporting keep their declared advisory
status; no advisory check is relabeled as a pass. The maintained blocking flake8
selection is `webapp/`; an exploratory broader scan found two existing undefined
names in explicitly skipped legacy image-processing tests, left deferred.

Earlier failed harness runs (missing Linux Git/Node), stale-contract failures
and endpoint-blocked helper executions remain private historical evidence.
They do not describe the final source's test selection. Corrected tests follow
the approved support route/helper removal, not a change to endpoint protection.
