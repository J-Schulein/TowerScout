# Reproduction and evidence boundaries

Check candidate-source.zip and candidate-source-manifest.json against SHA256SUMS.
Extract to an isolated directory, or apply candidate.bundle over the specified
receiving base. Preserve the declared source identity; do not import old fork refs.

On Windows, use a short checkout/extraction directory. If the full paths
exceed the host toolchain limits, choose a shorter root or use an organization-
approved Git/Windows long-path configuration; no setting change is required by
this packet. This checkout prerequisite is separate from the still-pending
80-character installed-package qualification.

Use Node >=22.12 and Python 3.11/3.12. Install reviewed requirements in an isolated
environment. This packet's Python freeze files describe the actual environments.

```
npm ci
npm audit --include=dev --audit-level=high
node -e "const p=require('puppeteer'); if(typeof p.launch!=='function') process.exit(1)"
node webapp/build.js
git diff --exit-code -- webapp/js/towerscout.js
python -m pytest tests/unit/ tests/integration/test_end_to_end.py::test_current_app_boot_and_core_route_surface tests/integration/test_geocoding_integration.py -q -p no:cacheprovider
python tests/frontend/verify_export_serialization.py
node tests/frontend/test_task106_followup.js
node tests/frontend/test_task106_export_selection.js
node tests/frontend/test_task106_restore_safety.js
node tests/frontend/test_detection_cancel_recovery_contract.js
node tests/frontend/test_setup_wizard_validation_contract.js
node tests/integration/test_task_064_provider_state_manager.js
docker build --target frontend --tag towerscout-frontend:review .
```

The existing browser-controller tests load real source in a minimal DOM with
synthetic transport/controller fixtures. Their simulated service uses Node and
does not execute PowerShell host-helper code. Local execution used an isolated
localhost page and ports with headless Edge; receiving CI uses its declared
Chromium/Linux setup. Production models, live provider accounts, actual final
images, public downloads and two-host deployment are not exercised by those tests.

Raw local logs/JUnit records and early failed checkpoints remain private because
they contain local paths and test infrastructure details. test-results.json has
every case/status; browser-results.json records all five executed contracts.
The registry audit is time-specific and must be rerun on authorized CI/upload.
All nine required receiving check identities remain unchanged. Exact-head remote
dispatch and actual receiving merge checks still require their applicable approval.

Run the focused repair contracts with `python -m pytest tests/unit/test_dataset_mapping_selection.py -q`.
Run the R2 contracts with `python -m pytest tests/unit/test_dataset_writer_roundtrip.py -q`.
The npm/frontend/browser and maintained results are fresh for this exact head.
Historical trust/dependency receipts and previous-head CI remain explicitly identified in EVIDENCE-REUSE.json.
