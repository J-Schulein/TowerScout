# Current Tasks - Active Sprint

**Sprint Period**: March 19 - April 4, 2026 (Sprint 04 - 16 days)  
**Last Updated**: April 1, 2026  
**Focus**: Setup Wizard closeout + performance/stability + cleanup/polish  
**Status**: ⏳ **SPRINT 04 IN PROGRESS** - TASK-046, TASK-048, ISSUE-003 follow-up, TASK-050, and TASK-049 are complete; TASK-047 is the remaining in-sprint implementation decision before Sprint 05 prep

## 🎉 Sprint 03 Completion (March 11-18, 2026)

**Sprint Status**: ✅ **COMPLETE - ALL OBJECTIVES ACHIEVED**  
**Sprint Duration**: 8 days (completed 6 days ahead of schedule)  
**Sprint Effort**: 56 hours actual (planned: 44-71 hours)  
**Sprint Velocity**: 7.0 hours/day (vs Sprint 02: 4.4 hours/day)  
**Task Completion Rate**: 8 of 8 tasks (100%)  
**Critical Issues Resolved**: 2 of 2 (ISSUE-001, ISSUE-002)  
**Bundle Evolution**: 372.6 KB → 412.8 KB (+40.2 KB)

**Sprint 03 Achievements**:
- ✅ Manual tower addition feature fully restored (TASK-033)
- ✅ Export system enhanced with ML documentation (TASK-036)
- ✅ Google Maps API migration completed (TASK-039 Phases 5-6)
- ✅ Drawing mode UX with context-aware notifications
- ✅ CSV export with ML/Manual source indicator  
- ✅ Integration testing validated all features
- ✅ Global variable deprecation system completed
- ✅ Comprehensive documentation updated

**Sprint 03 Retrospective**: See [SPRINT-03-RETROSPECTIVE.md](./context/status/SPRINT-03-RETROSPECTIVE.md)  
**Completed Tasks**: See [completed-tasks.md](./completed-tasks.md) for full Sprint 03 task details

---

## 🎯 SPRINT 04 GOALS

**Sprint Period**: March 19 - April 4, 2026 (16 days)  
**Planning Completed**: March 18, 2026  
**Sprint Focus**: Setup Wizard Implementation + Code Quality Improvements  
**Target Capacity**: 65-75 hours (accommodating expanded scope)  
**Sprint Plan**: See [SPRINT-04-PLAN.md](./context/status/SPRINT-04-PLAN.md) for full details

### Sprint 04 Objectives

**Primary Goal**: Deliver Setup Wizard & Settings Screen (TASK-046) to eliminate manual .env editing

**Secondary Goals**:
1. Investigate ISSUE-003 performance with large datasets (discovery phase)
2. Improve application polish through UI formatting updates
3. Simplify console logging for better end-user experience
4. Complete a full-repo stale code and performance audit
5. Clean up legacy code from refactoring efforts using audited findings

---

## 📋 SPRINT 04 ACTIVE TASKS

### **TASK-046: Setup Wizard and Settings Screen** ✅
**Status**: COMPLETED  
**Type**: B (Feature Development)  
**Priority**: CRITICAL  
**Estimated Effort**: 40-50 hours (5-7 days with testing)  
**Target Sprint**: Sprint 04  
**Task File**: [TASK-046-setup-wizard-settings-screen.md](./tasks/TASK-046-setup-wizard-settings-screen.md)

**Objective**: Implement first-launch Setup Wizard and in-app Settings Screen for seamless API key management

**Key Features**:
- 🔑 API Key Management (validate and save without text editor)
- 🚀 First-Launch Setup Wizard (guided multi-step flow)
- ⚙️ Settings Modal (in-app configuration updates)
- 🐳 Docker Compatible (host-mounted .env updates)
- 📊 Performance Metrics Display (recent detection stats)
- 🔧 System Controls (debug mode, cache clearing)

**Completion Snapshot** (March 23, 2026):
- ✅ Phase 0 complete: discovery, requirements, and design decisions documented
- ✅ Phase 1 complete: `ts_config.py` plus `/api/config/validate-key`, `/api/config/save-keys`, `/api/config/status`, `/api/config/reset-session`, and `/api/config/performance`
- ✅ Phase 2 complete: setup wizard flow, provider validation, `.env` persistence, degraded setup-required boot mode, and single-provider runtime fixes
- ✅ Phase 3 complete: settings modal, masked key previews, clear-cache flow, performance metrics display, and settings save path
- ✅ Phase 4 complete: runtime smoke testing, validation hardening, TLS fallback, Azure probe fallback, and headerless performance-log parsing fix
- ✅ Phase 5 complete: task documentation synchronized and scope closeout recorded

**Closeout Notes**:
- Manual verification confirmed the setup wizard successfully saves Google and Azure keys into `webapp/config/.env`
- Settings-screen performance metrics now show real data after the log parser fix
- API-key handling was hardened by removing startup key-preview logging and ignoring config backups/lock files
- Debug-mode preference persistence remains in TASK-046, but broader verbose console-log gating is explicitly deferred to TASK-048

**Dependencies**:
- ✅ TASK-001 (API Key Security) - COMPLETED
- ✅ Error handling system - COMPLETED
- ✅ Frontend modular architecture - COMPLETED

**User Value**: Eliminates major UX friction point for non-technical users. Critical for Docker-based local deployment.

---

### **ISSUE-003: Large Dataset Performance Investigation** 🟡
**Status**: COMPLETED  
**Type**: A (Performance - Discovery Phase)  
**Priority**: MEDIUM  
**Estimated Effort**: 2-4 hours (investigation only)  
**Task File**: [SPRINT-04-PLAN.md](./context/status/SPRINT-04-PLAN.md#issue-003-large-dataset-performance-investigation)

**Objective**: Benchmark performance with 500+ detections and identify optimization opportunities

**Investigation Plan**:
1. Create test dataset with 500+ detections (30 min)
2. Profile detection list and map rendering (1.5-2 hours)
3. Identify bottlenecks (30-60 min)
4. Create recommendations report (30 min)

**Go/No-Go Criteria**:
- **GO** (implement fixes): Detection rendering >5 seconds
- **NO-GO** (defer): Acceptable performance, document for future

**User Value**: Proactive investigation before production issues arise

### TYPE A - ISSUE-003 DISCOVERY START - 2026-03-23 15:35 EDT
**Objective**: Start Sprint 04 large-dataset profiling with reproducible evidence instead of ad hoc observation.
**Execution**: Created `.agent_work/scripts/issue-003-benchmark.js` and benchmarked 100/500/1000 visible detections against Google-like and Azure-like provider update paths. Saved raw output to `.agent_work/context/analysis/ISSUE-003-benchmark-results.json` and published findings in `.agent_work/context/analysis/ISSUE-003-PERFORMANCE-INVESTIGATION.md`.
**Output**: Detection-list generation stayed roughly linear in the local harness, while the Azure path showed repeated full-shape scans (`374,750` lookups at 500 detections, `1,499,500` at 1000) caused by `getShapes().filter(...)` lookups per update. Broad Sprint 04 optimization work is currently a NO-GO; the evidence supports only a targeted Azure shape-index quick win if capacity remains.
**Next**: Decide whether to leave ISSUE-003 as documented discovery complete or convert the Azure shape-index refactor into a small follow-on implementation task.

### TYPE A - ISSUE-003 AZURE SHAPE INDEX FIX - 2026-03-23 16:10 EDT
**Objective**: Remove the Azure Maps large-dataset hotspot identified during ISSUE-003 discovery without changing detection behavior.
**Execution**: Updated `webapp/js/src/providers/AzureMap.js` to maintain a `detectionId -> shape` index for detection overlays, moved hot-path lookups in `updateMapRect()` and `colorMapRect()` to the index, synchronized index updates on clear/remove/re-ID flows, updated `webapp/js/src/detection/Detection.js` to delegate Azure cleanup to the provider helper and reindex shapes after detection sorting, then rebuilt `webapp/js/towerscout.js`.
**Output**: Azure detection updates no longer require repeated `getShapes().filter(...)` scans after the first cache miss. Validation completed with `node --check` on the touched source files, `node webapp/build.js`, and a mocked Azure smoke test that confirmed repeated updates and color changes reuse the cached shape while clear operations empty both the data source and the index.
**Next**: Monitor real browser behavior during normal Azure detection/review workflows and feed any remaining console-noise cleanup into TASK-048 rather than expanding ISSUE-003 scope again.

### TYPE A - ISSUE-003 AZURE INIT REGRESSION FIX - 2026-03-23 17:05 EDT
**Objective**: Restore Azure provider readiness after a browser test exposed a post-fix regression in the drawing-tools initialization path.
**Execution**: Removed an accidental `o.azureShape = shape;` statement from `initializeDrawingTools()` in `webapp/js/src/providers/AzureMap.js`, rebuilt `webapp/js/towerscout.js`, and re-ran source validation with `node --check` plus the frontend bundle build.
**Output**: Azure drawing-tool initialization no longer throws before `drawingManagerReady` can be marked, which removes the blocked "map is still loading" state reported when starting a circle search area after provider restore.
**Next**: Re-test the Azure circle-boundary workflow in the browser and keep the remaining `colorMapRect()` cleanup as non-blocking follow-up work only if more Azure-specific issues appear.

---

### **ISSUE-003 Follow-Up: Performance Quick Wins** 🟡
**Status**: COMPLETED  
**Type**: A (Performance Quick Wins)  
**Priority**: MEDIUM-HIGH  
**Estimated Effort**: 3-6 hours  
**Source**: [FURTHER-PERFORMANCE-IMPROVEMENT-INVESTIGATION.md](./context/analysis/FURTHER-PERFORMANCE-IMPROVEMENT-INVESTIGATION.md)

**Objective**: Land the lowest-risk post-ISSUE-003 performance wins before broader refactors or UI polish work.

**Sequencing Decision** (March 31, 2026):
- Execute immediately after TASK-048 so verbose logging/profiling noise is reduced first
- Keep scope to quick wins only; defer bigger backend/rendering refactors until after fresh measured profiles
- Complete this tranche before TASK-049 cleanup validation and before TASK-047 UI polish

**Initial Scope**:
- Gate or remove `ts_en.py` debug image writes from the normal detection path
- Remove duplicate frontend hydration/visibility passes (`generateList()` / `adjustConfidence()` / extra `det.update()` loops)
- Stop creating provider overlay objects for metadata-only tile records unless review mode needs them

**Deferred Until Measured**:
- Async or batched geocoding redesign
- Shared imagery cache for detection downloads
- Clustering, viewport culling, or canvas/WebGL overlay work

**User Value**: Faster heavy-load detection review with bounded implementation risk

### TYPE A - ISSUE-003 QUICK WINS PASS 1 - 2026-03-31 12:24 EDT
**Objective**: Land the first bounded quick-win batch from the March 31 follow-up investigation without opening broader backend or rendering refactors.
**Execution**: Updated `webapp/ts_en.py` so EfficientNet debug image dumps are disabled by default and only run when `TOWERSCOUT_SAVE_EN_DEBUG_IMAGES` is enabled, collapsed redundant detection hydration/visibility passes in the modular frontend sources, made metadata-only `Tile` objects skip overlay allocation at the `PlaceRect` layer, added null-safe provider overlay guards, mirrored the still-active legacy-path equivalents in `webapp/js/src/towerscout.js`, and rebuilt `webapp/js/towerscout.js`.
**Output**: Default detection runs no longer write secondary-classifier debug JPEGs, large-result hydration now pauses constructor-time updates and relies on a single post-hydration visibility pass, and metadata-only tile records no longer allocate provider overlays by default. The rebuilt frontend bundle size is now `446.1 KB`.
**Validation**: `C:\Users\bg90\TowerScout\.venv\Scripts\python.exe -m py_compile webapp\ts_en.py`; `node --check` on touched JS source files and `webapp/js/towerscout.js`; `node webapp/build.js`; `node tests/frontend/test_debug_logging_contract.js`; `node tests/frontend/test_global_contract.js`
**Next**: Use the completed quick-win tranche as the stability checkpoint before starting TASK-049 cleanup validation.

### TYPE A - ISSUE-003 QUICK WINS SMOKE TEST SIGNOFF - 2026-03-31 12:24 EDT
**Objective**: Confirm the quick-win tranche did not regress core runtime workflows before closing the task.
**Execution**: User browser-smoke-tested the updated detection flow and reported that the affected behavior appears to be working as expected.
**Output**: The quick-win tranche now has code/build validation plus live browser confirmation.
**Next**: Treat ISSUE-003 quick wins as complete and proceed to TASK-049 when ready.

---

### **TASK-047: UI Formatting and Polish** 🟢
**Status**: NOT_STARTED  
**Type**: A (UI/UX Polish)  
**Priority**: MEDIUM  
**Estimated Effort**: 6-10 hours  
**Task File**: [TASK-047-ui-formatting-and-polish.md](./tasks/TASK-047-ui-formatting-and-polish.md)

**Objective**: Implement the approved main-screen polish, settings readability fixes, longer polygon-complete notifications, and a bounded detection progress-status enhancement.

**Sequencing Decision** (March 31, 2026):
- Defer until after TASK-048 and the ISSUE-003 performance quick-win tranche
- Avoid polishing around map/rendering behavior that is still likely to change
- Re-evaluate exact scope once stability/performance work lands

**Scope**:
- Main-screen header, top-right utility row, action-row spacing, export hover text, and search-button corner-radius refinements
- Settings-screen `Resource Links` heading and readable white link styling
- Longer timeout only for the polygon-complete notifications
- Lightweight progress-overlay phase status plus counts during active detections, without raw log streaming

**Implementation Approach**:
1. Discovery Session (1 hour) - Review with user
2. Implementation (2-5 hours) - Apply CSS updates
3. Review & Refinement (1-2 hours) - Iterative adjustments

**User Value**: Enhanced visual polish and professional appearance

---

### **TASK-048: Console Log Audit and Simplification** 🟢
**Status**: COMPLETED  
**Type**: A (Developer Experience)  
**Priority**: MEDIUM  
**Estimated Effort**: 3-5 hours  
**Task File**: [SPRINT-04-PLAN.md](./context/status/SPRINT-04-PLAN.md#task-048-console-log-audit-and-simplification)

**Objective**: Audit and refine browser console log output for better end-user understanding

**Sequencing Decision** (March 31, 2026):
- This is the next active implementation task
- It should land before the ISSUE-003 quick-win tranche so profiling noise is reduced first
- It owns the deferred TASK-046 work for making the persisted debug preference actually gate verbose browser console output

**Implementation Plan**:
- Phase 1: Audit all console statements (1-2 hours)
- Phase 2: Define logging strategy (30 min)
- Phase 3: Implement simplification (1.5-2 hours)
- Phase 4: Documentation (30 min)

**Key Considerations**:
- Balance debugging needs vs. information overload
- Implement debug mode toggle for verbose logging
- Own the deferred TASK-046 follow-up for making the persisted debug preference actually gate verbose console output
- Ensure critical errors always visible
- Clear and actionable error messages

**User Value**: Cleaner console output, easier debugging for support

### TYPE A - TASK-048 DEBUG LOG GATING - 2026-03-31 11:01 EDT
**Objective**: Make the existing settings-screen debug toggle actually control verbose browser console output without muting normal DevTools usage.
**Execution**: Added an early `TowerScoutLogger` bootstrap in `webapp/templates/towerscout.html`, migrated app-owned verbose `console.log` statements in `webapp/js/src/` plus template boot scripts to `window.TowerScoutLogger.debug(...)`, routed `webapp/js/src/settings.js` through `TowerScoutLogger.setDebugMode()`, downgraded compatibility-setter deprecation warnings in `webapp/js/src/globals.js` to debug-only, added `tests/frontend/test_debug_logging_contract.js`, and rebuilt `webapp/js/towerscout.js`.
**Output**: Default console output now suppresses lifecycle/debug chatter while still surfacing warnings and errors. Enabling debug mode from Settings re-enables verbose traces immediately.
**Next**: Browser-smoke the Settings toggle plus Google/Azure initialization flows, then decide whether any remaining warnings should be reclassified before closing TASK-048.

### TYPE A - TASK-048 LAYERED APP LOGGING FIX - 2026-03-31 11:18 EDT
**Objective**: Restore useful in-app console/status messaging after the first TASK-048 pass over-focused on browser-console noise reduction.
**Execution**: Extended `TowerScoutLogger` in `webapp/templates/towerscout.html` with an always-on `info()` path that writes to the in-app output panel, added queued flush behavior for messages emitted before `#output` exists, kept `debug()` gated by the persisted debug preference, promoted key startup/provider/detection workflow messages in `webapp/js/src/towerscout.js`, `webapp/js/src/providers/providerInit.js`, `webapp/js/src/utils/apiHelpers.js`, and `webapp/js/src/ui/search.js` from debug-only to always-visible info status messages, updated the settings copy in `webapp/js/src/settings.js` and the template, then rebuilt `webapp/js/towerscout.js`.
**Output**: Users now get baseline application-status messages in the in-app output panel with debug mode disabled, while enabling debug mode adds the more detailed trace output back into both the app output panel and the browser console.
**Next**: Browser-smoke the output panel during startup, tile estimation, full detection, cancellation, and provider initialization to confirm the message volume feels right before closing TASK-048.

### TYPE A - TASK-048 SMOKE TEST SIGNOFF - 2026-03-31 11:25 EDT
**Objective**: Confirm the revised layered logging behavior feels right in real browser workflows before closing TASK-048.
**Execution**: User manually smoke-tested startup, provider initialization, tile estimation, full detection, cancellation, settings debug-mode toggling, and the in-app output panel/browser console behavior.
**Output**: User reported the behavior looks good. Baseline status messaging remains visible with debug mode disabled, and extra detail appears when debug mode is enabled.
**Next**: Mark TASK-048 complete and begin the ISSUE-003 performance quick-win tranche.

---

### **TASK-050: Full-Repo Stale Code and Performance Audit** 🟡
**Status**: COMPLETED  
**Type**: C (Architecture / Analysis)  
**Priority**: HIGH  
**Estimated Effort**: 6-10 hours  
**Task File**: [TASK-050-full-repo-stale-code-and-performance-audit.md](./tasks/TASK-050-full-repo-stale-code-and-performance-audit.md)

**Objective**: Perform a full-repository audit to identify stale/orphaned/generated code and capture no-functionality-change performance opportunities.

**Implementation Plan**:
- Phase 1: Structural inventory and reference tracing (2-3 hours)
- Phase 2: Evidence scoring and classification (2-3 hours)
- Phase 3: Performance opportunity review (1-2 hours)
- Phase 4: Documentation and task handoff (1 hour)

**Deliverables**:
- Master findings document in `.agent_work/context/analysis/`
- Baseline validation output for pytest collection and unused-code scanning
- Classification of confirmed stale items vs. runtime-verification candidates
- Recommendations mapped to TASK-049, ISSUE-003, and TASK-048

**User Value**: Creates an evidence-backed cleanup and performance roadmap without risking active functionality.

---

### **TASK-049: Legacy Code Cleanup** 🟢
**Status**: COMPLETED  
**Type**: A (Code Quality)  
**Priority**: MEDIUM  
**Estimated Effort**: 4-6 hours  
**Task File**: [TASK-049-legacy-code-cleanup.md](./tasks/TASK-049-legacy-code-cleanup.md)

**Objective**: Execute verified cleanup/remediation batches from TASK-050 without removing active or legacy-but-active paths.

**Closeout Decision** (March 31, 2026):
- TASK-049 starts with a low-risk, tracked-artifact-only batch derived from TASK-050 and the March 31 audit refresh
- Batch 1 removed `.coverage`, `.DS_Store`, tracked `webapp/cache/maps/*.cache`, and `webapp/templates/towerscout_backup.html`
- The task then repaired the pytest collection gate and archived high-confidence stale helper/test surfaces without deleting the historical artifacts outright
- Runtime dependency verification is moved to `TASK-051`, and the replacement for the quarantined legacy integration harness is moved to `TASK-052`
- `webapp/js/src/towerscout.js.stage3.bak` remains deferred as a local-only low-value artifact
- `webapp/js/towerscout.original.js` remains explicitly excluded because it is a deliberate rollback/reference asset and should not be removed through opportunistic stale-code cleanup

**Implementation Plan**:
- Phase 1: Intake TASK-050 findings and choose low-risk batch (30 min)
- Phase 2: Safe removal/remediation (1-2 hours)
- Phase 3: Validation (30-60 min) - Run tests and targeted smoke checks
- Phase 4: Report update and next-batch planning (30 min)

**Dependencies**:
- TASK-050 must identify and classify removal candidates first

**Areas to Focus**:
- Confirmed generated artifacts and backup files
- Verified stale test/debug surfaces
- Unused imports/locals and dead helper code
- Only items marked safe by TASK-050

**User Value**: Cleaner, more maintainable codebase

### TYPE A - TASK-049 BATCH 1 START - 2026-03-31 13:30 EDT
**Objective**: Refresh the TASK-050 audit for the March 31 working tree and execute only the approved low-risk tracked cleanup batch.
**Execution**: Marked TASK-049 in progress, created a dedicated task document, refreshed TASK-050 findings for current size metrics and already-consumed TASK-048 / ISSUE-003 quick wins, and limited the first cleanup pass to tracked `.coverage`, `.DS_Store`, `webapp/cache/maps/*.cache`, and `webapp/templates/towerscout_backup.html`.
**Output**: TASK-049 now has task-specific tracking and a decision-complete first-pass scope that excludes helper scripts, `webapp/tests/`, known broken tests, dependency drift, `towerscout.js.stage3.bak`, and `webapp/js/towerscout.original.js`.
**Next**: Execute the batch-1 removals, rerun validation baselines, and then decide whether deeper cleanup should stay in TASK-049 or move to follow-on work.

### TYPE A - TASK-049 LOW-RISK BATCH 1 EXECUTION - 2026-03-31 13:43 EDT
**Objective**: Remove only the approved tracked generated artifacts and stale tracked template backup without expanding into higher-risk cleanup.
**Execution**: Used `git rm --cached` for tracked `.coverage`, `.DS_Store`, and the 25 tracked `webapp/cache/maps/*.cache` files, and `git rm` for `webapp/templates/towerscout_backup.html`.
**Output**: All batch-1 targets are now removed from the tracked git inventory, while the excluded helper scripts, local backup artifacts, broken test files, dependency candidates, and `webapp/js/towerscout.original.js` remain untouched.
**Next**: Verify tracked-file removal and rerun the pytest and flake8 baselines against the post-cleanup tree.

### TYPE A - TASK-049 BATCH 1 VALIDATION - 2026-03-31 13:52 EDT
**Objective**: Confirm the low-risk cleanup batch did not widen the existing known drift.
**Execution**: Verified `git ls-files` returns no matches for the batch-1 targets, reran a runtime/reference search for `towerscout_backup.html`, reran `pytest --collect-only tests -q --basetemp .agent_work\\pytest-basetemp-task049 -o cache_dir=.agent_work\\.pytest_cache_task049`, and reran `flake8 webapp tests --select=F401,F841 --statistics --jobs 1`.
**Output**: Batch-1 targets are no longer tracked, the `towerscout_backup.html` reference search returned no runtime matches, pytest stayed at the known `149 collected / 2 errors` baseline, and flake8 stayed at the known `105 F401 / 14 F841` baseline.
**Next**: Decide whether TASK-049 should continue into helper/test/dependency cleanup or stop after the validated low-risk tranche. Note: pytest emitted a non-blocking cache warning because `.agent_work\\.pytest_cache_task049` was not writable for `lastfailed` cache output.

### TYPE A - TASK-049 VALIDATION-GATE REPAIR - 2026-03-31 14:25 EDT
**Objective**: Remove the known pytest collection blockers so later cleanup passes have a usable regression gate.
**Execution**: Added import-time test environment defaults in `tests/conftest.py`, introduced an env-gated lazy `EN_Classifier` path in `webapp/towerscout.py` that leaves eager initialization as the default runtime behavior, rewrote `tests/unit/test_event_system.py` to the current `ExitEvents` API, quarantined the stale `tests/integration/test_end_to_end.py` harness with a module-level skip, and reran targeted pytest validation.
**Output**: `tests/unit/test_event_system.py` now passes against the current API, and full `pytest --collect-only tests -q` completes at `154 collected / 0 collection errors`. The stale end-to-end harness is explicitly marked for later rebuild against the current Flask route surface instead of silently failing collection.
**Next**: If TASK-049 continues, move to medium-risk stale-surface triage next and keep CUDA-sensitive dependency cleanup last.

### TYPE A - TASK-049 MEDIUM-RISK STALE-SURFACE TRIAGE - 2026-03-31 15:05 EDT
**Objective**: Remove high-confidence stale helper/test surfaces from active paths without losing the historical artifacts.
**Execution**: Cleaned the unused import/local noise in `webapp/towerscout.py`, added `.agent_work/context/archive/2026-03-task-049-stale-surfaces/README.md`, archived `webapp/js/src/comment_providers.sh`, `webapp/js/src/temp_extract_providers.sh`, and the full `webapp/tests/` tree into the new archive folder, then reran pytest collection and flake8 baseline checks.
**Output**: The stale helper scripts and manual `webapp/tests/` harnesses are no longer present in active repo paths, the archive preserves them for recovery, `webapp/towerscout.py` is clean for `F401/F841`, and the overall unused-import/local baseline improved from `105/14` to `73/6`.
**Next**: Finalize closeout and hand runtime-sensitive follow-ons to Sprint 05 tasks.

### TYPE A - TASK-049 CLOSEOUT DECISION - 2026-03-31 16:05 EDT
**Objective**: Close TASK-049 once only separately scoped leftovers remain.
**Execution**: Declared TASK-049 complete after the validated cleanup/archive pass, moved runtime dependency verification to `TASK-051`, moved the current smoke-test rebuild to `TASK-052`, deferred `webapp/js/src/towerscout.js.stage3.bak` as a local-only artifact, and preserved `webapp/js/towerscout.original.js` as an explicitly excluded rollback/reference asset.
**Output**: TASK-049 is complete, and the remaining work is now split into narrower pre-containerization tasks instead of being forced into stale-code cleanup.
**Next**: Start `TASK-047` when ready and carry `TASK-051` / `TASK-052` into Sprint 05 before `TASK-025`.

---

### **Quick Wins** 🟢
**Status**: NOT_STARTED  
**Priority**: LOW-MEDIUM  
**Total Estimated Effort**: 4-6 hours

**Browser Refresh Warning Fix** (2-3 hours)
- Debug `window.onbeforeunload` inconsistencies
- Cross-browser compatibility testing
- Implement reliable solution

**Error Handling Standardization** (2-3 hours)
- Remove deprecated `fatalError()` references
- Standardize on `TowerScoutErrorHandler`
- Update documentation

---

## 📊 Sprint 04 Execution Timeline

**Sprint Duration**: 16 days (March 19 - April 4, 2026)  
**Target Capacity**: 65-75 hours (mid-range pace)  
**Extended From**: 14 days to accommodate code quality tasks

### Week 1: March 19-25 (Foundation)
**Focus**: Backend infrastructure and discovery work  
**Estimated Effort**: 32-46 hours

| Date | Tasks | Hours |
|------|-------|-------|
| Mar 19-20 | TASK-046 Phase 0 + ISSUE-003 Investigation | 8-12h |
| Mar 21-23 | TASK-046 Phase 1 + Console/Code Cleanup Discovery | 12-18h |
| Mar 24-25 | TASK-046 Phase 2 START (Setup Wizard UI) | 12-16h |

### Week 2: March 26-April 1 (Implementation & Polish)
**Focus**: Feature completion and code quality  
**Estimated Effort**: 30-44 hours

| Date | Tasks | Hours |
|------|-------|-------|
| Mar 26-28 | TASK-046 Phase 2-3 + TASK-048 audit/strategy + performance quick-win planning | 16-24h |
| Mar 29-30 | TASK-048 implementation + ISSUE-003 quick wins + TASK-049 cleanup batch | 8-12h |
| Mar 31 | TASK-049 validation + TASK-047 only if stability work is complete + Testing START | 6-8h |

### Week 3: April 1-4 (Testing & Completion)
**Focus**: Comprehensive testing and closeout  
**Estimated Effort**: 15-23 hours

| Date | Tasks | Hours |
|------|-------|-------|
| Apr 1-3 | TASK-046 Phase 4 Testing + Final Validation | 12-18h |
| Apr 4 | TASK-046 Phase 5 Documentation + Retrospective | 3-5h |

**Total Sprint Effort**: 60-90 hours (target: 65-75h)

---

## 🎯 Sprint 04 Definition of Done

### Must-Have (Primary Goals)
- [ ] Setup wizard functional on first launch, blocks app until configured
- [ ] Settings screen accessible and functional for API key updates
- [ ] API key validation working with clear feedback (<5 seconds)
- [ ] .env file persistence with backup/rollback mechanism
- [ ] Zero regressions in existing functionality (all Sprint 03 features work)
- [ ] All 13 TASK-046 acceptance criteria met
- [ ] Cross-browser testing complete (Chrome, Firefox, Edge, Safari)

### Should-Have (Secondary Goals)
- [x] ISSUE-003 investigation complete with recommendations
- [ ] UI formatting improvements implemented and approved
- [ ] Console log output simplified and standardized
- [x] Full-repo stale code/performance audit completed and documented
- [ ] Legacy code cleaned up from audited findings, all tests passing
- [ ] Browser refresh warning works consistently
- [ ] Error handling patterns fully standardized

### Nice-to-Have (Stretch Goals)
- [x] Quick performance optimizations (if ISSUE-003 identifies easy wins)
- [ ] Debug mode toggle for verbose logging
- [ ] Bundle size reduced through code cleanup
- [ ] Enhanced developer documentation

### Sprint Health Metrics
- Task completion rate: 100% (maintain Sprint 02-03 standard)
- Actual effort within 15% of estimate
- Zero critical bugs introduced
- All automated tests passing
- Bundle size stays under 500 KB (currently 412.8 KB)
- Documentation updated for all new features

---

## 📅 Next Steps

**Immediate Actions**:
1. Start `TASK-047` when you want to resume Sprint 04 implementation work
2. Carry runtime dependency verification/split into `TASK-051` before `TASK-025`
3. Carry the current integration smoke-test rebuild into `TASK-052` before `TASK-025`

**Sprint Kickoff**: March 19, 2026  
**Sprint Review**: Weekly check-ins (March 25, April 1)  
**Sprint Retrospective**: April 4, 2026

---

---

## ✅ PREVIOUS SPRINT SUMMARIES

### **SPRINT 03 ACHIEVEMENTS** (March 11-18, 2026)
**Status**: ✅ COMPLETE (8/8 tasks, 56 hours, 100% completion rate)

**Key Deliverables**:
- Manual tower addition feature fully restored (TASK-033)
- Export system enhanced with ML/Manual tracking (TASK-036)
- Google Maps API migration completed (TASK-039)
- Drawing mode UX with context-aware notifications
- Global variable deprecation system implemented
- Integration testing validates all features

**Full Details**: See [completed-tasks.md](./completed-tasks.md) and [SPRINT-03-RETROSPECTIVE.md](./context/status/SPRINT-03-RETROSPECTIVE.md)

---

### **SPRINT 02 ACHIEVEMENTS** (February 18 - March 11, 2026)
**Status**: ✅ COMPLETE (5/5 tasks, 61 hours)
- TASK-041: Deep Dive Priority 2 (State Management & Memory Cleanup)
- TASK-037: User Journey Verification (9 of 10 issues resolved)
- TASK-039: Emergency Geocoding Fixes
- TASK-040: Azure Maps Visual Consistency
- TASK-035: Memory Management & Map Object Cleanup
- TASK-031: Interactive Highlighting System
- TASK-032: Enhanced Details Panel


**Key Deliverables**:
- Modular frontend architecture (27 modules)
- Zero regressions in comprehensive testing
- 3 critical race conditions fixed
- Comprehensive documentation updates

**Full Details**: See [completed-tasks.md](./completed-tasks.md)

---

### **SPRINT 01 ACHIEVEMENTS** (February 4-18, 2026)
**Status**: ✅ COMPLETE (7/7 tasks, 32 hours, 90% success rate)

**Key Deliverables**:
- Exceptional memory performance improvements
- Cross-provider functionality validated
- 5 critical issues resolved
- Enhanced user experience features

**Full Details**: See [completed-tasks.md](./completed-tasks.md)

---

## 📚 Documentation References

- **Sprint 04 Plan**: [SPRINT-04-PLAN.md](./context/status/SPRINT-04-PLAN.md)
- **Sprint 03 Retrospective**: [SPRINT-03-RETROSPECTIVE.md](./context/status/SPRINT-03-RETROSPECTIVE.md)
- **Task Backlog**: [task-backlog.md](./task-backlog.md)
- **Completed Tasks**: [completed-tasks.md](./completed-tasks.md)
- **Spec-Driven Workflow**: [.github/instructions/spec-driven-approach.instructions.md](../.github/instructions/spec-driven-approach.instructions.md)
- **Copilot Instructions**: [.github/copilot-instructions.md](../.github/copilot-instructions.md)
- Docker containerization (TASK-025) if capacity allows
