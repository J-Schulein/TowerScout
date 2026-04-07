# Current Tasks - Active Sprint

**Sprint Period**: April 7 - April 25, 2026 (Sprint 05 - 19 days)  
**Last Updated**: April 7, 2026  
**Focus**: Deployment readiness, Docker containerization, and validation infrastructure  
**Status**: 🆕 **SPRINT 05 PLANNING** - Sprint 05 officially starts April 7, 2026

---

## 🎉 Sprint 04 Completion (March 19 - April 6, 2026)

**Sprint Status**: ✅ **COMPLETE - ALL CORE OBJECTIVES ACHIEVED**  
**Sprint Duration**: 19 days (extended from 16 days to absorb TASK-053)  
**Task Completion Rate**: 7 of 7 core tasks + 1 added closeout task (100%)  
**Bundle Evolution**: 412.8 KB → 446.1 KB (+33.3 KB)

**Sprint 04 Achievements**:
- ✅ Setup Wizard and Settings implemented (TASK-046)
- ✅ Large dataset performance investigation completed (ISSUE-003)
- ✅ Performance quick wins delivered (debug image gating, hydration cleanup)
- ✅ Console logging audit completed (TASK-048)
- ✅ Full-repo stale code audit completed (TASK-050)
- ✅ Legacy code cleanup with pytest gate repair (TASK-049)
- ✅ UI formatting and progress overlay (TASK-047)
- ✅ Detection workflow stabilization with browser validation (TASK-053)
- ✅ Browser smoke harness established
- ✅ Pytest collection gate: 154 collected / 0 collection errors

**Sprint 04 Retrospective**: See [SPRINT-04-RETROSPECTIVE.md](./context/status/SPRINT-04-RETROSPECTIVE.md)  
**Completed Tasks**: See [completed-tasks.md](./completed-tasks.md) for full Sprint 04 task details

---

## Pre-Sprint 05 Closeout Gate

These are current-branch closeout items for `feature-sprint-04-closeout`. Complete them before merging to `main` and creating the Sprint 05 branch so Sprint 05 delivery work starts from a cleaner baseline.

### **PRE-SPRINT-05-01: Runtime Path Normalization**
**Status**: COMPLETED  
**Type**: A (Closeout / Runtime Consistency)  
**Priority**: CRITICAL  
**Estimated Effort**: 4-8 hours  
**Branch Context**: `feature-sprint-04-closeout`  

**Objective**: Normalize TowerScout runtime path handling so logs, uploads, cache, sessions, temp files, and model-relative assets resolve consistently regardless of launch mode.

**Key Activities**:
- Choose and document a canonical runtime root for persistent and temp artifacts
- Replace mixed `cwd`-relative and app-relative path usage with centralized path definitions
- Normalize high-risk areas first: logs, uploads, map cache, filesystem sessions, and model paths
- Verify behavior remains consistent for local dev, pytest, and CI launch modes

**Validation**:
- App startup succeeds from the supported dev workflow
- Pytest collection and targeted smoke paths still pass from repo root
- No new duplicate runtime directories are created by mixed launch modes during validation

**Progress Update**:
- Added shared runtime path helpers in `webapp/ts_paths.py` anchored to `webapp/`
- Normalized `towerscout.py` runtime paths for map cache, uploads, model directories, Flask session storage, temp dataset export, and `send_from_directory` path resolution
- Updated supporting modules (`ts_en.py`, `ts_validation.py`, `ts_geocache.py`, `ts_logging.py`, `ts_performance.py`) to use shared app-anchored path helpers
- Updated `tests/test_performance_metrics.py` so it no longer changes `cwd` to `webapp/` just to find logs
- Verified repo-root import/app smoke, `cd webapp` import/app smoke, and targeted config/path tests

**Notes**:
- This is a closeout prerequisite, not Sprint 05 feature delivery work
- Final Docker volume decisions should be derived only after this task is complete
- Pre-push hygiene note: `.agent_work/context/analysis/browser-runs/` remains local-only and ignored because its `summary.json` artifacts can contain live provider request URLs and should not be committed without sanitization
- Transitional compatibility note: `ts_config.get_recent_performance_stats()` still falls back to `cwd/logs/performance.log` if the normalized `webapp/logs/performance.log` is absent
- Remaining `cwd` references are intentional diagnostics (`towerscout.py`, `ts_logging.py`), the temporary log-reader compatibility fallback in `ts_config.py`, and non-active helper/archive surfaces outside the runtime write path
- Remaining stale validation blockers are tracked under `TASK-052`, not under this closeout task

**Validation Results**:
- Repo-root and `cd webapp` launch-mode smokes both resolved uploads, map cache, model directories, session storage, and temp session paths under `webapp/`
- Both smokes returned `GET /` status `200`
- `webapp/flask_session/` was updated by the smoke runs while repo-root `flask_session/` retained its older April 6 timestamp, which confirms the normalized session target was used
- Targeted `tests/unit/test_config.py` path/log-reader cases passed (`4 passed`)

### **PRE-SPRINT-05-02: Post-Normalization Cleanup + Validation**
**Status**: COMPLETED  
**Type**: A (Closeout / Cleanup)  
**Priority**: HIGH  
**Estimated Effort**: 2-4 hours  
**Branch Context**: `feature-sprint-04-closeout`  

**Objective**: Remove or reclassify only confirmed dead runtime artifacts after normalization and validate the repo is ready to merge into `main`.

**Key Activities**:
- Re-check root-level runtime directories and confirm which ones are now obsolete
- Clean up only artifacts that are proven unused after normalization
- Update docs and task tracking to reflect the normalized runtime path behavior
- Confirm deferred items stay deferred: `TowerScoutSite/`, `Model/`, `SyntheticData/`, and `hosting/`
- Confirm no API key values will be included or exposed during the commit process

**Validation**:
- Smoke checks confirm the normalized runtime paths are the only active write targets
- Documentation and task notes consistently describe current behavior, future target state, and deferred cleanup
- Branch is ready for merge review without ambiguous runtime-path cleanup risk

**Notes**:
- Do not treat this as blanket repo pruning
- Archive or defer anything that still has rollback, operational, or product-surface value

**Progress Update**:
- Re-checked repo-root runtime-looking directories after normalization and removed confirmed stale local leftovers: repo-root `cache/`, `uploads/`, `flask_session/`, random `pytest-cache-files-*`, and `webapp/tmp*` temp dirs
- Kept repo-root `logs/` only as a transitional compatibility surface because `ts_config.get_recent_performance_stats()` still falls back to `cwd/logs/performance.log` if `webapp/logs/performance.log` is absent
- Updated path-sensitive docs and task tracking to use the canonical `webapp/` runtime contract for Sprint 05 planning and Docker follow-through
- Tightened `.gitignore` for random pytest/temp artifacts and local browser-run captures so secret-bearing analysis artifacts stay out of commits

**Validation Results**:
- Repo-root and `cd webapp` launch-mode smokes both returned `GET /` status `200`
- Deleted repo-root `cache/`, `uploads/`, and `flask_session/` stayed absent after both smokes, which confirms they are no longer active write targets
- `webapp/flask_session/` and `webapp/logs/` advanced during the smokes while repo-root `logs/` retained its pre-smoke April 7 timestamp, which confirms the canonical `webapp/` write targets were used
- `pytest --collect-only tests -q` collected `159` tests with no collection errors
- `pytest tests/unit/test_config.py -q` still reports the two known stale Google-validation test failures already scoped under `TASK-052`; they were not folded into this cleanup task

**Closeout Decision**:
- Deferred repo surfaces remain deferred: `TowerScoutSite/`, `Model/`, `SyntheticData/`, and `hosting/`
- Docker planning should now use the canonical `webapp/config/`, `webapp/flask_session/`, `webapp/logs/`, `webapp/temp/`, `webapp/uploads/`, and `webapp/cache/` mount set
- Repo-root `logs/` is transitional/local-only and should not be treated as a Docker persistence target

---

## 🎯 SPRINT 05 GOALS

**Sprint Period**: April 7 - April 25, 2026 (19 days)  
**Planning Completed**: April 6, 2026  
**Sprint Focus**: Deployment Readiness and Docker Containerization  
**Target Capacity**: 70-80 hours (accommodating Docker complexity)  
**Expected Bundle Growth**: +10-20 KB (infrastructure-heavy sprint unless TASK-054 expands into frontend warm-start UX)  

### Sprint 05 Objectives

**Primary Goal**: Deliver Docker containerization (TASK-025) with validated runtime dependencies and smoke test coverage

**Secondary Goals**:
1. Complete runtime dependency verification and split (TASK-051)
2. Establish current integration smoke test baseline (TASK-052)
3. Deliver local launch UX MVP after Docker baseline lands cleanly (TASK-054)
4. Consider multi-provider fallback (TASK-029), CPU optimization work (TASK-026), or deferred Sprint 04 quick wins if capacity remains

**Key Principle**: Keep TASK-025 focused on container build/run behavior. Use TASK-051 and TASK-052 as prerequisites so Docker acceptance criteria stay clear and runtime-risk changes remain isolated. Treat launcher/browser UX as follow-on work under TASK-054 rather than silently expanding Docker scope.

---

## 📋 SPRINT 05 ACTIVE TASKS

### **TASK-051: Runtime Dependency Verification and Split** 🟡
**Status**: NOT_STARTED  
**Type**: C (Architecture / Deployment Readiness)  
**Priority**: CRITICAL  
**Estimated Effort**: 4-8 hours  
**Target Sprint**: Sprint 05  

**Objective**: Verify runtime dependencies before containerization and separate confirmed runtime requirements from removable or optional packages without changing user-visible behavior.

**Key Activities**:
- Verify import/runtime necessity of deployment-sensitive packages in `webapp/requirements.txt`
- Confirm Torch CPU/CUDA detection and execution behavior
- Treat `ultralytics` as CUDA/runtime-sensitive until proven removable
- Remove or reclassify low-risk dependency drift (e.g., `seaborn`)
- Preserve current user workflow, appearance, and functionality

**Validation**:
- Clean-environment install test
- App startup verification
- CPU-only verification path
- CUDA-available verification path where hardware is available

**Dependencies**:
- TASK-049 stale-code audit findings ✅ COMPLETED

**Notes**: Recommended as pre-containerization gate. Do not fold into TASK-025 - different risks, acceptance criteria, and rollback needs.

**User Value**: Ensures Docker container has minimal, verified runtime dependencies

---

### **TASK-052: Current Integration Smoke Test Baseline** 🟡
**Status**: NOT_STARTED  
**Type**: A (Quality / Validation)  
**Priority**: CRITICAL  
**Estimated Effort**: 4-8 hours  
**Target Sprint**: Sprint 05  

**Objective**: Replace the quarantined legacy end-to-end harness with a current smoke test that validates the live Flask route surface and core app boot flow.

**Key Activities**:
- Replace skipped legacy `tests/integration/test_end_to_end.py` coverage
- Validate application boot with current configuration/setup flow
- Exercise core live routes and confirm expected response behavior
- Provide stable regression target for containerization work
- Keep test lightweight for regular Sprint 05 runs
- Triage or replace stale tests and mocks discovered during pre-sprint closeout so validation reflects the live route surface

**Success Criteria**:
- `pytest --collect-only tests -q` remains clean
- Current smoke test exists for app boot + core route availability
- Containerization work has concrete validation target beyond import/collection
- Stale validation surfaces are either updated to current behavior or explicitly retired from the active baseline

**Dependencies**:
- TASK-046 setup wizard/settings implementation ✅ COMPLETED
- TASK-049 validation-gate repair ✅ COMPLETED

**Notes**:
- Recommended before TASK-025 so Docker work validates against current, supported app surface.
- Current stale-test findings from PRE-SPRINT-05-01 include outdated Google API validation mocks in `tests/unit/test_config.py` and `GET /getobjects` assumptions in `tests/unit/test_flask_routes.py`.
- Unless one of those blocks additional closeout work earlier, handle them under TASK-052 rather than folding them into runtime-path normalization.

**User Value**: Provides regression protection during containerization

---

### **TASK-025: Docker Containerization** 🔴
**Status**: NOT_STARTED  
**Type**: A (Infrastructure)  
**Priority**: HIGH  
**Estimated Effort**: 1-2 days (8-16 hours)  
**Target Sprint**: Sprint 05  

**Objective**: Create Docker configuration for one-command local deployment

**Requirements**:
- Multi-stage Dockerfile with model weights
- Docker Compose configuration
- Environment variable management
- Platform-specific optimization (AMD64/ARM64)
- Volume mount strategy for persistent state

**Current Runtime Persistence Surfaces**:
Runtime-path normalization is complete. Docker work should treat the following as the active persistence contract:

1. **`webapp/config/`**
2. **`webapp/flask_session/`**
3. **`webapp/logs/`**
4. **`webapp/temp/`**
5. **`webapp/uploads/`**
6. **`webapp/cache/`**

**Transitional Compatibility Note**:
`ts_config.get_recent_performance_stats()` still falls back to `cwd/logs/performance.log` if `webapp/logs/performance.log` is absent. Treat repo-root `logs/` as a temporary local compatibility surface, not a Docker mount target.

**Environment Variables Required**:
- `GOOGLE_API_KEY`
- `AZURE_MAPS_SUBSCRIPTION_KEY`
- `DEFAULT_MAP_PROVIDER`
- `FLASK_SECRET_KEY` (must be stable across restarts)

**Dependencies**:
- ✅ TASK-046 (completed) - setup wizard/settings volume-mount behavior
- 🟡 TASK-051 - runtime dependency verification and split
- 🟡 TASK-052 - current integration smoke-test baseline

**Notes**:
- Keep focused on container build/run behavior
- Do NOT absorb dependency-verification or smoke-test replacement into this task
- Current app uses filesystem-backed Flask sessions and writes to `webapp/config/.env`
- Final Docker volume decisions should use the normalized `webapp/` runtime contract, not historical folder duplication
- Docker delivery must provide writable session storage, stable `FLASK_SECRET_KEY`, and persistent writable mount for `webapp/config/`
- TASK-025 Phase 1 must explicitly choose and document the model-weight strategy (image layer vs runtime download vs host volume)
- Without these, first-launch setup may fail or saved configuration lost on container replacement

**User Value**: Enables one-command deployment for non-technical users

---

### **TASK-054: Local Launch UX** 🟡
**Status**: NOT_STARTED  
**Type**: B (Deployment UX / Local Launch Flow)  
**Priority**: MEDIUM  
**Estimated Effort**: 1-2 days (8-12 hours)  
**Target Sprint**: Sprint 05 (post-Docker stretch goal)  

**Objective**: Deliver a user-friendly local launch flow for Docker deployments so users can start TowerScout with a click, have the browser open automatically, and receive a clear startup experience while the application becomes ready.

**Requirements**:
- Host-side launcher flow for supported local deployment targets (`start.bat` first, cross-platform launcher follow-up if capacity allows)
- Browser auto-open only after the app shell is reachable on the configured localhost port
- Clear separation between "container is up" and "application is ready for user interaction"
- User-facing startup experience that works with the existing Setup Wizard flow instead of bypassing it
- Troubleshooting path for common launch failures (Docker not running, port conflict, startup timeout)

**Proposed Delivery Phases**:
1. **Phase 1 - Launcher MVP**
   - Add launcher script(s) for local Docker startup
   - Wait for reachable app shell before opening the browser
   - Add companion stop/logs guidance or scripts so users are not forced into raw Docker CLI usage for routine support
2. **Phase 2 - Readiness + Browser Orchestration**
   - Add or formalize a lightweight startup/readiness endpoint for launcher polling
   - Ensure browser launch targets the correct localhost port and only happens once per launch attempt
   - Document expected behavior for first launch, repeat launch, and failure modes
3. **Phase 3 - Deferred Warm-Initialization UX**
   - Evaluate whether model/ZIP warm initialization can happen after the app shell is served
   - If feasible within Sprint 05 capacity, expose startup status to the frontend so setup/loading UI can distinguish "page is available" from "runtime is fully warm"
   - Defer this phase to Sprint 06 if Docker baseline or launcher MVP consumes available capacity

**Dependencies**:
- 🟡 TASK-052 - current integration smoke-test baseline
- 🔴 TASK-025 - Docker containerization baseline complete enough to support a stable local launcher target

**Notes**:
- Do NOT absorb this task into TASK-025. The launcher/browser UX is a separate user-experience layer with different failure modes and rollback concerns.
- Container code should not be responsible for opening the host browser; browser launch should be driven by the host-side launcher.
- If Sprint 05 tightens, ship Phase 1 first and defer background warm-initialization redesign.

**User Value**: Reduces or eliminates command-line interaction for local users while keeping Setup Wizard and startup behavior understandable.

---

### **TASK-029: Multi-Provider Fallback** 🟡
**Status**: NOT_STARTED  
**Type**: B (Reliability)  
**Priority**: MEDIUM  
**Estimated Effort**: 2-3 days (16-24 hours)  
**Target Sprint**: Sprint 05 (stretch goal)  

**Objective**: Implement automatic fallback between map providers for reliability

**Requirements**:
- Automatic provider switching on API failures
- Quality comparison and provider selection logic
- Rate limit handling and quota management
- Transparent failover for users

**Dependencies**:
- Provider abstraction layer ✅ COMPLETED

**Notes**: May be deferred to Sprint 06 if Docker work requires more time

**User Value**: Improved reliability when one provider experiences issues

---

### **Optional Quick Wins from Sprint 04** 🟢
**Status**: NOT_STARTED  
**Priority**: LOW-MEDIUM  
**Total Estimated Effort**: 4-6 hours

**Browser Refresh Warning Fix** (2-3 hours)
- Debug `window.onbeforeunload` inconsistencies
- Cross-browser compatibility testing
- Implement reliable solution

**Error Handling Pattern Standardization** (2-3 hours)
- Remove deprecated `fatalError()` references
- Standardize on `TowerScoutErrorHandler`
- Update documentation

**Notes**: Include only if Sprint 05 capacity allows after TASK-051, TASK-052, and TASK-025

---

## 📊 Sprint 05 Execution Plan

**Sprint Duration**: 19 days (April 7 - April 25, 2026)  
**Target Capacity**: 70-80 hours  
**Sprint Pace**: Medium-to-high complexity work

### Week 1: April 7-13 (Validation Infrastructure)
**Focus**: Prepare for containerization with verified dependencies and test baseline  
**Estimated Effort**: 24-32 hours

| Date | Tasks | Hours |
|------|-------|-------|
| Apr 7-9 | TASK-051: Runtime dependency verification | 8-12h |
| Apr 10-11 | TASK-052: Integration smoke test baseline | 8-12h |
| Apr 12-13 | TASK-025 Phase 1: Docker research and planning, plus TASK-054 scoping and acceptance criteria | 8-10h |

**Week 1 Note**:
- `PRE-SPRINT-05-02` closeout validation is complete; start Docker work from the canonical `webapp/` runtime contract rather than the old mixed-path folder duplication.

### Week 2: April 14-20 (Docker Implementation)
**Focus**: Build and test containerized deployment  
**Estimated Effort**: 30-40 hours

| Date | Tasks | Hours |
|------|-------|-------|
| Apr 14-16 | TASK-025 Phase 2: Dockerfile and compose config | 16-24h |
| Apr 17-18 | TASK-025 Phase 3: Volume mounts and validation | 10-12h |
| Apr 19-20 | TASK-025 Phase 4: Testing and documentation | 8-12h |

### Week 3: April 21-25 (Polish and Stretch Goals)
**Focus**: Final validation, launch UX polish, and stretch work  
**Estimated Effort**: 16-24 hours

| Date | Tasks | Hours |
|------|-------|-------|
| Apr 21-22 | TASK-025 Final validation and fixes | 8-12h |
| Apr 23-24 | TASK-054 Phase 1-2: launcher MVP, readiness wait, browser auto-open, and launch-flow documentation | 8-12h |
| Apr 25 | Sprint 05 Retrospective | 2-4h |

**Total Sprint Effort**: 70-96 hours (target: 70-80h)

---

## 🎯 Sprint 05 Definition of Done

### Must-Have (Primary Goals)
- [ ] TASK-051 complete: Runtime dependencies verified and split documented
- [ ] TASK-052 complete: Current integration smoke test in place
- [ ] TASK-025 Phase 1-3 complete: Docker container builds and runs
- [ ] Setup Wizard functional in Docker environment
- [ ] Settings save/load works with volume mounts
- [ ] Detection workflow validated in container
- [ ] All volume mounts tested and documented
- [ ] Docker Compose configuration validated
- [ ] Zero regressions from Sprint 04 functionality

### Should-Have (Secondary Goals)
- [ ] TASK-025 Phase 4 complete: Full Docker documentation
- [ ] Multi-platform support (AMD64 at minimum)
- [ ] TASK-054 Phase 1 complete: launcher MVP for local Docker startup
- [ ] TASK-054 Phase 2 complete or clearly scoped/deferred with documented readiness approach
- [ ] Browser Refresh Warning Fix (if capacity allows)
- [ ] Error Handling Standardization (if capacity allows)

### Nice-to-Have (Stretch Goals)
- [ ] TASK-029 investigation started after TASK-054
- [ ] TASK-029 partial implementation (provider fallback logic)
- [ ] ARM64 platform support
- [ ] Docker Hub image publishing
- [ ] Performance optimization in containerized environment

### Sprint Health Metrics
- TASK-051 and TASK-052 completed before TASK-025 starts
- Docker container starts successfully on first attempt
- All TASK-046 features work in containerized environment
- Documentation includes troubleshooting guide
- All automated tests passing in container
- Container image size reasonable (<2GB with models)

---

## 📅 Sprint 05 Planning Notes

**Key Decisions**:
1. **Sequencing is critical**: TASK-051 and TASK-052 MUST complete before TASK-025
2. **TASK-025 scope discipline**: Do NOT absorb dependency or validation work into Docker task
3. **TASK-054 stays separate**: Launcher/browser UX work starts only after Docker baseline is stable enough to target
4. **Volume mount testing**: Explicitly test Setup Wizard save/load in Docker
5. **Model-weight strategy is a Phase 1 decision**: do not defer layer/download/volume treatment until late Docker validation
6. **Fallback plan**: If Docker takes longer, defer TASK-054 Phase 2-3 and TASK-029 to Sprint 06

**Risk Mitigation**:
- Start with TASK-051 to identify any surprises in dependencies early
- TASK-052 provides regression protection during Docker work
- Keep TASK-025 phases separate for easier rollback if needed
- Keep TASK-054 phased so launcher MVP can ship without forcing startup-pipeline redesign into the same sprint
- Use a conservative planning pace around 3.5-4.0 hrs/day instead of Sprint 03 peak velocity
- Document all Docker-specific configuration decisions

**Success Indicators**:
- New user can run `docker-compose up` and complete Setup Wizard
- Configuration persists across container restarts
- Detection workflow works end-to-end in container
- User can launch the local Docker deployment with minimal or no manual CLI interaction
- No manual .env editing required

---

## 🔗 Related Documentation

- [Sprint 05 Planning](./context/status/SPRINT-05-PLAN.md) - Detailed sprint plan synchronized with this tracker
- [Sprint 04 Retrospective](./context/status/SPRINT-04-RETROSPECTIVE.md)
- [Task Backlog](./task-backlog.md)
- [Completed Tasks](./completed-tasks.md)
- [Docker Requirements Analysis](./context/analysis/REMOVAL-CANDIDATES-CONTAINERIZATION.md)

---

## 📝 Notes

**Sprint 04 Learnings Applied**:
- Keep sprint plans synced with live task status
- Update definition-of-done checklists as work completes
- Perform mid-sprint resync if scope changes
- Mark optional items as optional everywhere

**Sprint 05 Focus**:
- This sprint is about deployment readiness, not feature development
- Emphasis on validation, testing, and infrastructure
- Conservative approach to containerization
- Document everything for non-technical deployment

**Next Sprint Preview (Sprint 06)**:
- TASK-026: CPU Optimization
- TASK-029: Complete multi-provider fallback (if not finished)
- TASK-027: Enhanced Error Handling
- TASK-028: Mobile Responsiveness
- Additional polish and optimization work
