# Sprint 05 Plan - Deployment Readiness and Local Launch Foundations

**Sprint Period**: April 7 - April 25, 2026 (19 days)  
**Planning Date**: April 6, 2026  
**Updated Through**: April 7, 2026  
**Sprint Focus**: Deployment readiness, Docker containerization, and local launch UX foundations  
**Target Capacity**: 70-80 hours  
**Expected Bundle Growth**: +10-20 KB (infrastructure-heavy sprint)

---

## Plan Authority

This file is the authoritative Sprint 05 plan.

It supersedes the historical planning snapshot in [SPRINT-PLANNING-SESSION-2026-04-06.md](./SPRINT-PLANNING-SESSION-2026-04-06.md) wherever the two differ.

The main Sprint 05 plan updates since the April 6 planning session are:

1. `TASK-054` is now the preferred post-Docker stretch task for launch UX.
2. `TASK-029` remains valuable, but it is now sequenced after `TASK-054`.
3. Runtime path normalization is treated as pre-sprint closeout work, not active Sprint 05 feature delivery.
4. The detailed Sprint 05 scope is synchronized with [current-tasks.md](../../current-tasks.md).

---

## Sprint Objectives

### Primary Goal

Deliver Docker containerization (`TASK-025`) with validated runtime dependencies and a current smoke-test baseline.

### Secondary Goals

1. Complete `TASK-051` runtime dependency verification and split.
2. Complete `TASK-052` current integration smoke-test baseline.
3. Deliver `TASK-054` local launch UX MVP after Docker baseline lands cleanly.
4. Consider `TASK-029`, `TASK-026`, or deferred Sprint 04 quick wins only if capacity remains.

### Planning Assumptions

- Plan around a sustainable pace of roughly `3.5-4.0 hrs/day`, not Sprint 03 peak velocity.
- Keep Sprint 05 weighted toward infrastructure and validation, not broad frontend feature work.
- Treat smaller bundle growth as the expected outcome unless `TASK-054` expands into frontend warm-start UX.

---

## Scope Boundaries

### What Sprint 05 Must Deliver

- Confirm actual runtime dependencies before containerization.
- Rebuild the smoke-test baseline around the current live app boot and route surface.
- Deliver Docker build/run behavior with persistent state mounted correctly.
- Preserve Setup Wizard, Settings, and current detection workflow behavior in the Docker environment.

### What Sprint 05 Should Not Quietly Absorb

- Broad dependency cleanup beyond `TASK-051`
- Large validation-harness rewrites beyond `TASK-052`
- Startup-pipeline redesign folded into `TASK-025`
- Multi-provider fallback as an assumed in-sprint commitment

### Explicit Scope Boundary

`TASK-025` owns container build/run behavior.  
`TASK-054` owns launcher, browser-open behavior, readiness polling, and any follow-on startup UX.

---

## Prerequisites and Carry-In Context

### Completed Before Sprint 05 Delivery Work

- `PRE-SPRINT-05-01` runtime path normalization is complete.
- Canonical app-anchored runtime directories now exist under `webapp/`.
- Docker mount planning should use normalized `webapp/` paths, not historical mixed root behavior.

### Closeout Still Worth Tracking

- `PRE-SPRINT-05-02` closeout cleanup and validation is complete.
- Its outcomes should stay separate from `TASK-025` so Docker decisions do not get mixed with repo cleanup scope.

### Runtime and Deployment Assumptions

- Canonical runtime writes now live under `webapp/` for config, sessions, logs, uploads, cache, temp/session artifacts, and model-relative assets.
- Filesystem-backed Flask sessions remain a real deployment constraint.
- `webapp/config/.env` persistence is a real runtime requirement.
- Repo-root `logs/` remains only a transitional local compatibility surface for the performance-summary fallback and should not be used as a Docker mount.
- `FLASK_SECRET_KEY` must remain stable across restarts.
- Model-weight handling is still an explicit Docker decision, not a solved assumption.

---

## Planned Task Sequence

### `TASK-051: Runtime Dependency Verification and Split`

**Why first**:
- It lowers Docker risk before image work starts.
- It prevents deployment-sensitive dependency drift from getting hidden inside containerization work.

**Key outputs**:
- Verified runtime dependency set
- CPU/CUDA behavior notes
- Documented keep/remove/reclassify decisions

**Exit criteria**:
- Clean-environment install test
- App startup verification
- CPU path verified
- CUDA path verified where hardware is available

### `TASK-052: Current Integration Smoke Test Baseline`

**Why second**:
- It gives Docker work a current validation target tied to the live app, not stale legacy assumptions.

**Key outputs**:
- Current app-boot smoke test
- Core route availability validation
- Updated or retired stale validation surfaces

**Exit criteria**:
- `pytest --collect-only tests -q` remains clean
- Current smoke path exists and runs against the live route surface

### `TASK-025: Docker Containerization`

**Why third**:
- Docker work should start only after dependency and validation baselines are credible.

**Key outputs**:
- Dockerfile and Compose configuration
- Persistent mount strategy
- Stable runtime environment contract
- Documented model-weight handling strategy

**Required decisions during Phase 1**:
- Model weights in image layer vs runtime download vs host volume
- Minimum supported platform target (`AMD64` required, `ARM64` stretch)
- Container health/readiness approach for later launcher support

**Exit criteria**:
- Container builds successfully
- Setup Wizard works in Docker
- Settings persist across restarts
- Detection workflow validated in container

### `TASK-054: Local Launch UX`

**Why fourth**:
- It depends on a stable Docker baseline.
- It should improve local UX without destabilizing `TASK-025` delivery.

**Phase 1 target**:
- Launcher MVP (`start.bat` first)
- Browser auto-open after readiness wait
- Basic troubleshooting path (`stop` / `logs` guidance or scripts)

**Phase 2 target**:
- Lightweight readiness endpoint or equivalent readiness contract
- Documented first-run / repeat-run behavior

**Phase 3 target**:
- Evaluate deferred warm-start UX for models and ZIP data

**Exit criteria for Sprint 05 success**:
- A local user can launch Docker with minimal or no manual CLI interaction
- Browser opens only after the app shell is reachable

### `TASK-029: Multi-Provider Fallback`

This remains a stretch goal and should only begin after `TASK-054` if capacity remains.

---

## Execution Timeline

### Week 1: April 7-13

**Focus**: validation infrastructure and Docker planning

| Date | Tasks | Hours |
|------|-------|-------|
| Apr 7-9 | `TASK-051` runtime dependency verification | 8-12h |
| Apr 10-11 | `TASK-052` integration smoke test baseline | 8-12h |
| Apr 12-13 | `TASK-025` Phase 1 Docker research/planning plus `TASK-054` scoping and acceptance criteria | 8-10h |

**Week 1 note**:
- `PRE-SPRINT-05-02` is complete, so Docker work should start from the canonical `webapp/` runtime contract rather than the pre-normalization folder tree.

### Week 2: April 14-20

**Focus**: Docker implementation and validation

| Date | Tasks | Hours |
|------|-------|-------|
| Apr 14-16 | `TASK-025` Phase 2: Dockerfile and Compose configuration | 16-24h |
| Apr 17-18 | `TASK-025` Phase 3: volume mounts and validation | 10-12h |
| Apr 19-20 | `TASK-025` Phase 4: testing and documentation | 8-12h |

### Week 3: April 21-25

**Focus**: final validation, launch UX, and stretch work

| Date | Tasks | Hours |
|------|-------|-------|
| Apr 21-22 | `TASK-025` final validation and fixes | 8-12h |
| Apr 23-24 | `TASK-054` Phase 1-2: launcher MVP, readiness wait, browser auto-open, and launch-flow documentation | 8-12h |
| Apr 25 | Sprint 05 retrospective | 2-4h |

**Total Sprint Effort**: `70-96 hours`  
**Planning Target**: `70-80 hours`

---

## Key Risks and Mitigations

### Risk 1: Docker Scope Expansion

**Risk**:
`TASK-025` grows to absorb dependency cleanup, smoke-test work, or launch UX.

**Mitigation**:
- Keep `TASK-051`, `TASK-052`, and `TASK-054` explicitly separate.
- Treat any startup-UX redesign as `TASK-054` or Sprint 06 work.

### Risk 2: Persistent-State Misconfiguration

**Risk**:
Config, session, temp, log, cache, or upload paths are not mounted correctly.

**Mitigation**:
- Use normalized `webapp/` runtime paths.
- Validate Setup Wizard save/load and restart persistence explicitly.

### Risk 3: Model-Weight Strategy Ambiguity

**Risk**:
Container delivery stalls because weight handling is not decided early.

**Mitigation**:
- Force the decision in `TASK-025` Phase 1.
- Document the chosen strategy and its tradeoffs in the Docker docs.

### Risk 4: Velocity Drift

**Risk**:
Sprint planning assumes Sprint 03 pace instead of a sustainable infrastructure pace.

**Mitigation**:
- Plan using the `3.5-4.0 hrs/day` assumption.
- Keep `TASK-029` and warm-start work explicitly optional.

### Risk 5: Launch UX Overreach

**Risk**:
`TASK-054` expands from launcher MVP into full runtime warm-start redesign.

**Mitigation**:
- Ship Phase 1 first.
- Defer Phase 3 warm-start UX if Docker baseline or readiness work consumes capacity.

---

## Definition of Done

### Must-Have

- `TASK-051` complete
- `TASK-052` complete
- `TASK-025` Phase 1-3 complete
- Setup Wizard functional in Docker
- Settings save/load validated with persistence
- Detection workflow validated in Docker
- Docker Compose configuration validated
- No regressions against Sprint 04 core behavior

### Should-Have

- `TASK-025` Phase 4 complete
- `AMD64` support validated
- `TASK-054` Phase 1 launcher MVP complete
- `TASK-054` Phase 2 either complete or cleanly deferred with documented readiness approach
- Deferred Sprint 04 quick wins reconsidered only if capacity remains

### Nice-to-Have

- `TASK-029` investigation begins after `TASK-054`
- `ARM64` support validated
- Docker Hub publishing path documented
- Warm-start UX feasibility assessed for Sprint 06

---

## Success Indicators

- A new user can run `docker compose up` and complete Setup Wizard.
- Configuration persists across container restarts.
- Detection workflow works end-to-end in the Docker environment.
- A local user can start the app with minimal or no manual CLI interaction once `TASK-054` lands.
- Documentation explains both the container contract and the local launch path clearly.

---

## References

- [Current Tasks](../../current-tasks.md)
- [Sprint Planning Session - 2026-04-06](./SPRINT-PLANNING-SESSION-2026-04-06.md)
- [Metrics Report - 2026-04](./METRICS-REPORT-2026-04.md)
- [Removal Candidates - Containerization](../analysis/REMOVAL-CANDIDATES-CONTAINERIZATION.md)
- [Sprint 04 Retrospective](./SPRINT-04-RETROSPECTIVE.md)

---

**Status**: Sprint 05 planning baseline complete and synchronized with `current-tasks.md`  
**Next Action**: Execute `TASK-051`, then `TASK-052`, then begin `TASK-025` Phase 1
