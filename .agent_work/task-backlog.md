# Task Backlog - Remaining Work

**Last Updated**: May 8, 2026  
**Planning State**: Sprint 05 completed work has been removed from the backlog. `TASK-065` remains in `current-tasks.md` as the active carry-forward item. No new not-started tasks have been moved into `current-tasks.md`.  
**Ordering Method**: The table below is ordered by current project value, dependency shape, and what most directly advances a credible v1 local release. Historical task numbering, prior priority labels, sprint labels, and "future enhancement" wording were intentionally disregarded while ordering the list.

---

## Cleanup Notes

- Removed completed or current-task-only backlog entries for `TASK-051`, `TASK-052`, `TASK-054`, `TASK-055`, `TASK-056`, `TASK-057`, `TASK-062`, `TASK-063`, `TASK-064`, `TASK-025`, and `TASK-065`.
- Kept `TASK-029` in the backlog because it was not started.
- Archived the not-started `TASK-029` active task artifact under `.agent_work/context/archive/2026-05/not-started-task-artifacts/`; the backlog row below is now the planning source for that task until it is selected.

---

## Ordered Remaining Backlog

| Order | Task | Status | Type | Estimated Effort | Key Dependencies | Recommended Disposition And Rationale |
|---:|---|---|---|---|---|---|
| 1 | `TASK-066` Release Candidate Validation Gate | NOT_STARTED | C (Release Engineering / Validation) | 1-2 days (8-16h) | `TASK-065`; agreed release package shape | Keep first. Before adding more features, prove the release ZIP, pinned image digest, checksums, manifest, provider setup, asset import, TLS CA import, and first-run restart behavior from a clean user-facing path. |
| 2 | `TASK-069` License And Release Policy Review | NOT_STARTED | C (Legal / Release Policy / Governance) | 0.5-1 day technical prep plus owner/legal review | `TASK-025`; `TASK-065`; owner/legal availability | Keep near the front. Technical release readiness is not the same as permission to distribute; this can block v1 late if deferred. |
| 3 | `TASK-067` CI Release Gate Tightening | NOT_STARTED | C (CI / Release Engineering) | 1-2 days (8-16h) | `TASK-065`; `TASK-066` checklist | Keep. Once the release-candidate checklist exists, promote the highest-value digest, manifest, packaging, and launcher checks into CI or documented required/manual gates. |
| 4 | `TASK-068` Windows Test Portability And Script Validation | NOT_STARTED | B/C (Testing / Developer Experience) | 0.5-1 day (4-8h) | `TASK-065`; current release helper tests | Keep as a release-support follow-up. Decide whether PowerShell release-helper coverage stays Windows-only or gains explicit PowerShell Core coverage in CI. |
| 5 | `TASK-070` Restricted-Network Package Enhancements | NOT_STARTED | B/C (Release Engineering / Offline Support) | 1-3 days (8-24h) | `TASK-065`; `TASK-066` | Keep, but after the normal connected release path is validated. This should not block v1 unless restricted-network support becomes a launch requirement. |
| 6 | `TASK-058` Background Detection Jobs And Durable Run State | NOT_STARTED | C (Architecture / Reliability) | 3-5 days (24-40h) | Release baseline stable; current progress/cancel contract understood | Keep. This is the highest-value post-release architecture work because long-running detection should not stay bound to request/thread-local assumptions. |
| 7 | `TASK-059` Backend Layer Decomposition And Logging Consolidation | NOT_STARTED | C (Architecture / Maintainability) | 3-5 days (24-40h) | `TASK-058` | Keep after `TASK-058`. Route/service boundaries should follow the actual job and state ownership model rather than be guessed first. |
| 8 | `TASK-027` Enhanced Error Handling | NOT_STARTED | A/B (Reliability / UX) | 1-2 days (8-16h) | Existing logging and support diagnostics | Keep. Better user-facing recovery, retry, and troubleshooting messages compound the value of the release-support work. Fold the old error-handler quick win into this task where practical. |
| 9 | `TASK-026` CPU Optimization | NOT_STARTED | C (Performance) | 2-3 days (16-24h) | Current inference baseline; release host assumptions | Keep. CPU-only performance matters for the selected local deployment baseline, but it should follow release-candidate validation so optimization starts from a stable package. |
| 10 | `TASK-029` Multi-Provider Fallback | NOT_STARTED | B (Reliability) | 2-3 days (16-24h) | Provider abstraction; improved error handling preferred | Keep, but not before release gates. Automatic fallback can improve reliability, but it must preserve provider provenance and avoid masking unsafe/no-key conditions. |
| 11 | `TASK-060` Frontend Build Modernization | NOT_STARTED | B (Frontend Infrastructure) | 1-2 days (8-16h) | Stable release branch or explicit modernization window | Keep. Manual ordered concatenation is maintenance risk, but changing the build pipeline is not necessary for the immediate release gate. |
| 12 | `TASK-028` Mobile Responsiveness | NOT_STARTED | B (UI/UX) | 2 days (16h) | Core desktop/local release stable | Keep as field-work improvement. Useful for investigators, but not required before the first local desktop release is proven. |
| 13 | `TASK-061` Coordinated NumPy 2 Runtime Migration | NOT_STARTED | C (Dependency / Runtime Compatibility) | 1-2 days (8-16h) | Stable release baseline; dependency test window | Keep as deliberate dependency modernization. Do not mix it into release cleanup or CPU optimization unless a security/support issue forces it. |
| 14 | Sprint 04 Deferred Quick Wins | NOT_STARTED | A (Polish / Cleanup) | 4-6h | None hard; `TASK-027` overlap | Merge rather than preserve as standalone sprint scope. Browser refresh warning can be a small polish task; error-handler standardization belongs under `TASK-027`. |
| 15 | Advanced Filtering | NOT_STARTED | B (Feature) | 3-4 days (24-32h) | Larger result-set workflow evidence; durable state may help | Defer. Valuable only after release/reliability foundations and clearer evidence that result-set management is the next user bottleneck. |
| 16 | Performance Dashboard | NOT_STARTED | A/B (Monitoring / Diagnostics) | 2 days (16h) | Metrics contract; durable job/run state preferred | Defer and potentially reshape. Support diagnostics are already improving; a dashboard should be driven by real operator needs after `TASK-058`. |
| 17 | User Preferences | NOT_STARTED | B (UX) | 1-2 days (8-16h) | Settings/storage contract; repeated-user evidence | Defer or reconsider. Sprint 04 Settings already covers part of this value; do not add preference surface until repeated-user workflow pain is clear. |

---

## Sprint 06 Selection Guidance

Do not automatically select this whole list for Sprint 06. A conservative Sprint 06 should close `TASK-065`, then choose a small release-readiness slice:

1. `TASK-066` to define and execute the release-candidate gate.
2. `TASK-069` if v1 distribution or public release is near.
3. `TASK-067` and `TASK-068` only to the extent they automate or clarify checks that would otherwise be repeated manually.

If the release path pauses, `TASK-058` is the best next architecture investment. It should precede `TASK-059`.

---

## Historical Performance Snapshot

| Sprint | Duration | Outcome | Notes |
|---|---:|---|---|
| Sprint 01 | February 4-18, 2026 | Complete | Foundation, memory, and UX work |
| Sprint 02 | February-March 2026 | Complete | Architecture work |
| Sprint 03 | March 11-18, 2026 | Complete | Legacy feature restoration and Google Maps API migration |
| Sprint 04 | March 19-April 6, 2026 | Complete | Setup/settings, performance investigation, cleanup, detection stabilization |
| Sprint 05 | April 7-May 8, 2026 | Closeout | Runtime determinism, local YOLO ownership, smoke baseline, release hardening, OCI packaging, launcher MVP |

---

## Related Documentation

- [Current Tasks](./current-tasks.md)
- [Completed Tasks](./completed-tasks.md)
- [Sprint 05 Retrospective Analysis](./context/analysis/SPRINT-05-RETROSPECTIVE-ANALYSIS-2026-05-08.md)
