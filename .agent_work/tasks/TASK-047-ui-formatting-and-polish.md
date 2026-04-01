# TASK-047: UI Formatting and Polish

**Status**: NOT_STARTED  
**Priority**: MEDIUM  
**Type**: A (UI/UX Polish)  
**Estimated Effort**: 6-10 hours  
**Created**: April 1, 2026  
**Target Sprint**: Sprint 04

---

## Objective

Implement the approved set of main-screen polish, settings-screen readability fixes, and bounded process-flow improvements for detection progress feedback without introducing meaningful runtime overhead or changing core detection behavior.

This pass includes the 10 user-approved adjustments discussed on April 1, 2026. The hard item remains in scope, but it is explicitly narrowed to lightweight phase-status plus counts on the existing detection progress overlay rather than raw Flask terminal log streaming.

---

## Scope For This Pass

**Included**:
- Main UI header alignment and emphasis for `div.fheader`
- Removal of the `About TowerScout` link from `div#fversion`
- Balanced same-row button spacing refinements for `#fadd` and `#fsave`
- Hover hint text for export buttons in `#fsave`
- Corner-radius consistency for `Circle`, `Custom shape`, and `Clear` search controls
- Settings modal copy and link-contrast refinements for the resource section
- Longer timeout for polygon-complete notifications only
- Detection progress overlay enhancements using structured phase status plus counts

**Explicitly Excluded**:
- Raw Flask terminal output mirroring in the browser
- Per-tile or per-detection UI log spam during active detection
- Frequent progress writes into Flask cookie-backed session state
- Broad notification-duration changes outside the polygon-complete messages
- New workflow redesign outside the listed adjustments
- Any change to model thresholds, model weights, or detection-selection behavior

---

## Key Decisions

1. Keep TASK-047 as a Type A polish task, but use a dedicated task document because the approved scope now spans UI, UX, and bounded backend progress plumbing.
2. Use an impact-first sequence: low-risk visual polish first, then notification timing, then the bounded progress-overlay enhancement.
3. Preserve equal-width, single-row button layouts for both `#fadd` and `#fsave`; create spacing by reducing visual bulk and adding explicit gaps rather than switching to content-width buttons or wrapping.
4. Extend only the two polygon-complete notifications. Leave the global notification default unchanged.
5. Implement item 10 as coarse phase-status plus counts with lightweight polling and in-memory tracking, not raw backend log streaming.
6. Add performance guardrails to item 10: no disk-backed live progress logging, no cookie-session writes for progress, no per-tile DOM updates, and no poll interval tighter than `750ms`.

---

## Requirements (EARS Notation)

**R-047-001**: WHEN the main UI renders on desktop, THE SYSTEM SHALL center the `TowerScout` label within `div.fheader` and present it with stronger visual emphasis than the current header styling.

**R-047-002**: WHEN the top-right utility area renders, THE SYSTEM SHALL remove the `About TowerScout` link from `div#fversion` and leave the `Settings` button as the only control in that container.

**R-047-003**: WHEN the manual tower action row renders, THE SYSTEM SHALL keep `Add Towers`, `Save Towers`, `Clear`, and `Clear all` on a single line with balanced equal-width buttons and increased spacing between buttons.

**R-047-004**: WHEN the export action row renders, THE SYSTEM SHALL keep `Download results`, `Download dataset`, and `Restore dataset` on a single line with balanced equal-width buttons and increased spacing between buttons.

**R-047-005**: WHEN users hover the export action buttons, THE SYSTEM SHALL show button-specific hint text explaining each button's purpose.

**R-047-006**: WHEN the search-area controls render in `div.fsearch`, THE SYSTEM SHALL give `Circle`, `Custom shape`, and `Clear` corner radii visually consistent with the rest of the button system without breaking same-row alignment.

**R-047-007**: WHEN the Settings modal renders, THE SYSTEM SHALL rename the `Resources` section heading to `Resource Links`.

**R-047-008**: WHEN resource links render in the Settings modal, THE SYSTEM SHALL display readable white text with accessible hover and focus states against the existing dark modal background.

**R-047-009**: WHEN a polygon-complete notification is shown for either custom search boundaries or manual tower additions, THE SYSTEM SHALL keep that notification visible longer than the default app-notification timeout.

**R-047-010**: WHEN a tower-detection run is active, THE SYSTEM SHALL show structured progress feedback in `div#progress_div` for the current workflow phase and available counts, including at minimum tile preparation, imagery download, model detection, result filtering, geocoding, and finalization.

**R-047-011**: WHEN item 10 is implemented, THE SYSTEM SHALL source progress state from lightweight in-memory tracking keyed to the active session and SHALL NOT stream raw terminal output into the browser.

**R-047-012**: IF live progress data is temporarily unavailable during a detection run, THEN THE SYSTEM SHALL preserve the existing progress bar and cancel workflow instead of blocking the detection request.

**R-047-013**: WHEN the progress overlay updates during detection, THE SYSTEM SHALL avoid meaningful degradation of application responsiveness by using coarse updates, throttled polling, and natural batch/phase boundaries.

---

## Acceptance Criteria

- [ ] `TowerScout` is centered and visibly bolder in `div.fheader` on the desktop main screen.
- [ ] `About TowerScout` is removed from `div#fversion`, leaving only the `Settings` button there.
- [ ] The `#fadd` action row remains a single line with equal-width buttons and clearly increased spacing.
- [ ] The `#fsave` action row remains a single line with equal-width buttons and clearly increased spacing.
- [ ] Each export button shows a meaningful hover title: results export, dataset export, and dataset restore.
- [ ] `Circle`, `Custom shape`, and `Clear` use rounded corners consistent with the rest of the UI button language.
- [ ] The Settings modal section heading reads `Resource Links`.
- [ ] Resource links in Settings are white and remain readable in default, hover, visited, and keyboard-focus states.
- [ ] The polygon-complete notifications for search-area drawing and manual tower drawing use an explicit longer timeout than the default notification timeout.
- [ ] The default global notification timeout remains unchanged for unrelated messages.
- [ ] `div#progress_div` shows a status title and supporting detail text in addition to the existing progress bar and Cancel button.
- [ ] Detection progress feedback covers at least these phases: tile preparation/filtering, imagery download, model detection, boundary/result filtering, geocoding, and finalization.
- [ ] Model-detection progress reports counts at batch level, not raw tile-by-tile console messages.
- [ ] Geocoding progress reports coarse counts and does not flood the UI with per-address updates.
- [ ] Progress polling is throttled to a bounded interval of about `750ms` and stops when detection completes, fails, or is cancelled.
- [ ] Existing detection cancel behavior continues to work.
- [ ] No model thresholds, model outputs, export formats, or review-mode behavior regress as part of this pass.

---

## Dependencies

- Sprint 04 sequencing and active-task tracking in `.agent_work/current-tasks.md`
- Existing setup/settings UI from `TASK-046`
- Existing notification system in `webapp/js/src/managers/ErrorHandler.js`
- Existing progress overlay and detection workflow in `webapp/js/src/ui/search.js`
- Existing detection batch processing in `webapp/ts_yolov5.py`

---

## Files Likely To Change

- `webapp/templates/towerscout.html`
- `webapp/css/ts_styles.css`
- `webapp/css/ts_styles_mobile.css` if any shared selector change creates a mobile regression
- `webapp/js/src/providers/GoogleMap.js`
- `webapp/js/src/providers/AzureMap.js`
- `webapp/js/src/ui/search.js`
- `webapp/towerscout.py`
- `webapp/ts_yolov5.py`
- `webapp/ts_events.py` or a new lightweight progress-tracking module if a separate file is cleaner

---

## Implementation Plan

### Phase 1: Main UI Polish
- Center and strengthen `div.fheader` styling in desktop CSS without changing the existing grid layout.
- Remove the `About TowerScout` link markup from `div#fversion` and keep the Settings button right-aligned.
- Refine `#fadd` and `#fsave` rows so their buttons stay equal-width on one line, but use slightly lighter padding and explicit `gap` spacing between buttons.
- Add descriptive `title` attributes to each export button in `#fsave`.
- Apply rounded-corner styling to the `Circle`, `Custom shape`, and `Clear` buttons so they visually match the other action buttons while preserving the current same-row search layout.

### Phase 2: Settings Readability Polish
- Rename the Settings section header from `Resources` to `Resource Links` in `webapp/templates/towerscout.html`.
- Add resource-link color styling in `webapp/css/ts_styles.css` for normal, visited, hover, and focus-visible states so link text remains white/readable against the modal background.
- Keep the existing modal structure and save flow unchanged.

### Phase 3: Notification Timing Adjustment
- Update only the polygon-complete notifications in `webapp/js/src/providers/GoogleMap.js` and `webapp/js/src/providers/AzureMap.js` to use an explicit longer timeout.
- Default assumption for this pass: use `9000ms` for those two completion notices.
- Leave all other `TowerScoutErrorHandler.showUserNotification(...)` calls at their current timing unless they are the two approved polygon-complete messages.

### Phase 4: Detection Progress Overlay Enhancement
- Add a lightweight, thread-safe progress tracker keyed by session ID.
- Preferred implementation shape:
  - either extend `webapp/ts_events.py` with progress-state storage in a separate structure
  - or add a small dedicated module such as `webapp/ts_progress.py` if that keeps the responsibilities cleaner
- Add a read-only backend endpoint such as `GET /api/detection/progress` that returns the current structured state for the active session.
- Update `webapp/towerscout.py` to set coarse-grained status transitions at natural points in `/getobjects`:
  - `preparing_tiles`
  - `tiles_filtered`
  - `downloading_imagery`
  - `running_model`
  - `filtering_results`
  - `geocoding`
  - `finalizing`
  - `complete`
  - `cancelled`
  - `error`
- Include counts where naturally available:
  - candidate and retained tile counts after filtering
  - model batches completed / total batches and processed tile count
  - raw detection count after model output
  - inside / outside / retained counts after filtering and dedupe
  - geocoding processed / total counts, updated only every 10 detections and at completion
- Update `webapp/ts_yolov5.py` to accept an optional progress callback so model status can advance once per completed batch rather than once per tile.
- Extend `div#progress_div` in `webapp/templates/towerscout.html` with status-title and detail-text placeholders beneath the existing progress bar.
- Update `webapp/js/src/ui/search.js` so:
  - `enableProgress()` starts a throttled poll loop against the new progress endpoint
  - `disableProgress()` stops that poll loop on success, cancel, or failure
  - the existing estimated progress bar remains intact
  - the overlay shows structured phase text and counts rather than raw console output
- Preserve the Cancel button and existing `/abort` flow.

### Phase 5: Validation
- Rebuild the frontend bundle with `node webapp/build.js`.
- Run `node --check` on touched frontend source files.
- Run `C:\Users\bg90\TowerScout\.venv\Scripts\python.exe -m py_compile` on touched backend modules.
- Add or update targeted automated coverage for the progress-tracker state transitions if a new module or callback path is introduced.
- Perform browser smoke checks for:
  - desktop main-screen header/button/layout changes
  - Settings modal heading and link contrast
  - polygon-complete notices for both Google and Azure drawing workflows
  - detection start, live phase updates, cancellation, and successful completion
- Confirm item 10 does not visibly slow tile estimation or full detection in ordinary use.

---

## Performance Guardrails For Item 10

- Do not write live progress into Flask `session`, because TowerScout uses signed cookie-backed sessions.
- Do not write progress updates to disk or reuse raw Flask console output as the browser payload.
- Do not update progress UI more frequently than the polling interval.
- Update model progress at batch boundaries only.
- Update geocoding progress only at coarse checkpoints (`every 10 detections`, plus final update).
- If the live-status path fails, fall back to the current progress bar and finish the request normally.

---

## Risks And Watchpoints

- The progress-overlay enhancement is the only meaningful regression risk in this task because it touches backend/frontend coordination instead of pure CSS.
- `div#progress_div` currently contains only the progress bar and Cancel button, so markup and JS changes must preserve the current cancel affordance.
- Any status-tracking implementation that writes into cookie-backed sessions or emits per-tile UI updates would violate the performance intent of this task.
- Main-screen spacing changes must be checked on both Google and Azure providers because the right-column layout already has several tightly packed action rows.

---

## Implementation Log

### TYPE A - TASK-047 DOCUMENTATION AND SCOPE LOCK - 2026-04-01 11:00 EDT
**Objective**: Translate the approved April 1 adjustment list into a dedicated, implementation-ready TASK-047 document without starting code changes.
**Context**: TASK-047 was still open-ended in Sprint 04 tracking. The user then supplied 10 concrete requests across Main UI Screen, Settings Screen, and Process Flow/User Experience, including one harder progress-feedback enhancement.
**Decision**: Keep TASK-047 scoped to the approved list, treat item 10 as structured phase-status plus counts instead of raw log streaming, and add explicit performance guardrails so the later implementation does not harm model responsiveness.
**Execution**: Created `.agent_work/tasks/TASK-047-ui-formatting-and-polish.md` with scope, requirements, acceptance criteria, implementation phases, and validation guidance. Synced `.agent_work/current-tasks.md` so Sprint 04 tracking points to this task document.
**Output**: TASK-047 now has a dedicated task file and a decision-complete implementation scope.
**Validation**: Documentation review only; no code or runtime behavior changed in this step.
**Next**: Start implementation when ready, beginning with the low-risk main-screen and settings-screen polish before the bounded progress-overlay enhancement.
