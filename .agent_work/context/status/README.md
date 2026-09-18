# Current Status Sources

Only live project-wide status and planning material belongs here.

Current navigation:

- [`../../decisions/018-task-087-windows-launcher-feasibility-pivot.md`](../../decisions/018-task-087-windows-launcher-feasibility-pivot.md)
  retains the Task-087 launcher security and validation-only artifact boundary.
- [`../../decisions/019-unsigned-preview-and-october-production-signing.md`](../../decisions/019-unsigned-preview-and-october-production-signing.md)
  controls the August 19 Proceed-to-preview disposition, unsigned
  `v0.1.3-preview.N` line, and October Task-100 signing sequence.
- [`../../decisions/020-task-101-node-puppeteer-security-baseline.md`](../../decisions/020-task-101-node-puppeteer-security-baseline.md)
  records the completed Node/Puppeteer security baseline and Task-101's
  no-exception, no-dismissal disposition.
- [`../../tasks/active/TASK-087/FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md`](../../tasks/active/TASK-087/FULL-PACKAGE-VALIDATION-EVIDENCE-2026-08-05.md)
  is the current functional record for source-bound unsigned validation-only
  packages. Later entries cover packaged Docker and approved-provider Podman
  Google/Azure repair, controlled recovery, provider-installer reproducibility,
  and rootless-Podman enforcement. Those artifacts remain nonpublishable. The
  Task-101 remediation/default-branch gate passed without exception or
  dismissal, and PR #67 reconciliation head `946deaf` passed exact-head CI/CD
  run `32383065903` plus Task-087 run `32383065959`. Task-101 is complete and
  Task-087 is explicitly resumed. Lifecycle head `6e0f744` passed CI/CD run
  `32385304086` and Task-087 run `32385304052`. Independent technical/security
  review then requested source changes, so Task-087 is active but review-
  remediation-gated and PR #67 remains Draft. Source remediation and exact-head
  re-review precede a newly integrated normal-user preview package; merge and
  publication retain separate gates. Task-100 owns October signing and
  representative endpoint qualification.
- [`../../tasks/active/TASK-087/TECHNICAL-SECURITY-REMEDIATION-DESIGN-2026-08-20.md`](../../tasks/active/TASK-087/TECHNICAL-SECURITY-REMEDIATION-DESIGN-2026-08-20.md)
  is the current exact-target, durable-recovery, Windows trust/filesystem, and
  preview-integrity design checkpoint. The project lead approved Gate A
  IMPLEMENT on August 21; live mutation and later artifact/release gates remain
  separately controlled.
- [`../../tasks/active/TASK-087/REVIEW-EVIDENCE-2026-08-05.md`](../../tasks/active/TASK-087/REVIEW-EVIDENCE-2026-08-05.md)
  is preserved as the historical preview-only static technical-review packet;
  it is not the current functional result.

- [`Handoff-Planning/`](./Handoff-Planning/) contains the canonical October
  roadmap, the unchanged `v0.1.2` Pilot track, Pilot custody, and active Pilot
  validation evidence.

Completed PR reviews, execution packets, superseded plans, and old release
checklists belong under [`../archive/`](../archive/).

The superseded August 4 Task-087 pivot requests are archived under
[`../archive/2026-08/`](../archive/2026-08/); ADR-018 is the controlling
security-boundary decision, while ADR-019 controls current release sequencing.
