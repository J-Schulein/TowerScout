---
name: towerscout-monthly-leadership-reporting
description: Draft evidence-backed TowerScout monthly leadership reporting from repository history and project records. Use for Technical Status Meeting (TSM) updates, Monthly Status Report (MSR) workstream activity, monthly accomplishments, upcoming milestones, executive status summaries, or a biggest-success story for a requested calendar month.
---

# TowerScout Monthly Leadership Reporting

## Goal

Turn one month of TowerScout repository evidence into concise, aligned,
leadership-facing TSM and MSR content without requiring the user to restate the
project context or reporting format.

Use this as the primary TowerScout skill for monthly leadership reporting.
Consult other TowerScout skills only when a report claim requires a focused
secondary check; do not run every domain skill.

## Resolve the reporting period

1. Use an explicitly named month when provided.
2. Interpret "last month" or "past month" as the previous completed calendar
   month.
3. Interpret "this month" or an unspecified monthly request as the current
   month through today's date.
4. State the evidence cutoff when the reporting month is incomplete.
5. Treat the next calendar month after the reporting period as the upcoming-task
   horizon unless the user supplies another horizon.

Do not ask for dates when these rules resolve the request safely.

## Collect the evidence

Run the read-only inventory first:

```powershell
python -B .agents/skills/towerscout-monthly-leadership-reporting/scripts/collect_monthly_evidence.py --repo . --month YYYY-MM --as-of YYYY-MM-DD
```

Then inspect the relevant underlying records rather than reporting from commit
subjects alone:

1. Read `.github/copilot-instructions.md` for current project context.
2. Read `.agent_work/current-tasks.md`, `.agent_work/task-backlog.md`, and
   `.agent_work/completed-tasks.md`.
3. Inspect monthly commits and the changed task, retrospective, decision,
   status, UAT, pilot, release, and validation files identified by the
   inventory.
4. Read detailed task files for candidate accomplishments and blockers.
5. Read validation summaries before claiming that a runtime, provider,
   release, or user workflow passed.
6. Read the current canonical roadmap for upcoming milestones, approvals,
   validation gates, and decision points.

Use local repository evidence by default. Use GitHub or another external source
only when the user requests live remote state or a local record explicitly
depends on it.

## Reconcile status before writing

Classify each candidate item as one of:

- released, distributed, or completed
- validated but not released
- merged but still gated
- in progress on the current branch
- planned or milestone-gated
- blocked or owner-gated

Apply these rules:

- Use git history and dated evidence for when work occurred.
- Use `completed-tasks.md` and retrospectives for completion claims.
- Use `current-tasks.md` and detailed active task files for current status.
- Use the backlog and canonical roadmap for upcoming work.
- Distinguish `main` from current-branch work.
- Treat uncommitted files as supporting context, not authoritative completed
  evidence, unless the user explicitly directs otherwise.
- Do not count stashes as reporting-period accomplishments.
- Do not describe scanner findings as incidents or independent application
  defects.
- Preserve qualified limitations, pending external validation, residual-risk
  decisions, and owner approvals.
- Never expose provider keys, local areas of interest, raw support logs,
  screenshots, or other sensitive evidence.

When records conflict, report the most conservative evidence-backed state and
briefly note the discrepancy if it affects leadership interpretation.

## Select leadership workstreams

Choose five or six workstreams that best represent:

- delivery or pilot/user outcomes
- release or milestone progress
- validated reliability or portability
- security or operational-risk reduction
- user testing, documentation, or support readiness
- ownership, governance, or decision readiness

Favor outcomes over implementation volume. Combine related commits and tasks
into one workstream, and do not elevate routine maintenance unless it changed a
material risk, milestone, or user outcome.

Select the biggest success story from the strongest concrete delivered or
validated outcome. Prefer a user-visible result over an enabling decision such
as a schedule extension, while using the enabling decision as context when it
increased the value or durability of the result.

## Write the report

Read
[`references/leadership-report-template.md`](references/leadership-report-template.md)
before drafting and follow it exactly for requested sections.

Keep the language:

- concise, outcome-focused, and suitable for leaders outside daily
  implementation
- specific enough to show meaningful progress and impact
- clear about what is complete, qualified, pending, or owner-gated
- free of task IDs, commit hashes, package internals, and test counts unless a
  detail materially strengthens the leadership message

Produce report text in the response by default. Do not create or update a
repository status file unless the user asks to save the report.

## Final checks

Before returning the report:

1. Confirm every TSM workstream title appears in the MSR in the same order.
2. Confirm each TSM update is one concise sentence.
3. Confirm each MSR workstream has exactly the three requested bullets.
4. Confirm upcoming tasks fall within the requested horizon and cite a
   milestone, gate, approval, validation, or decision where possible.
5. Confirm no in-progress or branch-only work is described as released.
6. Confirm the success story is a concrete result and its description and
   impact are brief.
