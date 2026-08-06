#!/usr/bin/env python3
"""Collect a read-only TowerScout monthly reporting evidence inventory."""

from __future__ import annotations

import argparse
import calendar
import re
import subprocess
import sys
from datetime import date, datetime, timedelta
from pathlib import Path


TASK_HEADING = re.compile(r"^###\s+\*{0,2}(TASK-\d+):?\s*(.*?)\*{0,2}\s*$")
STATUS_LINE = re.compile(r"^\*\*Status\*\*:\s*(.+)$")
RELEVANT_PREFIXES = (
    ".agent_work/",
    ".github/",
    "docs/",
    "scripts/",
    "tests/",
)
RELEVANT_FILES = {
    "README.md",
    "Dockerfile",
    "compose.yaml",
    "compose.build.yaml",
    "release-manifest.v1.json",
}
EVIDENCE_TERMS = (
    "completed",
    "current-task",
    "backlog",
    "retrospective",
    "roadmap",
    "status",
    "decision",
    "pilot",
    "uat",
    "user-testing",
    "handoff",
    "release",
    "validation",
    "evidence",
    "runlog",
    "quick-start",
    "user-guide",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Print a read-only monthly evidence inventory for TowerScout."
    )
    parser.add_argument("--repo", default=".", help="TowerScout repository root.")
    parser.add_argument(
        "--month",
        help="Reporting month in YYYY-MM format; defaults to the as-of month.",
    )
    parser.add_argument(
        "--as-of",
        help="Evidence cutoff in YYYY-MM-DD format; defaults to today.",
    )
    parser.add_argument(
        "--max-commits",
        type=int,
        default=200,
        help="Maximum commits to print per git section.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=100,
        help="Maximum changed evidence files to print.",
    )
    parser.add_argument(
        "--max-tasks",
        type=int,
        default=50,
        help="Maximum task-status entries to print per snapshot.",
    )
    return parser.parse_args()


def parse_iso_date(value: str | None, label: str) -> date:
    if value is None:
        return date.today()
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError(f"{label} must use YYYY-MM-DD: {value}") from exc


def parse_month(value: str | None, as_of: date) -> tuple[int, int]:
    if value is None:
        return as_of.year, as_of.month
    try:
        parsed = datetime.strptime(value, "%Y-%m")
    except ValueError as exc:
        raise ValueError(f"--month must use YYYY-MM: {value}") from exc
    return parsed.year, parsed.month


def month_bounds(year: int, month: int, as_of: date) -> tuple[date, date]:
    start = date(year, month, 1)
    last = date(year, month, calendar.monthrange(year, month)[1])
    if start > as_of:
        raise ValueError("reporting month cannot start after the --as-of date")
    return start, min(last, as_of)


def next_month_bounds(year: int, month: int) -> tuple[date, date]:
    if month == 12:
        next_year, next_month = year + 1, 1
    else:
        next_year, next_month = year, month + 1
    start = date(next_year, next_month, 1)
    end = date(
        next_year,
        next_month,
        calendar.monthrange(next_year, next_month)[1],
    )
    return start, end


def run_git(repo: Path, *args: str, check: bool = True) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout.strip()


def git_ref_exists(repo: Path, ref: str) -> bool:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", ref],
        cwd=repo,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def period_args(start: date, end: date) -> list[str]:
    exclusive_end = end + timedelta(days=1)
    return [
        f"--since={start.isoformat()} 00:00:00",
        f"--until={exclusive_end.isoformat()} 00:00:00",
    ]


def split_nonempty(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def limited(lines: list[str], maximum: int) -> list[str]:
    if len(lines) <= maximum:
        return lines
    return [*lines[:maximum], f"... {len(lines) - maximum} additional entries omitted"]


def extract_task_statuses_from_text(content: str) -> list[tuple[str, str]]:
    lines = content.splitlines()
    results: list[tuple[str, str]] = []
    for index, line in enumerate(lines):
        heading = TASK_HEADING.match(line.strip())
        if not heading:
            continue
        task_id = heading.group(1)
        title = heading.group(2).strip().strip("*")
        title = re.sub(r"\*{2}\s*✅?\s*$", "", title).strip()
        task_name = f"{task_id}: {title}" if title else task_id
        for status_index in range(index + 1, min(index + 12, len(lines))):
            status = STATUS_LINE.match(lines[status_index].strip())
            if not status:
                continue
            fragments = [status.group(1).strip()]
            continuation_index = status_index + 1
            while continuation_index < len(lines):
                continuation = lines[continuation_index].strip()
                if (
                    not continuation
                    or continuation.startswith("#")
                    or continuation.startswith("**")
                ):
                    break
                fragments.append(continuation)
                continuation_index += 1
            results.append((task_name, " ".join(fragments)))
            break
    return results


def extract_task_statuses(path: Path) -> list[tuple[str, str]]:
    if not path.exists():
        return []
    content = path.read_text(encoding="utf-8", errors="replace")
    return extract_task_statuses_from_text(content)


def extract_git_task_statuses(repo: Path, ref: str, path: str) -> list[tuple[str, str]]:
    content = run_git(repo, "show", f"{ref}:{path}", check=False)
    return extract_task_statuses_from_text(content)


def is_relevant(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return normalized in RELEVANT_FILES or normalized.startswith(RELEVANT_PREFIXES)


def evidence_priority(path: str) -> tuple[int, str]:
    lowered = path.lower()
    score = sum(term in lowered for term in EVIDENCE_TERMS)
    return (-score, lowered)


def print_lines(lines: list[str], empty_text: str = "None found.") -> None:
    if not lines:
        print(f"- {empty_text}")
        return
    for line in lines:
        print(f"- {line}")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    args = parse_args()
    try:
        as_of = parse_iso_date(args.as_of, "--as-of")
        year, month = parse_month(args.month, as_of)
        start, end = month_bounds(year, month, as_of)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    repo = Path(args.repo).resolve()
    if not (repo / ".git").exists():
        print(f"error: not a git repository root: {repo}", file=sys.stderr)
        return 2

    try:
        branch = run_git(repo, "branch", "--show-current") or "(detached HEAD)"
        status = split_nonempty(run_git(repo, "status", "--short"))
        dates = period_args(start, end)
        log_format = "--pretty=format:%h|%ad|%D|%s"
        all_commits = split_nonempty(
            run_git(
                repo,
                "log",
                "--branches",
                "--tags",
                *dates,
                "--date=short",
                log_format,
            )
        )
        main_commits: list[str] = []
        branch_only: list[str] = []
        main_cutoff = ""
        if git_ref_exists(repo, "main"):
            main_commits = split_nonempty(
                run_git(repo, "log", "main", *dates, "--date=short", log_format)
            )
            branch_only = split_nonempty(
                run_git(repo, "log", "main..HEAD", *dates, "--date=short", log_format)
            )
            main_cutoff = run_git(
                repo,
                "rev-list",
                "-1",
                f"--before={end.isoformat()} 23:59:59",
                "main",
                check=False,
            )
        changed = split_nonempty(
            run_git(
                repo,
                "log",
                "--branches",
                "--tags",
                *dates,
                "--name-only",
                "--pretty=format:",
            )
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    relevant_changed = sorted(
        {path.replace("\\", "/") for path in changed if is_relevant(path)},
        key=evidence_priority,
    )
    next_start, next_end = next_month_bounds(year, month)

    print("# TowerScout Monthly Evidence Inventory")
    print()
    print(f"- Repository: `{repo}`")
    print(f"- Reporting period: {start.isoformat()} through {end.isoformat()}")
    print(
        f"- Next-month planning window: {next_start.isoformat()} through "
        f"{next_end.isoformat()}"
    )
    print(f"- Evidence cutoff: {as_of.isoformat()}")
    print(f"- Current branch: `{branch}`")
    print()
    print("## Evidence cautions")
    print()
    print("- Commit inventory includes local branches and tags, but excludes stashes.")
    print("- Current-branch work must be distinguished from work merged to `main`.")
    print("- Uncommitted files are supporting context, not completed evidence.")
    print("- Current worktree task state is present-day context, not a historical snapshot.")
    print("- Read the underlying task and validation records before drafting claims.")
    print()
    print("## Worktree state")
    print()
    print_lines(status, "Clean.")
    print()
    print("## Reporting-period commits on local branches and tags")
    print()
    print_lines(limited(all_commits, args.max_commits))
    print()
    print("## Reporting-period commits reachable from main")
    print()
    print_lines(limited(main_commits, args.max_commits), "`main` not found or no commits.")
    print()
    print("## Reporting-period current-branch commits not on main")
    print()
    print_lines(limited(branch_only, args.max_commits))
    print()
    print("## Main task snapshot at the reporting cutoff")
    print()
    if main_cutoff:
        print(f"- Main cutoff commit: `{main_cutoff[:12]}`")
        cutoff_current = extract_git_task_statuses(
            repo, main_cutoff, ".agent_work/current-tasks.md"
        )
        print_lines(
            limited(
                [f"{task} - {status_text}" for task, status_text in cutoff_current],
                args.max_tasks,
            )
        )
    else:
        print("- No `main` cutoff commit found.")
    print()
    print("## Main completed-task snapshot at the reporting cutoff")
    print()
    if main_cutoff:
        cutoff_completed = extract_git_task_statuses(
            repo, main_cutoff, ".agent_work/completed-tasks.md"
        )
        print_lines(
            limited(
                [f"{task} - {status_text}" for task, status_text in cutoff_completed],
                args.max_tasks,
            )
        )
    else:
        print("- No `main` cutoff commit found.")
    print()
    print("## Current worktree task snapshot")
    print()
    current = extract_task_statuses(repo / ".agent_work" / "current-tasks.md")
    print_lines(
        limited(
            [f"{task} - {status_text}" for task, status_text in current],
            args.max_tasks,
        )
    )
    print()
    print("## Current worktree completed-task snapshot")
    print()
    completed = extract_task_statuses(repo / ".agent_work" / "completed-tasks.md")
    print_lines(
        limited(
            [f"{task} - {status_text}" for task, status_text in completed],
            args.max_tasks,
        )
    )
    print()
    print("## Changed reporting and evidence files")
    print()
    print_lines(limited(relevant_changed, args.max_files))
    print()
    print("## Canonical sources to inspect")
    print()
    canonical = [
        ".github/copilot-instructions.md",
        ".agent_work/current-tasks.md",
        ".agent_work/task-backlog.md",
        ".agent_work/completed-tasks.md",
    ]
    for relative in canonical:
        state = "present" if (repo / relative).exists() else "missing"
        print(f"- `{relative}` - {state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
