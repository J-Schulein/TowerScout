from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

try:
    from .inspect_build import inspect_build
except ImportError:  # Direct execution: python launcher/build_provenance.py
    from inspect_build import inspect_build


PROVENANCE_FILENAME = "BUILD-PROVENANCE.v1.json"
PROVENANCE_SCHEMA_VERSION = 1
BUILD_TREE_HASH_CONTRACT = "sha256-path-null-content-sha256-v1"
SOURCE_REF_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validated_source_ref(source_ref: str) -> str:
    normalized = source_ref.strip().lower()
    if not SOURCE_REF_PATTERN.fullmatch(normalized):
        raise ValueError("Source ref must be a full 40-character Git commit SHA.")
    return normalized


def _clean_git_source_ref(repo_root: Path) -> str:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError(
            "Unable to resolve the launcher build source ref."
        ) from error
    if status:
        raise RuntimeError(
            "Launcher provenance must be generated from a clean Git worktree."
        )
    return _validated_source_ref(commit)


def build_tree_sha256(build_dir: Path) -> str:
    if build_dir.is_symlink():
        raise ValueError("Launcher build must not contain symbolic links.")
    build_dir = build_dir.resolve()
    if not build_dir.is_dir():
        raise ValueError("Launcher build directory does not exist.")
    if build_dir.is_symlink() or any(
        path.is_symlink() for path in build_dir.rglob("*")
    ):
        raise ValueError("Launcher build must not contain symbolic links.")

    files: list[tuple[str, Path]] = []
    casefolded: set[str] = set()
    for path in build_dir.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(build_dir).as_posix()
        if relative == PROVENANCE_FILENAME:
            continue
        folded = relative.casefold()
        if folded in casefolded:
            raise ValueError("Launcher build contains case-colliding file paths.")
        casefolded.add(folded)
        files.append((relative, path))

    digest = hashlib.sha256()
    digest.update(BUILD_TREE_HASH_CONTRACT.encode("ascii") + b"\0")
    for relative, path in sorted(files, key=lambda item: item[0].casefold()):
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
        digest.update(b"\0")
    return digest.hexdigest()


def create_build_provenance_payload(
    *, repo_root: Path, build_dir: Path, source_ref: str
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    if build_dir.is_symlink():
        raise ValueError("Launcher build must not contain symbolic links.")
    build_dir = build_dir.resolve()
    source_ref = _validated_source_ref(source_ref)
    if not repo_root.is_dir():
        raise ValueError("Repository root does not exist.")

    errors = inspect_build(build_dir)
    if errors:
        raise ValueError("Launcher build inspection failed: " + "; ".join(errors))
    tk_license = build_dir / "_internal" / "_tk_data" / "license.terms"
    if not tk_license.is_file():
        raise ValueError("Launcher build is missing the bundled Tcl/Tk license.")
    requirements_path = repo_root / "launcher" / "requirements-build.txt"
    if not requirements_path.is_file():
        raise ValueError("Launcher build requirements file is missing.")

    return {
        "build_tree_hash_contract": BUILD_TREE_HASH_CONTRACT,
        "build_tree_sha256": build_tree_sha256(build_dir),
        "launcher_executable_sha256": sha256_file(build_dir / "TowerScoutLauncher.exe"),
        "requirements_build_sha256": sha256_file(requirements_path),
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "source_ref": source_ref,
    }


def write_build_provenance(*, repo_root: Path, build_dir: Path) -> dict[str, object]:
    repo_root = repo_root.resolve()
    if build_dir.is_symlink():
        raise ValueError("Launcher build must not contain symbolic links.")
    build_dir = build_dir.resolve()
    source_ref = _clean_git_source_ref(repo_root)
    payload = create_build_provenance_payload(
        repo_root=repo_root,
        build_dir=build_dir,
        source_ref=source_ref,
    )
    destination = build_dir / PROVENANCE_FILENAME
    temporary = build_dir / f".{PROVENANCE_FILENAME}.{uuid.uuid4().hex}.tmp"
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return payload


def verify_build_provenance(
    *, repo_root: Path, build_dir: Path, expected_source_ref: str
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    if build_dir.is_symlink():
        raise ValueError("Launcher build must not contain symbolic links.")
    build_dir = build_dir.resolve()
    expected_source_ref = _validated_source_ref(expected_source_ref)
    path = build_dir / PROVENANCE_FILENAME
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Launcher build provenance is missing or invalid.") from error
    if not isinstance(payload, dict):
        raise ValueError("Launcher build provenance must contain a JSON object.")

    required_fields = {
        "build_tree_hash_contract",
        "build_tree_sha256",
        "launcher_executable_sha256",
        "requirements_build_sha256",
        "schema_version",
        "source_ref",
    }
    if set(payload) != required_fields:
        raise ValueError("Launcher build provenance fields are invalid.")
    if payload.get("schema_version") != PROVENANCE_SCHEMA_VERSION:
        raise ValueError("Launcher build provenance schema is unsupported.")
    if payload.get("build_tree_hash_contract") != BUILD_TREE_HASH_CONTRACT:
        raise ValueError("Launcher build provenance tree-hash contract is unsupported.")
    if payload.get("source_ref") != expected_source_ref:
        raise ValueError("Launcher build provenance source ref does not match.")

    for field in (
        "build_tree_sha256",
        "launcher_executable_sha256",
        "requirements_build_sha256",
    ):
        value = payload.get(field)
        if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
            raise ValueError(f"Launcher build provenance {field} is invalid.")

    requirements_path = repo_root / "launcher" / "requirements-build.txt"
    if not requirements_path.is_file():
        raise ValueError("Launcher build requirements file is missing.")
    if payload["requirements_build_sha256"] != sha256_file(requirements_path):
        raise ValueError("Launcher build provenance requirements SHA-256 mismatch.")
    if payload["launcher_executable_sha256"] != sha256_file(
        build_dir / "TowerScoutLauncher.exe"
    ):
        raise ValueError("Launcher build provenance executable SHA-256 mismatch.")
    if payload["build_tree_sha256"] != build_tree_sha256(build_dir):
        raise ValueError("Launcher build provenance tree SHA-256 mismatch.")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Record exact-source provenance for a TowerScout launcher build."
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path("dist/TowerScoutLauncher"),
    )
    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        payload = write_build_provenance(
            repo_root=repo_root,
            build_dir=args.build_dir,
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Launcher build provenance failed: {error}", file=sys.stderr)
        return 1
    print(f"Launcher build provenance: {args.build_dir / PROVENANCE_FILENAME}")
    print(f"Source ref: {payload['source_ref']}")
    print(f"Build tree SHA-256: {payload['build_tree_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
