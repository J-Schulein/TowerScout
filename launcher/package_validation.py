from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

try:
    from .build_provenance import verify_build_provenance
    from .inspect_build import inspect_build
except ImportError:  # Direct execution: python launcher/package_validation.py
    from build_provenance import verify_build_provenance
    from inspect_build import inspect_build


SOURCE_REF_PATTERN = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN_PACKAGE_SUFFIXES = {".bat", ".cmd", ".key", ".pem", ".ps1"}
FULL_PACKAGE_FORBIDDEN_SUFFIXES = {
    ".cer",
    ".crt",
    ".der",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
}
FULL_PACKAGE_REQUIRED_FILES = {
    ".env.example",
    "SHA256SUMS.txt",
    "SOURCE.txt",
    "bootstrap.cmd",
    "compose.gpu.podman.yaml",
    "compose.gpu.yaml",
    "compose.yaml",
    "release-manifest.v1.json",
    "scripts/bootstrap.ps1",
    "scripts/import-assets.cmd",
    "scripts/import-assets.ps1",
    "scripts/import-tls-ca.cmd",
    "scripts/import-tls-ca.ps1",
    "scripts/launch.ps1",
    "scripts/lib/TowerScoutBootstrap.ps1",
    "scripts/lib/TowerScoutCertificateStore.ps1",
    "scripts/lib/TowerScoutCompose.ps1",
    "scripts/logs.cmd",
    "scripts/logs.ps1",
    "scripts/repair-provider-tls.cmd",
    "scripts/repair-provider-tls.ps1",
    "scripts/setup-towerscout.ps1",
    "scripts/start.cmd",
    "scripts/start.ps1",
    "scripts/status.cmd",
    "scripts/status.ps1",
    "scripts/stop.cmd",
    "scripts/stop.ps1",
    "setup-towerscout.cmd",
    "start.bat",
    "webapp/asset_manifest.v1.json",
}
FULL_PACKAGE_PREEXISTING_OVERLAY_FILES = {
    "LAUNCHER-PROVENANCE.txt",
    "VALIDATION-ONLY.txt",
    "validation-manifest.v1.json",
}
PACKAGE_KIND_LAUNCHER_POLICY = "launcher-policy"
PACKAGE_KIND_FULL_RUNNABLE = "full-runnable"
FULL_PACKAGE_PURPOSE = "task-087-full-package-functional-validation-only"
SENSITIVE_ENV_NAME = re.compile(
    r"(?:^|_)(?:API_KEY|KEY|PASSWORD|SECRET|TOKEN)$", re.IGNORECASE
)
COMPOSE_PROJECT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ValidationPackageResult:
    identity: str
    source_ref: str
    package_dir: Path
    archive_path: Path
    archive_sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _validated_source_ref(source_ref: str) -> str:
    normalized = source_ref.strip().lower()
    if not SOURCE_REF_PATTERN.fullmatch(normalized):
        raise ValueError("Source ref must be a full 40-character Git commit SHA.")
    return normalized


def _generated_utc(generated_at: datetime | None) -> str:
    value = generated_at or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_json_object(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON.") from error
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must contain a JSON object.")
    return payload


def _assert_no_symlinks(root: Path, label: str) -> None:
    if root.is_symlink() or any(path.is_symlink() for path in root.rglob("*")):
        raise ValueError(f"{label} must not contain symbolic links.")


def _safe_checksum_relative_path(value: str) -> str:
    if "\\" in value or ":" in value:
        raise ValueError("Package checksum contains an unsafe path.")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != value
    ):
        raise ValueError("Package checksum contains an unsafe path.")
    return value


def _verify_checksums(package_dir: Path) -> None:
    checksum_path = package_dir / "SHA256SUMS.txt"
    try:
        lines = checksum_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError("Base package checksums are unreadable.") from error

    recorded: dict[str, str] = {}
    casefolded: set[str] = set()
    for line in lines:
        if not line:
            continue
        parts = line.split("  ", 1)
        if len(parts) != 2 or not SHA256_PATTERN.fullmatch(parts[0]):
            raise ValueError("Base package checksum format is invalid.")
        relative = _safe_checksum_relative_path(parts[1])
        if relative.casefold() in casefolded:
            raise ValueError("Base package checksums contain a duplicate path.")
        casefolded.add(relative.casefold())
        recorded[relative] = parts[0]

    expected = {
        path.relative_to(package_dir).as_posix()
        for path in package_dir.rglob("*")
        if path.is_file() and path != checksum_path
    }
    if set(recorded) != expected:
        raise ValueError("Base package checksums do not cover exactly every file.")
    for relative, expected_hash in recorded.items():
        candidate = package_dir.joinpath(*PurePosixPath(relative).parts)
        if _sha256(candidate) != expected_hash:
            raise ValueError(f"Base package checksum mismatch: {relative}")


def _read_env_assignments(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError("Base package .env.example is unreadable.") from error
    values: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        name = name.strip()
        if name in values:
            raise ValueError(f"Base package .env.example repeats {name}.")
        values[name] = value.strip().strip("\"'")
    return values


def _assert_no_populated_secrets(env_values: dict[str, str]) -> None:
    populated = sorted(
        name
        for name, value in env_values.items()
        if value and SENSITIVE_ENV_NAME.search(name)
    )
    if populated:
        raise ValueError(
            "Base package .env.example contains a populated secret setting: "
            + ", ".join(populated)
        )


def _update_env_example(
    path: Path, *, engine: str, gpu_mode: str, port: int, compose_project: str
) -> None:
    replacements = {
        "COMPOSE_PROJECT_NAME": compose_project,
        "TOWERSCOUT_CONTAINER_ENGINE": engine,
        "TOWERSCOUT_GPU_MODE": gpu_mode,
        "TOWERSCOUT_PORT": str(port),
    }
    lines = path.read_text(encoding="utf-8").splitlines()
    found: set[str] = set()
    updated: list[str] = []
    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            name = line.split("=", 1)[0].strip()
            if name in replacements:
                if name in found:
                    raise ValueError(f"Base package .env.example repeats {name}.")
                found.add(name)
                line = f"{name}={replacements[name]}"
        updated.append(line)
    for name in replacements:
        if name not in found:
            updated.append(f"{name}={replacements[name]}")
    path.write_text("\n".join(updated) + "\n", encoding="utf-8")


def _assert_full_tree_safe(package_dir: Path) -> None:
    _assert_no_symlinks(package_dir, "Full validation package")
    errors: list[str] = []
    for path in package_dir.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(package_dir).as_posix()
        lowered = relative.lower()
        compact = lowered.replace("-", "").replace("_", "")
        name = path.name.lower()
        if name.startswith(".env") and name != ".env.example":
            errors.append(f"live environment file is forbidden: {relative}")
        if path.suffix.lower() in FULL_PACKAGE_FORBIDDEN_SUFFIXES:
            errors.append(f"credential or certificate file is forbidden: {relative}")
        if "hosthelper" in compact:
            errors.append(f"dormant host-helper artifact is forbidden: {relative}")
        if name in {"apikey.txt", "credentials.json", "secrets.json"}:
            errors.append(f"credential file is forbidden: {relative}")
    if errors:
        raise ValueError(
            "Full validation package inspection failed: " + "; ".join(errors)
        )
    _assert_no_populated_secrets(_read_env_assignments(package_dir / ".env.example"))


def _validate_full_profile(
    *, engine: str, gpu_mode: str, port: int, compose_project: str
) -> None:
    if engine not in {"docker", "podman"}:
        raise ValueError("Engine must be one of: docker, podman.")
    if gpu_mode not in {"off", "auto", "on"}:
        raise ValueError("GPU mode must be one of: off, auto, on.")
    if isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    if not COMPOSE_PROJECT_PATTERN.fullmatch(compose_project):
        raise ValueError(
            "Compose project must be 1-63 lowercase letters, numbers, underscores, "
            "or hyphens."
        )


def _validate_full_base(
    base_package_dir: Path, *, source_ref: str, identity: str, gpu_mode: str
) -> dict[str, object]:
    if base_package_dir.name != f"towerscout-{identity}":
        raise ValueError(
            "Base package directory does not match the exact source identity."
        )
    if not base_package_dir.is_dir():
        raise ValueError("Base package directory does not exist.")
    _assert_full_tree_safe(base_package_dir)

    names = {
        path.relative_to(base_package_dir).as_posix()
        for path in base_package_dir.rglob("*")
        if path.is_file()
    }
    missing = sorted(FULL_PACKAGE_REQUIRED_FILES - names)
    if missing:
        raise ValueError(
            "Base package is missing required runnable files: " + ", ".join(missing)
        )
    if (base_package_dir / "launcher").exists() or any(
        (base_package_dir / relative).exists()
        for relative in FULL_PACKAGE_PREEXISTING_OVERLAY_FILES
    ):
        raise ValueError(
            "Base package must be unmodified package-release.ps1 -NoZip output."
        )
    compose = (base_package_dir / "compose.yaml").read_text(encoding="utf-8")
    if not re.search(r"(?m)^services:\s*$", compose) or not re.search(
        r"(?m)^\s{2}towerscout:\s*$", compose
    ):
        raise ValueError(
            "Base package Compose file is not a runnable TowerScout stack."
        )

    manifest = _load_json_object(
        base_package_dir / "release-manifest.v1.json", "Base release manifest"
    )
    if (
        manifest.get("schema_version") != 1
        or manifest.get("release_version") != identity
    ):
        raise ValueError(
            "Base release manifest identity does not match the source commit."
        )
    if manifest.get("track") != "agpl-yolo":
        raise ValueError("Base release manifest track is not supported.")
    digest = manifest.get("image_digest")
    image = manifest.get("image")
    flavor = manifest.get("pytorch_flavor")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Base release manifest must pin an image digest.")
    if not isinstance(image, str) or not image.endswith(f"@{digest}"):
        raise ValueError("Base release manifest image is not pinned to its digest.")
    if flavor not in {"cpu", "cuda126"}:
        raise ValueError("Base release manifest has an unsupported PyTorch flavor.")
    if gpu_mode == "on" and flavor == "cpu":
        raise ValueError("GPU mode on requires a CUDA package base.")

    source = manifest.get("corresponding_source")
    if not isinstance(source, dict) or source.get("source_ref") != source_ref:
        raise ValueError(
            "Base release manifest source ref does not match the exact commit."
        )
    artifacts = manifest.get("release_artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("Base release manifest is missing release artifacts.")
    if artifacts.get("control_zip") or artifacts.get("control_zip_sha256_sidecar"):
        raise ValueError("Base package must be package-release.ps1 -NoZip output.")
    if artifacts.get("package_contents_sha256") != "SHA256SUMS.txt":
        raise ValueError("Base release manifest does not reference package checksums.")
    asset_hash = artifacts.get("asset_bundle_sha256")
    if not isinstance(asset_hash, str) or not SHA256_PATTERN.fullmatch(asset_hash):
        raise ValueError("Base release manifest must record the asset bundle SHA-256.")

    source_text = (base_package_dir / "SOURCE.txt").read_text(encoding="utf-8")
    source_matches = re.findall(r"(?mi)^Source ref:\s*([0-9a-f]{40})\s*$", source_text)
    if source_matches != [source_ref]:
        raise ValueError("Base SOURCE.txt does not match the exact source commit.")
    env = _read_env_assignments(base_package_dir / ".env.example")
    expected_env = {
        "TOWERSCOUT_IMAGE": image,
        "TOWERSCOUT_IMAGE_DIGEST": digest,
        "TOWERSCOUT_PYTORCH_FLAVOR": flavor,
    }
    if any(env.get(name) != value for name, value in expected_env.items()):
        raise ValueError(
            "Base package environment does not match its release manifest."
        )
    _verify_checksums(base_package_dir)
    return manifest


def _clean_git_source_ref(repo_root: Path) -> str:
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
    if status:
        raise RuntimeError(
            "Validation packages must be assembled from a clean Git worktree."
        )
    return _validated_source_ref(commit)


def _assert_safe_launcher_build(
    launcher_build_dir: Path, *, repo_root: Path, source_ref: str
) -> dict[str, object]:
    errors = inspect_build(launcher_build_dir)
    if errors:
        raise ValueError("Launcher build inspection failed: " + "; ".join(errors))
    if any(path.is_symlink() for path in launcher_build_dir.rglob("*")):
        raise ValueError("Launcher build must not contain symbolic links.")
    tk_license = launcher_build_dir / "_internal" / "_tk_data" / "license.terms"
    if not tk_license.is_file():
        raise ValueError("Launcher build is missing the bundled Tcl/Tk license.")
    return verify_build_provenance(
        repo_root=repo_root,
        build_dir=launcher_build_dir,
        expected_source_ref=source_ref,
    )


def _assert_validation_tree(package_dir: Path) -> None:
    errors: list[str] = []
    for path in package_dir.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(package_dir).as_posix()
        lowered = relative.lower()
        if path.suffix.lower() in FORBIDDEN_PACKAGE_SUFFIXES:
            errors.append(f"forbidden script or credential file: {relative}")
        if path.name.lower() == ".env":
            errors.append(f"live environment file is forbidden: {relative}")
        if "host-helper" in lowered or "repair-provider-tls" in lowered:
            errors.append(f"dormant repair helper is forbidden: {relative}")
    if errors:
        raise ValueError("Validation package inspection failed: " + "; ".join(errors))


def _write_checksums(package_dir: Path) -> None:
    checksum_path = package_dir / "SHA256SUMS.txt"
    files = sorted(
        (
            path
            for path in package_dir.rglob("*")
            if path.is_file() and path != checksum_path
        ),
        key=lambda path: path.relative_to(package_dir).as_posix().lower(),
    )
    checksum_path.write_text(
        "".join(
            f"{_sha256(path)}  {path.relative_to(package_dir).as_posix()}\n"
            for path in files
        ),
        encoding="utf-8",
    )


def _write_archive(package_dir: Path, archive_path: Path) -> None:
    with zipfile.ZipFile(
        archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in sorted(
            (item for item in package_dir.rglob("*") if item.is_file()),
            key=lambda item: item.relative_to(package_dir).as_posix().lower(),
        ):
            archive.write(
                path,
                arcname=(
                    f"{package_dir.name}/{path.relative_to(package_dir).as_posix()}"
                ),
            )


def _publish_staged_artifacts(
    artifacts: tuple[tuple[Path, Path], ...],
) -> None:
    def replace_with_retry(staged: Path, destination: Path) -> None:
        delay_seconds = 0.5
        for attempt in range(8):
            try:
                os.replace(staged, destination)
                return
            except PermissionError:
                if attempt == 7:
                    raise
                time.sleep(delay_seconds)
                delay_seconds = min(delay_seconds * 2, 4.0)

    published: list[Path] = []
    try:
        for staged, destination in artifacts:
            replace_with_retry(staged, destination)
            published.append(destination)
    except OSError:
        for destination in reversed(published):
            if destination.is_dir():
                shutil.rmtree(destination, ignore_errors=True)
            else:
                destination.unlink(missing_ok=True)
        raise


def assemble_full_validation_package(
    *,
    repo_root: Path,
    base_package_dir: Path,
    launcher_build_dir: Path,
    output_dir: Path,
    source_ref: str,
    engine: str,
    gpu_mode: str,
    port: int,
    compose_project: str,
    generated_at: datetime | None = None,
) -> ValidationPackageResult:
    if base_package_dir.is_symlink():
        raise ValueError("Base package directory must not be a symbolic link.")
    if launcher_build_dir.is_symlink():
        raise ValueError("Launcher build directory must not be a symbolic link.")
    repo_root = repo_root.resolve()
    base_package_dir = base_package_dir.resolve()
    launcher_build_dir = launcher_build_dir.resolve()
    output_dir = output_dir.resolve()
    source_ref = _validated_source_ref(source_ref)
    _validate_full_profile(
        engine=engine,
        gpu_mode=gpu_mode,
        port=port,
        compose_project=compose_project,
    )
    generated_utc = _generated_utc(generated_at)
    identity = f"Task-087-validation-{source_ref[:12]}"
    package_name = f"towerscout-{identity}"
    package_dir = output_dir / package_name
    archive_path = output_dir / f"{package_name}.zip"
    archive_checksum_path = output_dir / f"{package_name}.zip.sha256"

    if not repo_root.is_dir():
        raise ValueError("Repository root does not exist.")
    if not launcher_build_dir.is_dir():
        raise ValueError("Launcher build directory does not exist.")
    if output_dir == base_package_dir or base_package_dir in output_dir.parents:
        raise ValueError("Output directory must not be inside the base package.")
    if any(
        path.exists() for path in (package_dir, archive_path, archive_checksum_path)
    ):
        raise FileExistsError(
            f"Full validation output already exists for {identity}; "
            "choose a new output directory."
        )

    launcher_provenance = _assert_safe_launcher_build(
        launcher_build_dir,
        repo_root=repo_root,
        source_ref=source_ref,
    )
    manifest = _validate_full_base(
        base_package_dir,
        source_ref=source_ref,
        identity=identity,
        gpu_mode=gpu_mode,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    staging_root = output_dir / f"{package_name}-staging-{uuid.uuid4().hex}"
    staging_root.mkdir()
    try:
        staged_package = staging_root / package_name
        shutil.copytree(base_package_dir, staged_package)
        shutil.copytree(launcher_build_dir, staged_package / "launcher")
        _update_env_example(
            staged_package / ".env.example",
            engine=engine,
            gpu_mode=gpu_mode,
            port=port,
            compose_project=compose_project,
        )

        launcher_sha256 = _sha256(
            staged_package / "launcher" / "TowerScoutLauncher.exe"
        )
        release_artifacts = manifest["release_artifacts"]
        assert isinstance(release_artifacts, dict)
        release_artifacts["control_zip"] = archive_path.name
        release_artifacts["control_zip_sha256"] = ""
        release_artifacts["control_zip_sha256_sidecar"] = archive_checksum_path.name
        release_artifacts["control_zip_sha256_reason"] = (
            "Validation-only archive hash is recorded in the adjacent SHA-256 "
            "sidecar to avoid a circular in-archive digest."
        )
        manifest["validation"] = {
            "host_helper_packaged": False,
            "launcher_tls_mutation_enabled": False,
            "package_kind": PACKAGE_KIND_FULL_RUNNABLE,
            "purpose": FULL_PACKAGE_PURPOSE,
            "release_candidate": False,
            "source_ref": source_ref,
        }
        _write_json(staged_package / "release-manifest.v1.json", manifest)

        validation_manifest = {
            "artifact_identity": identity,
            "asset_bundle_sha256": release_artifacts["asset_bundle_sha256"],
            "compose_project": compose_project,
            "engine": engine,
            "execution_authorized_by_package": False,
            "execution_scope": (
                "separately project-lead-authorized isolated development "
                "workstation functional validation only"
            ),
            "generated_utc": generated_utc,
            "github_release_authorized": False,
            "gpu_mode": gpu_mode,
            "host_helper_packaged": False,
            "image_digest": manifest["image_digest"],
            "launcher_build_tree_sha256": launcher_provenance["build_tree_sha256"],
            "launcher_requirements_build_sha256": launcher_provenance[
                "requirements_build_sha256"
            ],
            "launcher_sha256": launcher_sha256,
            "launcher_signature_verified": False,
            "launcher_tls_mutation_enabled": False,
            "managed_endpoint_evidence_authorized": False,
            "merge_authorized": False,
            "package_kind": PACKAGE_KIND_FULL_RUNNABLE,
            "port": port,
            "purpose": FULL_PACKAGE_PURPOSE,
            "release_candidate": False,
            "schema_version": 1,
            "source_ref": source_ref,
        }
        _write_json(staged_package / "validation-manifest.v1.json", validation_manifest)
        (staged_package / "VALIDATION-ONLY.txt").write_text(
            "TOWERSCOUT TASK-087 FULL RUNNABLE VALIDATION ONLY\n\n"
            "This package is not a release candidate and is not approved for "
            "distribution, merge, or production use.\n"
            "It contains the normal digest-pinned TowerScout control package, the "
            "controlled native TLS-repair launcher, and the existing Task-086 manual "
            "repair scripts. The launcher does not run those scripts. TLS repair "
            "requires exact-target validation and explicit typed confirmation.\n"
            "Functional execution requires separate project-lead authorization and "
            "does not satisfy the signed representative managed-endpoint gate.\n"
            "Do not add endpoint exclusions or place provider keys, certificate "
            "details, raw responses, or logs in validation evidence.\n",
            encoding="utf-8",
        )
        (staged_package / "LAUNCHER-PROVENANCE.txt").write_text(
            "TowerScout launcher validation provenance\n"
            f"Source commit: {source_ref}\n"
            "Build requirements: launcher/requirements-build.txt exact pins\n"
            f"Launcher SHA-256: {launcher_sha256}\n"
            f"Launcher build tree SHA-256: "
            f"{launcher_provenance['build_tree_sha256']}\n"
            f"Build requirements SHA-256: "
            f"{launcher_provenance['requirements_build_sha256']}\n"
            "Launcher signature: not verified by this assembler\n"
            f"Package kind: {PACKAGE_KIND_FULL_RUNNABLE}\n",
            encoding="utf-8",
        )
        _assert_full_tree_safe(staged_package)
        _write_checksums(staged_package)

        staged_archive = staging_root / archive_path.name
        staged_sidecar = staging_root / archive_checksum_path.name
        _write_archive(staged_package, staged_archive)
        archive_sha256 = _sha256(staged_archive)
        staged_sidecar.write_text(
            f"{archive_sha256}  {archive_path.name}\n", encoding="utf-8"
        )
        _publish_staged_artifacts(
            (
                (staged_package, package_dir),
                (staged_archive, archive_path),
                (staged_sidecar, archive_checksum_path),
            )
        )
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)

    return ValidationPackageResult(
        identity=identity,
        source_ref=source_ref,
        package_dir=package_dir,
        archive_path=archive_path,
        archive_sha256=archive_sha256,
    )


def assemble_validation_package(
    *,
    repo_root: Path,
    launcher_build_dir: Path,
    output_dir: Path,
    source_ref: str,
    generated_at: datetime | None = None,
) -> ValidationPackageResult:
    repo_root = repo_root.resolve()
    launcher_build_dir = launcher_build_dir.resolve()
    output_dir = output_dir.resolve()
    source_ref = _validated_source_ref(source_ref)
    generated_utc = _generated_utc(generated_at)
    identity = f"Task-087-validation-{source_ref[:12]}"
    package_dir = output_dir / identity
    archive_path = output_dir / f"{identity}.zip"
    archive_checksum_path = output_dir / f"{identity}.zip.sha256"

    if not repo_root.is_dir():
        raise ValueError("Repository root does not exist.")
    if not launcher_build_dir.is_dir():
        raise ValueError("Launcher build directory does not exist.")
    if package_dir.exists() or archive_path.exists() or archive_checksum_path.exists():
        raise FileExistsError(
            f"Validation output already exists for {identity}; "
            "choose a new output directory."
        )

    launcher_provenance = _assert_safe_launcher_build(
        launcher_build_dir,
        repo_root=repo_root,
        source_ref=source_ref,
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    staging_root = output_dir / f"{identity}-staging-{uuid.uuid4().hex}"
    staging_root.mkdir()
    try:
        staged_package = staging_root / identity
        staged_package.mkdir()
        shutil.copytree(launcher_build_dir, staged_package / "launcher")

        (staged_package / "compose.yaml").write_text(
            "# Task-087 package-discovery sentinel only.\n"
            "# This validation artifact contains no runnable TowerScout stack.\n"
            "services: {}\n",
            encoding="utf-8",
        )
        (staged_package / ".env.example").write_text(
            "# Non-secret launcher discovery defaults for validation only.\n"
            "COMPOSE_PROJECT_NAME=towerscout-task087-validation\n"
            "TOWERSCOUT_GPU_MODE=auto\n"
            "TOWERSCOUT_PORT=5000\n"
            "TOWERSCOUT_PYTORCH_FLAVOR=unknown\n",
            encoding="utf-8",
        )
        _write_json(
            staged_package / "release-manifest.v1.json",
            {
                "image": "",
                "image_digest": "",
                "package_kind": PACKAGE_KIND_LAUNCHER_POLICY,
                "pytorch_flavor": "unknown",
                "release_version": identity,
                "schema_version": 1,
                "track": "task-087-validation-only",
            },
        )
        _write_json(
            staged_package / "validation-manifest.v1.json",
            {
                "artifact_identity": identity,
                "execution_authorized": False,
                "generated_utc": generated_utc,
                "github_release_authorized": False,
                "launcher_build_tree_sha256": launcher_provenance["build_tree_sha256"],
                "launcher_requirements_build_sha256": launcher_provenance[
                    "requirements_build_sha256"
                ],
                "launcher_sha256": launcher_provenance["launcher_executable_sha256"],
                "launcher_tls_mutation_enabled": False,
                "merge_authorized": False,
                "package_kind": PACKAGE_KIND_LAUNCHER_POLICY,
                "purpose": "task-087-launcher-policy-validation-only",
                "release_candidate": False,
                "schema_version": 1,
                "signed": False,
                "source_ref": source_ref,
            },
        )
        (staged_package / "SOURCE.txt").write_text(
            f"source_ref={source_ref}\nartifact_identity={identity}\n",
            encoding="utf-8",
        )
        (staged_package / "VALIDATION-ONLY.txt").write_text(
            "TASK-087 VALIDATION-ONLY ARTIFACT\n\n"
            "This is not a TowerScout release candidate or end-user package.\n"
            "It contains no runnable TowerScout application stack or host helper. "
            "The launcher binary contains the native repair UI, but exact-target "
            "validation prevents repair in this sentinel-only package.\n"
            "Do not publish it as a GitHub Release, tag it, merge on its evidence, "
            "or distribute it through cdcai.\n"
            "Do not execute an unsigned build on a managed endpoint. An approved "
            "signing owner must sign and timestamp the launcher before representative "
            "endpoint-policy validation.\n",
            encoding="utf-8",
        )
        _assert_validation_tree(staged_package)
        _write_checksums(staged_package)

        staged_archive = staging_root / archive_path.name
        staged_sidecar = staging_root / archive_checksum_path.name
        _write_archive(staged_package, staged_archive)
        archive_sha256 = _sha256(staged_archive)
        staged_sidecar.write_text(
            f"{archive_sha256}  {archive_path.name}\n", encoding="utf-8"
        )
        _publish_staged_artifacts(
            (
                (staged_package, package_dir),
                (staged_archive, archive_path),
                (staged_sidecar, archive_checksum_path),
            )
        )
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)
    return ValidationPackageResult(
        identity=identity,
        source_ref=source_ref,
        package_dir=package_dir,
        archive_path=archive_path,
        archive_sha256=archive_sha256,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assemble a Task-087 validation-only launcher package."
    )
    parser.add_argument(
        "--package-kind",
        choices=(PACKAGE_KIND_LAUNCHER_POLICY, PACKAGE_KIND_FULL_RUNNABLE),
        default=PACKAGE_KIND_LAUNCHER_POLICY,
    )
    parser.add_argument("--base-package-dir", type=Path)
    parser.add_argument(
        "--launcher-build-dir",
        type=Path,
        default=Path("dist/TowerScoutLauncher"),
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("dist/task-087-validation")
    )
    parser.add_argument("--engine", choices=("docker", "podman"))
    parser.add_argument("--gpu", choices=("off", "auto", "on"))
    parser.add_argument("--port", type=int)
    parser.add_argument("--compose-project")
    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        source_ref = _clean_git_source_ref(repo_root)
        if args.package_kind == PACKAGE_KIND_FULL_RUNNABLE:
            missing = [
                option
                for option, value in (
                    ("--base-package-dir", args.base_package_dir),
                    ("--engine", args.engine),
                    ("--gpu", args.gpu),
                    ("--port", args.port),
                    ("--compose-project", args.compose_project),
                )
                if value is None
            ]
            if missing:
                raise ValueError(
                    "Full-runnable assembly requires: " + ", ".join(missing)
                )
            result = assemble_full_validation_package(
                repo_root=repo_root,
                base_package_dir=args.base_package_dir,
                launcher_build_dir=args.launcher_build_dir,
                output_dir=args.output_dir,
                source_ref=source_ref,
                engine=args.engine,
                gpu_mode=args.gpu,
                port=args.port,
                compose_project=args.compose_project,
            )
        else:
            result = assemble_validation_package(
                repo_root=repo_root,
                launcher_build_dir=args.launcher_build_dir,
                output_dir=args.output_dir,
                source_ref=source_ref,
            )
    except (FileExistsError, OSError, RuntimeError, ValueError) as error:
        print(f"Validation package assembly failed: {error}", file=sys.stderr)
        return 1
    print(f"Package kind: {args.package_kind}")
    print(f"Validation package: {result.package_dir}")
    print(f"Archive: {result.archive_path}")
    print(f"Archive SHA-256: {result.archive_sha256}")
    print(f"Source ref: {result.source_ref}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
