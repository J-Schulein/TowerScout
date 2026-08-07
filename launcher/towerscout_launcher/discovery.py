from __future__ import annotations

import json
import re
import shutil

# Subprocess is limited to fixed read-only runtime probes; no caller command or shell.
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .models import (
    LauncherSnapshot,
    PackageIdentity,
    PublicState,
    RepairPreview,
    RuntimeProbe,
    TowerScoutStatus,
)

_ALLOWED_ENV_NAMES = {
    "COMPOSE_PROJECT_NAME",
    "TOWERSCOUT_CONTAINER_ENGINE",
    "TOWERSCOUT_GPU_MODE",
    "TOWERSCOUT_IMAGE",
    "TOWERSCOUT_IMAGE_DIGEST",
    "TOWERSCOUT_PORT",
    "TOWERSCOUT_PYTORCH_FLAVOR",
}
_ENGINE_COMMANDS: Mapping[str, tuple[str, ...]] = {
    "docker": ("version", "--format", "{{json .}}"),
    "podman": ("info", "--format", "json"),
}
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9._:@/+\-]{0,300}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 1_048_576
_MAX_RUNTIME_OUTPUT = 262_144
_MAX_READINESS_BYTES = 131_072
_RUNTIME_PROBE_TIMEOUT_SECONDS = 5.0


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise HTTPError(req.full_url, code, "Redirect rejected", headers, fp)


def locate_package_root(start: Path | None = None) -> Path:
    """Locate a package root from trusted executable/module-relative candidates."""
    candidates: tuple[Path, ...]
    if start is not None:
        candidates = (start.resolve(),)
    elif getattr(sys, "frozen", False):
        executable_dir = Path(sys.executable).resolve().parent
        candidates = (executable_dir, executable_dir.parent)
    else:
        candidates = (Path(__file__).resolve().parents[2],)

    for candidate in candidates:
        if (candidate / "compose.yaml").is_file() and (
            candidate / "release-manifest.v1.json"
        ).is_file():
            return candidate
    raise RuntimeError("TowerScout package files were not found beside the launcher.")


def _safe_public_text(value: object, fallback: str = "unknown") -> str:
    text = str(value or "").strip()
    if not text or not _SAFE_TEXT.fullmatch(text):
        return fallback
    return text


def _read_allowed_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file() or path.stat().st_size > 262_144:
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        if name not in _ALLOWED_ENV_NAMES:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[name] = value
    return values


def load_package_identity(root: Path) -> PackageIdentity:
    root = root.resolve()
    manifest_path = root / "release-manifest.v1.json"
    if (
        not manifest_path.is_file()
        or manifest_path.stat().st_size > _MAX_MANIFEST_BYTES
    ):
        raise RuntimeError("TowerScout release identity is unavailable.")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("TowerScout release identity is invalid.") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise RuntimeError("TowerScout release identity uses an unsupported schema.")

    env_path = root / ".env"
    if not env_path.is_file():
        env_path = root / ".env.example"
    env = _read_allowed_env(env_path)

    version = _safe_public_text(manifest.get("release_version"), "template")
    track = _safe_public_text(manifest.get("track"), "unknown")
    manifest_image = _safe_public_text(manifest.get("image"), "")
    env_image = _safe_public_text(env.get("TOWERSCOUT_IMAGE"), "")
    if manifest_image and env_image and manifest_image != env_image:
        raise RuntimeError(
            "TowerScout package image identity does not match its environment."
        )
    image = env_image or manifest_image or "unknown"
    manifest_digest = _safe_public_text(manifest.get("image_digest"), "")
    env_digest = _safe_public_text(env.get("TOWERSCOUT_IMAGE_DIGEST"), "")
    if manifest_digest and env_digest and manifest_digest != env_digest:
        raise RuntimeError(
            "TowerScout package image digest does not match its environment."
        )
    digest = _safe_public_text(env_digest or manifest_digest, "")
    if digest and not _DIGEST.fullmatch(digest):
        digest = ""
    flavor = _safe_public_text(
        env.get("TOWERSCOUT_PYTORCH_FLAVOR") or manifest.get("pytorch_flavor"),
        "unknown",
    ).lower()
    if flavor not in {"cpu", "cuda121", "cuda126", "source", "unknown"}:
        flavor = "unknown"
    engine = env.get("TOWERSCOUT_CONTAINER_ENGINE", "").strip().lower()
    if engine not in {"docker", "podman"}:
        engine = ""
    gpu = env.get("TOWERSCOUT_GPU_MODE", "off").strip().lower()
    if gpu not in {"off", "auto", "on"}:
        gpu = "off"
    try:
        port = int(env.get("TOWERSCOUT_PORT", "5000"))
    except ValueError:
        port = 5000
    if not 1 <= port <= 65535:
        port = 5000
    project = _safe_public_text(env.get("COMPOSE_PROJECT_NAME"), "towerscout")

    return PackageIdentity(
        root=root,
        release_version=version,
        track=track,
        image=image,
        image_digest=digest,
        pytorch_flavor=flavor,
        engine_hint=engine,
        gpu_mode=gpu,
        port=port,
        compose_project=project,
        is_release_package=version != "template",
    )


def _default_runner(
    command: Sequence[str], *, cwd: Path, timeout: float
) -> subprocess.CompletedProcess[str]:
    # The executable name and every argument are selected from the internal allowlist.
    # A windowed PyInstaller parent must not ask Windows to attach a console for the
    # runtime CLI child; that path can stall before Docker or Podman initializes.
    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    return subprocess.run(  # nosec B603
        list(command),
        cwd=cwd,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        creationflags=creation_flags,
    )


def probe_runtime(
    engine: str,
    package_root: Path,
    *,
    resolver: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = _default_runner,
) -> RuntimeProbe:
    if engine not in _ENGINE_COMMANDS:
        raise ValueError("Unsupported runtime probe.")
    executable = resolver(engine)
    display_name = "Docker" if engine == "docker" else "Podman"
    if not executable:
        return RuntimeProbe(
            engine,
            PublicState.UNAVAILABLE,
            False,
            False,
            f"{display_name} is not installed.",
        )
    resolved = Path(executable).resolve()
    if not resolved.is_absolute() or resolved.name.lower() not in {
        engine,
        f"{engine}.exe",
    }:
        return RuntimeProbe(
            engine,
            PublicState.ERROR,
            True,
            False,
            f"{display_name} could not be verified safely.",
        )
    command = (str(resolved),) + _ENGINE_COMMANDS[engine]
    try:
        result = runner(
            command,
            cwd=package_root,
            timeout=_RUNTIME_PROBE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return RuntimeProbe(
            engine,
            PublicState.ERROR,
            True,
            False,
            f"{display_name} status check timed out after five seconds.",
        )
    except (OSError, subprocess.SubprocessError):
        return RuntimeProbe(
            engine,
            PublicState.ERROR,
            True,
            False,
            f"{display_name} status check failed.",
        )
    if len(result.stdout) + len(result.stderr) > _MAX_RUNTIME_OUTPUT:
        return RuntimeProbe(
            engine,
            PublicState.ERROR,
            True,
            False,
            f"{display_name} returned an invalid response.",
        )
    if result.returncode != 0:
        return RuntimeProbe(
            engine,
            PublicState.UNAVAILABLE,
            True,
            False,
            f"{display_name} is installed but unavailable.",
        )
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        parsed = None
    if not isinstance(parsed, dict):
        return RuntimeProbe(
            engine,
            PublicState.ERROR,
            True,
            False,
            f"{display_name} returned an invalid status response.",
        )
    return RuntimeProbe(
        engine,
        PublicState.SUCCESS,
        True,
        True,
        f"{display_name} is running and reachable.",
    )


def read_towerscout_status(package: PackageIdentity) -> TowerScoutStatus:
    url = f"http://127.0.0.1:{package.port}/api/readiness"
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
    # Never route the package-local readiness request through environment proxies.
    opener = build_opener(ProxyHandler({}), _RejectRedirects())
    try:
        with opener.open(request, timeout=3.0) as response:
            body = response.read(_MAX_READINESS_BYTES + 1)
    except (OSError, HTTPError, URLError, TimeoutError):
        return TowerScoutStatus(
            PublicState.UNAVAILABLE,
            "unreachable",
            "TowerScout is not reachable at the package port.",
        )
    if len(body) > _MAX_READINESS_BYTES:
        return TowerScoutStatus(
            PublicState.ERROR,
            "invalid",
            "TowerScout returned an invalid status response.",
        )
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return TowerScoutStatus(
            PublicState.ERROR,
            "invalid",
            "TowerScout returned an invalid status response.",
        )
    if not isinstance(payload, dict):
        return TowerScoutStatus(
            PublicState.ERROR,
            "invalid",
            "TowerScout returned an invalid status response.",
        )
    readiness = str(payload.get("state", "unknown")).strip().lower()
    if readiness not in {"starting", "setup_required", "degraded", "ready", "fatal"}:
        readiness = "unknown"
    runtime = payload.get("runtime")
    if not isinstance(runtime, dict):
        runtime = {}
    version = payload.get("version")
    if not isinstance(version, dict):
        version = {}
    runtime_engine = str(runtime.get("container_engine", "")).strip().lower()
    if runtime_engine not in {"docker", "podman"}:
        runtime_engine = ""
    selected_device = str(runtime.get("selected_device", "")).strip().lower()
    if selected_device not in {"cpu", "cuda"}:
        selected_device = ""
    flavor = _safe_public_text(runtime.get("pytorch_flavor"), "")
    digest = _safe_public_text(version.get("image_digest"), "")
    if digest and not _DIGEST.fullmatch(digest):
        digest = ""
    identity_mismatch = bool(
        package.is_release_package
        and package.image_digest
        and digest != package.image_digest
    )
    profile_mismatch = bool(
        package.is_release_package
        and (
            (package.gpu_mode == "off" and selected_device == "cuda")
            or (package.gpu_mode == "on" and selected_device == "cpu")
            or (flavor and package.pytorch_flavor not in {"unknown", flavor.lower()})
        )
    )
    if identity_mismatch or profile_mismatch:
        state = PublicState.ERROR
        message = "The running TowerScout instance does not match this package profile."
        runtime_engine = ""
    elif readiness == "fatal":
        state = PublicState.ERROR
        message = "TowerScout reports a fatal readiness state. Use the existing support commands."
    elif readiness in {"setup_required", "degraded", "ready"}:
        state = PublicState.SUCCESS
        message = f"TowerScout is reachable and reports {readiness.replace('_', ' ')}."
    else:
        state = PublicState.UNAVAILABLE
        message = "TowerScout is reachable but not ready yet."
    return TowerScoutStatus(
        state,
        readiness,
        message,
        runtime_engine=runtime_engine,
        selected_device=selected_device,
        pytorch_flavor=flavor,
        image_digest=digest,
    )


def collect_snapshot(root: Path | None = None) -> LauncherSnapshot:
    package_root = locate_package_root(root)
    package = load_package_identity(package_root)
    runtimes = tuple(probe_runtime(name, package_root) for name in ("docker", "podman"))
    return LauncherSnapshot(package, runtimes, read_towerscout_status(package))


def choose_engine(snapshot: LauncherSnapshot) -> str:
    if snapshot.towerscout.runtime_engine in {"docker", "podman"}:
        return snapshot.towerscout.runtime_engine
    if snapshot.package.engine_hint in {"docker", "podman"}:
        return snapshot.package.engine_hint
    reachable = [item.engine for item in snapshot.runtimes if item.reachable]
    return reachable[0] if len(reachable) == 1 else ""


def build_repair_preview(
    snapshot: LauncherSnapshot, *, provider: str, engine: str
) -> RepairPreview:
    if provider not in {"google", "azure"} or engine not in {"docker", "podman"}:
        return RepairPreview(
            PublicState.ERROR,
            "Preview unavailable",
            "Choose one of the fixed TowerScout providers and a detected runtime.",
        )
    runtime = next((item for item in snapshot.runtimes if item.engine == engine), None)
    if runtime is None or not runtime.reachable:
        return RepairPreview(
            PublicState.UNAVAILABLE,
            "Preview unavailable",
            "The selected runtime is not reachable. No changes were attempted.",
        )
    provider_name = "Google Maps" if provider == "google" else "Azure Maps"
    engine_name = "Docker" if engine == "docker" else "Podman"
    profile = snapshot.package.gpu_mode.upper()
    body = (
        f"Target: {snapshot.package.package_label}\n"
        f"Runtime profile: {engine_name}, GPU {profile}, port {snapshot.package.port}\n"
        f"Provider: {provider_name}\n\n"
        "A separately confirmed repair will inspect the provider TLS chain, select one "
        "unambiguous CA candidate, stage a combined CA bundle in TowerScout's persistent "
        "configuration volume, preserve the normal system roots, restart the same runtime "
        "profile, wait for readiness, and verify the provider connection.\n\n"
        "This plan is preview-only. Showing it did not inspect certificates, change "
        "trust, stop or restart a container, or run the dormant helper. Use Repair TLS "
        "and restart only after reviewing the exact target."
    )
    return RepairPreview(PublicState.SUCCESS, "TLS repair preview", body)
