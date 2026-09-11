from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class PublicState(str, Enum):
    SUCCESS = "success"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass(frozen=True)
class PackageIdentity:
    root: Path
    release_version: str
    track: str
    image: str
    image_digest: str
    pytorch_flavor: str
    engine_hint: str
    gpu_mode: str
    port: int
    compose_project: str
    is_release_package: bool

    @property
    def package_label(self) -> str:
        if self.is_release_package:
            return f"TowerScout {self.release_version} ({self.pytorch_flavor})"
        return f"TowerScout source prototype ({self.pytorch_flavor})"


@dataclass(frozen=True)
class RuntimeProbe:
    engine: str
    state: PublicState
    installed: bool
    reachable: bool
    public_message: str


@dataclass(frozen=True)
class TowerScoutStatus:
    state: PublicState
    readiness: str
    public_message: str
    runtime_engine: str = ""
    selected_device: str = ""
    pytorch_flavor: str = ""
    image_digest: str = ""


@dataclass(frozen=True)
class LauncherSnapshot:
    package: PackageIdentity
    runtimes: tuple[RuntimeProbe, ...]
    towerscout: TowerScoutStatus


@dataclass(frozen=True)
class RepairPreview:
    state: PublicState
    title: str
    body: str
