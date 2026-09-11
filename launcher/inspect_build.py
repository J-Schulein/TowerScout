from __future__ import annotations

import hashlib
import sys
import struct
from pathlib import Path

FORBIDDEN_SUFFIXES = {".bat", ".cmd", ".ps1", ".pem", ".key", ".env"}
PE_MACHINE_AMD64 = 0x8664
PE_SUBSYSTEM_WINDOWS_GUI = 2
RUNTIME_POLICY_RELATIVE_PATH = (
    Path("_internal") / "towerscout_launcher" / "runtime-policy.v1.json"
)
RUNTIME_POLICY_SHA256 = (
    "c4dbf79f6732290ccb9c525f6493662de59cb5960fc2f4228fae518eb89702c4"
)
RUNTIME_DEPENDENCY_POLICY_RELATIVE_PATH = (
    Path("_internal") / "towerscout_launcher" / "runtime-dependency-policy.v1.json"
)
RUNTIME_DEPENDENCY_POLICY_SHA256 = (
    "1c699ac7d2d2592305e876431d57231ef63e5ccdaaeb033c7d3526db307a3890"
)
MAX_RUNTIME_POLICY_BYTES = 128 * 1024


def _inspect_launcher_pe(path: Path) -> list[str]:
    errors: list[str] = []
    data = path.read_bytes()
    if len(data) < 256 or data[:2] != b"MZ":
        return ["TowerScoutLauncher.exe is not a valid PE file."]
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 96 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return ["TowerScoutLauncher.exe has an invalid PE header."]
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    optional_header = pe_offset + 24
    subsystem = struct.unpack_from("<H", data, optional_header + 68)[0]
    if machine != PE_MACHINE_AMD64:
        errors.append("TowerScoutLauncher.exe is not Windows AMD64.")
    if subsystem != PE_SUBSYSTEM_WINDOWS_GUI:
        errors.append("TowerScoutLauncher.exe is not a windowed GUI application.")
    if b"UPX!" in data:
        errors.append("TowerScoutLauncher.exe contains an UPX marker.")
    return errors


def _inspect_policy(
    root: Path,
    *,
    relative_path: Path,
    expected_sha256: str,
    label: str,
) -> list[str]:
    expected = root / relative_path
    if not expected.is_file():
        return [f"The package-bound {label} is missing."]
    try:
        with expected.open("rb") as handle:
            data = handle.read(MAX_RUNTIME_POLICY_BYTES + 1)
    except OSError:
        return [f"The package-bound {label} is unreadable."]
    if len(data) > MAX_RUNTIME_POLICY_BYTES:
        return [f"The package-bound {label} exceeds its size limit."]
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        return [f"The package-bound {label} integrity check failed."]
    return []


def _inspect_runtime_policies(root: Path) -> list[str]:
    return [
        *_inspect_policy(
            root,
            relative_path=RUNTIME_POLICY_RELATIVE_PATH,
            expected_sha256=RUNTIME_POLICY_SHA256,
            label="runtime policy",
        ),
        *_inspect_policy(
            root,
            relative_path=RUNTIME_DEPENDENCY_POLICY_RELATIVE_PATH,
            expected_sha256=RUNTIME_DEPENDENCY_POLICY_SHA256,
            label="runtime dependency policy",
        ),
    ]


def inspect_build(root: Path) -> list[str]:
    errors: list[str] = []
    executable = root / "TowerScoutLauncher.exe"
    if not executable.is_file():
        errors.append("TowerScoutLauncher.exe is missing.")
    else:
        errors.extend(_inspect_launcher_pe(executable))
    errors.extend(_inspect_runtime_policies(root))
    files = [path for path in root.rglob("*") if path.is_file()]
    if not files:
        errors.append("The launcher build is empty.")
    expected_policy_paths = {
        "runtime-policy.v1.json": root / RUNTIME_POLICY_RELATIVE_PATH,
        "runtime-dependency-policy.v1.json": (
            root / RUNTIME_DEPENDENCY_POLICY_RELATIVE_PATH
        ),
    }
    for path in files:
        expected_policy_path = expected_policy_paths.get(path.name.casefold())
        if expected_policy_path is not None and path != expected_policy_path:
            errors.append("A runtime policy exists outside its fixed package path.")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES or path.name.lower().startswith(
            ".env"
        ):
            errors.append(f"Forbidden packaged file type: {path.name}")
    return errors


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("dist/TowerScoutLauncher")
    errors = inspect_build(root)
    if errors:
        print("Launcher package inspection failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(
        "Launcher package inspection passed (one-directory, no script or secret files)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
