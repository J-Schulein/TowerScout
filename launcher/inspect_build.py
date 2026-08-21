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
    "6c198c097b511d9a73c168a244c89f5932a27abd12b5870118a80c46c5356011"
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


def _inspect_runtime_policy(root: Path) -> list[str]:
    expected = root / RUNTIME_POLICY_RELATIVE_PATH
    if not expected.is_file():
        return ["The package-bound runtime policy is missing."]
    try:
        with expected.open("rb") as handle:
            data = handle.read(MAX_RUNTIME_POLICY_BYTES + 1)
    except OSError:
        return ["The package-bound runtime policy is unreadable."]
    if len(data) > MAX_RUNTIME_POLICY_BYTES:
        return ["The package-bound runtime policy exceeds its size limit."]
    if hashlib.sha256(data).hexdigest() != RUNTIME_POLICY_SHA256:
        return ["The package-bound runtime policy integrity check failed."]
    return []


def inspect_build(root: Path) -> list[str]:
    errors: list[str] = []
    executable = root / "TowerScoutLauncher.exe"
    if not executable.is_file():
        errors.append("TowerScoutLauncher.exe is missing.")
    else:
        errors.extend(_inspect_launcher_pe(executable))
    errors.extend(_inspect_runtime_policy(root))
    files = [path for path in root.rglob("*") if path.is_file()]
    if not files:
        errors.append("The launcher build is empty.")
    for path in files:
        if (
            path.name.casefold() == "runtime-policy.v1.json"
            and path != root / RUNTIME_POLICY_RELATIVE_PATH
        ):
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
