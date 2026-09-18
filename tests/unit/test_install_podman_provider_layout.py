from __future__ import annotations

import base64
import csv
import hashlib
import io
import shutil
import sys
import uuid
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_ROOT = ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from install_podman_provider_layout import (  # noqa: E402
    LayoutError,
    install_exact_wheels,
)


@pytest.fixture
def workspace_temp() -> Iterator[Path]:
    path = (
        ROOT / ".agent_work" / "pytest-temp" / f"task087-layout-unit-{uuid.uuid4().hex}"
    )
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _record_hash(contents: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(contents).digest())
    return "sha256=" + digest.decode("ascii").rstrip("=")


def _record_bytes(
    members: dict[str, bytes],
    record_path: str,
    transform: Callable[[list[list[str]]], None] | None = None,
) -> bytes:
    rows = [
        [path, _record_hash(contents), str(len(contents))]
        for path, contents in sorted(members.items())
    ]
    rows.append([record_path, "", ""])
    if transform is not None:
        transform(rows)
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(rows)
    return stream.getvalue().encode("utf-8")


def _write_wheel(
    root: Path,
    filename: str,
    files: dict[str, bytes] | None = None,
    transform: Callable[[list[list[str]]], None] | None = None,
) -> Path:
    stem = filename.split("-", 1)[0]
    record_path = f"{stem}-1.0.dist-info/RECORD"
    members = {
        f"{stem}.py": b"VALUE = 1\n",
        f"{stem}-1.0.dist-info/METADATA": (
            f"Metadata-Version: 2.1\nName: {stem}\nVersion: 1.0\n\n"
        ).encode("utf-8"),
        f"{stem}-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
        **(files or {}),
    }
    members[record_path] = _record_bytes(members, record_path, transform)
    wheel_path = root / filename
    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for member, contents in members.items():
            archive.writestr(member, contents)
    return wheel_path


def _empty_destination(root: Path) -> Path:
    destination = root / "site-packages"
    destination.mkdir()
    return destination


@pytest.mark.parametrize(
    "member",
    (
        "../escape.py",
        "/absolute.py",
        "folder\\escape.py",
        "CON.py",
        "e\u0301.py",
        "loader.pth",
        "module.pyc",
        "sitecustomize.py",
        "usercustomize/__init__.py",
    ),
)
def test_materializer_rejects_unsafe_archive_paths(
    workspace_temp: Path,
    member: str,
) -> None:
    wheel = _write_wheel(
        workspace_temp,
        "unsafe-1.0-py3-none-any.whl",
        {member: b"unsafe"},
    )

    with pytest.raises(LayoutError):
        install_exact_wheels((wheel,), _empty_destination(workspace_temp))


def test_materializer_rejects_case_collisions(workspace_temp: Path) -> None:
    wheel = _write_wheel(
        workspace_temp,
        "collision-1.0-py3-none-any.whl",
        {"Collision.py": b"duplicate"},
    )

    with pytest.raises(LayoutError):
        install_exact_wheels((wheel,), _empty_destination(workspace_temp))


@pytest.mark.parametrize("mode", ("hash", "size", "set"))
def test_materializer_rejects_record_mismatch(
    workspace_temp: Path,
    mode: str,
) -> None:
    def corrupt(rows: list[list[str]]) -> None:
        if mode == "hash":
            rows[0][1] = "sha256=" + ("A" * 43)
        elif mode == "size":
            rows[0][2] = "999"
        else:
            rows.pop(0)

    wheel = _write_wheel(
        workspace_temp,
        "record-1.0-py3-none-any.whl",
        transform=corrupt,
    )

    with pytest.raises(LayoutError):
        install_exact_wheels((wheel,), _empty_destination(workspace_temp))


def test_materializer_rejects_cross_wheel_installed_collision(
    workspace_temp: Path,
) -> None:
    first = _write_wheel(
        workspace_temp,
        "first-1.0-py3-none-any.whl",
        {"shared.py": b"first"},
    )
    second = _write_wheel(
        workspace_temp,
        "second-1.0-py3-none-any.whl",
        {"Shared.py": b"second"},
    )

    with pytest.raises(LayoutError):
        install_exact_wheels((first, second), _empty_destination(workspace_temp))


def test_materializer_rejects_nonempty_destination(workspace_temp: Path) -> None:
    wheel = _write_wheel(workspace_temp, "nonempty-1.0-py3-none-any.whl")
    destination = _empty_destination(workspace_temp)
    (destination / "existing.py").write_text("existing", encoding="utf-8")

    with pytest.raises(LayoutError):
        install_exact_wheels((wheel,), destination)


def test_materializer_cleans_partial_output_after_write_failure(
    workspace_temp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = _write_wheel(workspace_temp, "cleanup-1.0-py3-none-any.whl")
    destination = _empty_destination(workspace_temp)
    original_open = Path.open
    writes = 0

    def fail_second_write(path: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        nonlocal writes
        if args and args[0] == "xb":
            writes += 1
            if writes == 2:
                raise OSError("synthetic write failure")
        return original_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "open", fail_second_write)

    with pytest.raises(LayoutError, match="wheel layout is invalid"):
        install_exact_wheels((wheel,), destination)

    assert not any(destination.iterdir())
