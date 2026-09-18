"""Materialize an exact provider ``site-packages`` tree from wheel bytes.

This installer helper deliberately uses only the Python standard library.  It
does not establish runtime trust: the Gate A native owner must still
authenticate and retain the interpreter, wheels, and installed files before
use.  Its job is narrower—produce the same byte inventory reconstructed by
``runtime_podman_provider`` without pip-generated metadata drift.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import re
import shutil
import sys
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import NoReturn, Sequence

MAX_WHEEL_BYTES = 32 * 1024 * 1024
MAX_WHEEL_FILES = 4096
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_RELATIVE_PATH_CHARACTERS = 1024
RECORD_SHA256 = re.compile(r"^sha256=([A-Za-z0-9_-]{43})$")
WINDOWS_RESERVED = re.compile(
    r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE
)


class LayoutError(RuntimeError):
    """Sanitized exact-layout failure."""


def _fail() -> NoReturn:
    raise LayoutError("The managed provider wheel layout is invalid.")


def _safe_archive_path(value: object) -> bool:
    if (
        type(value) is not str
        or not 1 <= len(value) <= MAX_RELATIVE_PATH_CHARACTERS
        or "\\" in value
        or "\x00" in value
        or value.startswith("/")
        or value.endswith("/")
        or value != unicodedata.normalize("NFC", value)
    ):
        return False
    path = PurePosixPath(value)
    return bool(
        not path.is_absolute()
        and path.parts
        and all(
            part not in {"", ".", ".."}
            and not part.endswith((".", " "))
            and not any(character in part for character in '<>:"|?*')
            and not WINDOWS_RESERVED.fullmatch(part)
            for part in path.parts
        )
    )


def _record_digest(value: str) -> bytes:
    match = RECORD_SHA256.fullmatch(value)
    if match is None:
        _fail()
    try:
        digest = base64.urlsafe_b64decode(match.group(1) + "=")
    except (TypeError, ValueError):
        _fail()
    if len(digest) != 32:
        _fail()
    return digest


def _parse_record(contents: bytes) -> dict[str, tuple[str, str]]:
    try:
        text = contents.decode("utf-8", errors="strict")
        if text.startswith("\ufeff") or "\x00" in text:
            _fail()
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeError, csv.Error, ValueError):
        _fail()
    output: dict[str, tuple[str, str]] = {}
    folded: set[str] = set()
    for row in rows:
        if len(row) != 3 or not _safe_archive_path(row[0]):
            _fail()
        key = row[0].casefold()
        if key in folded:
            _fail()
        folded.add(key)
        output[row[0]] = (row[1], row[2])
    return output


def _installed_relative(member: str) -> PureWindowsPath:
    parts = PurePosixPath(member).parts
    data_indices = tuple(
        index for index, part in enumerate(parts) if part.casefold().endswith(".data")
    )
    if data_indices:
        if (
            len(data_indices) != 1
            or data_indices[0] != 0
            or len(parts) < 3
            or parts[1].casefold() not in {"purelib", "platlib"}
        ):
            _fail()
        parts = parts[2:]
    if not parts:
        _fail()
    relative = PureWindowsPath(*parts)
    top_level = relative.parts[0].casefold()
    if (
        relative.suffix.casefold() in {".pth", ".pyc"}
        or top_level in {"sitecustomize", "usercustomize"}
        or top_level.startswith(("sitecustomize.", "usercustomize."))
    ):
        _fail()
    return relative


@dataclass(frozen=True, slots=True)
class _Member:
    relative_path: PureWindowsPath
    contents: bytes


def _wheel_members(path: Path) -> tuple[_Member, ...]:
    try:
        if (
            path.name != path.name.strip()
            or path.suffix.casefold() != ".whl"
            or not path.is_file()
            or path.is_symlink()
            or not 1 <= path.stat().st_size <= MAX_WHEEL_BYTES
        ):
            _fail()
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= MAX_WHEEL_FILES:
                _fail()
            members: dict[str, bytes] = {}
            folded: set[str] = set()
            expanded = 0
            for info in infos:
                if (
                    info.is_dir()
                    or not _safe_archive_path(info.filename)
                    or info.flag_bits & 0x1
                    or info.compress_type
                    not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or info.file_size > MAX_MEMBER_BYTES
                    or (info.external_attr >> 16) & 0xF000 == 0xA000
                    or info.filename.casefold() in folded
                ):
                    _fail()
                folded.add(info.filename.casefold())
                expanded += info.file_size
                if expanded > MAX_EXPANDED_BYTES:
                    _fail()
                contents = archive.read(info)
                if len(contents) != info.file_size:
                    _fail()
                members[info.filename] = contents
    except LayoutError:
        raise
    except (
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ):
        _fail()

    record_paths = [
        name for name in members if name.casefold().endswith(".dist-info/record")
    ]
    if len(record_paths) != 1:
        _fail()
    record_path = record_paths[0]
    record = _parse_record(members[record_path])
    if set(record) != set(members):
        _fail()

    output: list[_Member] = []
    for name, contents in members.items():
        encoded_hash, encoded_size = record[name]
        if name == record_path:
            if encoded_hash or encoded_size:
                _fail()
        elif (
            _record_digest(encoded_hash) != hashlib.sha256(contents).digest()
            or not encoded_size.isascii()
            or not encoded_size.isdecimal()
            or int(encoded_size) != len(contents)
        ):
            _fail()
        output.append(_Member(_installed_relative(name), contents))
    return tuple(output)


def install_exact_wheels(wheel_paths: Sequence[Path], site_packages: Path) -> None:
    """Write an empty destination's exact, collision-free wheel inventory."""

    try:
        if (
            not wheel_paths
            or len(wheel_paths) > 16
            or not site_packages.is_dir()
            or site_packages.is_symlink()
            or any(site_packages.iterdir())
        ):
            _fail()
    except LayoutError:
        raise
    except OSError:
        _fail()
    all_members: list[_Member] = []
    folded: set[str] = set()
    for wheel_path in wheel_paths:
        if not isinstance(wheel_path, Path):
            _fail()
        for member in _wheel_members(wheel_path):
            key = str(member.relative_path).casefold()
            if key in folded:
                _fail()
            folded.add(key)
            all_members.append(member)

    def cleanup() -> None:
        try:
            children = tuple(site_packages.iterdir())
        except OSError:
            children = ()
        for child in children:
            try:
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink()
            except OSError:
                pass

    try:
        for member in all_members:
            target = site_packages.joinpath(*member.relative_path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(member.contents)
    except LayoutError:
        cleanup()
        raise
    except (OSError, RuntimeError, ValueError):
        cleanup()
        _fail()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--site-packages", required=True, type=Path)
    parser.add_argument("wheels", nargs="+", type=Path)
    args = parser.parse_args(argv)
    try:
        install_exact_wheels(tuple(args.wheels), args.site_packages)
    except LayoutError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
