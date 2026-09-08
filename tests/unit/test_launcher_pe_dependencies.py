from __future__ import annotations

import struct
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.pe_dependencies import (  # noqa: E402
    MAX_PE_DEPENDENCY_READ_BYTES,
    PeDependencyError,
    PeDependencyErrorCode,
    PeDependencyManifest,
    parse_pe_dependencies,
)

_PE_OFFSET = 0x80
_OPTIONAL_OFFSET = _PE_OFFSET + 24
_OPTIONAL_SIZE = 0xF0
_SECTION_TABLE_OFFSET = _OPTIONAL_OFFSET + _OPTIONAL_SIZE
_HEADERS_SIZE = 0x200
_SECTION_RAW_OFFSET = 0x200
_SECTION_RVA = 0x1000
_SECTION_SIZE = 0x600
_IMPORT_TABLE_OFFSET = 0x200
_DELAY_TABLE_OFFSET = 0x300
_EXPORT_TABLE_OFFSET = 0x380
_EXPORT_FUNCTIONS_OFFSET = 0x3C0
_FORWARDER_OFFSET = 0x400
_NAME_OFFSET = 0x500


def _rva(offset: int) -> int:
    return _SECTION_RVA + offset - _SECTION_RAW_OFFSET


def _build_pe(
    *,
    direct: tuple[str, ...] = ("KERNEL32.dll",),
    delay: tuple[str, ...] = ("WS2_32.dll",),
    forwarded: tuple[str, ...] = (),
    delay_attributes: int = 1,
) -> bytes:
    image = bytearray(_SECTION_RAW_OFFSET + _SECTION_SIZE)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, _PE_OFFSET)
    image[_PE_OFFSET : _PE_OFFSET + 4] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        image,
        _PE_OFFSET + 4,
        0x8664,
        1,
        0,
        0,
        0,
        _OPTIONAL_SIZE,
        0,
    )
    struct.pack_into("<H", image, _OPTIONAL_OFFSET, 0x020B)
    struct.pack_into("<I", image, _OPTIONAL_OFFSET + 60, _HEADERS_SIZE)
    struct.pack_into("<I", image, _OPTIONAL_OFFSET + 108, 16)

    section = _SECTION_TABLE_OFFSET
    image[section : section + 8] = b".rdata\x00\x00"
    struct.pack_into(
        "<IIII",
        image,
        section + 8,
        _SECTION_SIZE,
        _SECTION_RVA,
        _SECTION_SIZE,
        _SECTION_RAW_OFFSET,
    )

    name_cursor = _NAME_OFFSET
    for index, name in enumerate(direct):
        encoded = name.encode("ascii") + b"\x00"
        image[name_cursor : name_cursor + len(encoded)] = encoded
        descriptor = _IMPORT_TABLE_OFFSET + (index * 20)
        struct.pack_into("<I", image, descriptor + 12, _rva(name_cursor))
        name_cursor += len(encoded)
    direct_size = (len(direct) + 1) * 20 if direct else 0
    if direct:
        struct.pack_into(
            "<II",
            image,
            _OPTIONAL_OFFSET + 112 + 8,
            _rva(_IMPORT_TABLE_OFFSET),
            direct_size,
        )

    for index, name in enumerate(delay):
        encoded = name.encode("ascii") + b"\x00"
        image[name_cursor : name_cursor + len(encoded)] = encoded
        descriptor = _DELAY_TABLE_OFFSET + (index * 32)
        struct.pack_into("<I", image, descriptor, delay_attributes)
        struct.pack_into("<I", image, descriptor + 4, _rva(name_cursor))
        name_cursor += len(encoded)
    delay_size = (len(delay) + 1) * 32 if delay else 0
    if delay:
        struct.pack_into(
            "<II",
            image,
            _OPTIONAL_OFFSET + 112 + (13 * 8),
            _rva(_DELAY_TABLE_OFFSET),
            delay_size,
        )
    forwarder_cursor = _FORWARDER_OFFSET
    for index, value in enumerate(forwarded):
        encoded = value.encode("ascii") + b"\x00"
        image[forwarder_cursor : forwarder_cursor + len(encoded)] = encoded
        struct.pack_into(
            "<I",
            image,
            _EXPORT_FUNCTIONS_OFFSET + (index * 4),
            _rva(forwarder_cursor),
        )
        forwarder_cursor += len(encoded)
    if forwarded:
        export_size = forwarder_cursor - _EXPORT_TABLE_OFFSET
        struct.pack_into(
            "<II",
            image,
            _OPTIONAL_OFFSET + 112,
            _rva(_EXPORT_TABLE_OFFSET),
            export_size,
        )
        struct.pack_into("<I", image, _EXPORT_TABLE_OFFSET + 20, len(forwarded))
        struct.pack_into(
            "<I",
            image,
            _EXPORT_TABLE_OFFSET + 28,
            _rva(_EXPORT_FUNCTIONS_OFFSET),
        )
    return bytes(image)


def _format_error(value: bytes) -> PeDependencyError:
    with pytest.raises(PeDependencyError) as failure:
        parse_pe_dependencies(value)
    assert failure.value.code is PeDependencyErrorCode.FORMAT_INVALID
    return failure.value


class _RecordingReader:
    def __init__(self, value: bytes) -> None:
        self._value = value
        self.calls: list[tuple[int, int]] = []

    @property
    def size(self) -> int:
        return len(self._value)

    def read_at(self, offset: int, length: int) -> bytes:
        self.calls.append((offset, length))
        return self._value[offset : offset + length]


def test_parses_and_canonicalizes_direct_and_delay_imports() -> None:
    manifest = parse_pe_dependencies(
        _build_pe(
            direct=("USER32.DLL", "KERNEL32.dll"),
            delay=("WS2_32.dll",),
            forwarded=("NTDLL.RtlAllocateHeap",),
        )
    )

    assert manifest.direct_imports == ("kernel32.dll", "user32.dll")
    assert manifest.delay_imports == ("ws2_32.dll",)
    assert manifest.forwarded_imports == ("ntdll.dll",)
    assert len(manifest.evidence_sha256) == 64
    assert repr(manifest) == (
        "PeDependencyManifest("
        "direct_count=2, delay_count=1, forwarded_count=1, <redacted>)"
    )
    with pytest.raises(FrozenInstanceError):
        manifest.direct_imports = ()  # type: ignore[misc]


def test_reader_access_is_bounded_and_does_not_read_the_whole_image() -> None:
    value = _build_pe()
    reader = _RecordingReader(value)

    assert parse_pe_dependencies(reader) == parse_pe_dependencies(value)
    assert reader.calls
    assert max(length for _, length in reader.calls) <= MAX_PE_DEPENDENCY_READ_BYTES
    assert all(length < len(value) for _, length in reader.calls)


def test_manifest_model_rejects_a_forged_evidence_digest() -> None:
    with pytest.raises(ValueError):
        PeDependencyManifest(
            direct_imports=("kernel32.dll",),
            delay_imports=(),
            forwarded_imports=(),
            evidence_sha256="0" * 64,
        )


@pytest.mark.parametrize(
    "name",
    (
        "..\\evil.dll",
        "folder/evil.dll",
        "evil.dll:stream",
        "evil.exe",
        "trailing.dll.",
        "white space.dll",
    ),
)
def test_rejects_noncanonical_dependency_leaf_names(name: str) -> None:
    _format_error(_build_pe(direct=(name,), delay=()))


def test_rejects_duplicate_or_cross_table_duplicate_names() -> None:
    _format_error(_build_pe(direct=("same.dll", "SAME.DLL"), delay=()))
    _format_error(_build_pe(direct=("same.dll",), delay=("SAME.DLL",)))
    _format_error(_build_pe(direct=("same.dll",), delay=(), forwarded=("SAME.Target",)))


@pytest.mark.parametrize(
    "forwarder",
    ("missing_separator", ".Target", "MODULE.", "folder\\evil.Target"),
)
def test_rejects_invalid_export_forwarder_names(forwarder: str) -> None:
    _format_error(_build_pe(direct=(), delay=(), forwarded=(forwarder,)))


def test_rejects_legacy_or_unknown_delay_attributes_and_unsupported_directories() -> (
    None
):
    _format_error(_build_pe(delay_attributes=0))
    _format_error(_build_pe(delay_attributes=3))

    value = bytearray(_build_pe())
    struct.pack_into(
        "<II",
        value,
        _OPTIONAL_OFFSET + 112 + (11 * 8),
        _SECTION_RVA,
        8,
    )
    _format_error(bytes(value))

    value = bytearray(_build_pe())
    struct.pack_into(
        "<II",
        value,
        _OPTIONAL_OFFSET + 112 + (14 * 8),
        _SECTION_RVA,
        8,
    )
    _format_error(bytes(value))


def test_rejects_unterminated_descriptor_or_leaf_name() -> None:
    value = bytearray(_build_pe(direct=("one.dll",), delay=()))
    struct.pack_into(
        "<I",
        value,
        _OPTIONAL_OFFSET + 112 + 8 + 4,
        20,
    )
    _format_error(bytes(value))

    value = bytearray(_build_pe(direct=("one.dll",), delay=()))
    value[_NAME_OFFSET : _NAME_OFFSET + 256] = b"a" * 256
    _format_error(bytes(value))


@pytest.mark.parametrize(
    ("offset", "replacement", "kind"),
    (
        (0, b"NO", PeDependencyErrorCode.FORMAT_INVALID),
        (
            _PE_OFFSET + 4,
            struct.pack("<H", 0x014C),
            PeDependencyErrorCode.FORMAT_INVALID,
        ),
        (
            _OPTIONAL_OFFSET,
            struct.pack("<H", 0x010B),
            PeDependencyErrorCode.FORMAT_INVALID,
        ),
    ),
)
def test_rejects_invalid_pe_headers(
    offset: int, replacement: bytes, kind: PeDependencyErrorCode
) -> None:
    value = bytearray(_build_pe())
    value[offset : offset + len(replacement)] = replacement
    with pytest.raises(PeDependencyError) as failure:
        parse_pe_dependencies(bytes(value))
    assert failure.value.code is kind


def test_source_failures_are_sanitized() -> None:
    class BrokenReader:
        size = 512

        def read_at(self, offset: int, length: int) -> bytes:
            del offset, length
            raise OSError(r"C:\Users\private-user\secret.exe")

    with pytest.raises(PeDependencyError) as failure:
        parse_pe_dependencies(BrokenReader())

    assert failure.value.code is PeDependencyErrorCode.SOURCE_INVALID
    assert "private-user" not in str(failure.value)
