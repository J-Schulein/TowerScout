from __future__ import annotations

import ast
import struct
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.authenticode_pe as authenticode_pe_module  # noqa: E402
from towerscout_launcher.authenticode_pe import (  # noqa: E402
    MAX_CERTIFICATE_TABLE_BYTES,
    MAX_EXECUTABLE_BYTES,
    MAX_RANDOM_READ_BYTES,
    AuthenticodePeError,
    AuthenticodePeErrorCode,
    parse_embedded_authenticode_pe,
)

_PE_OFFSET = 0x80
_OPTIONAL_HEADER_OFFSET = _PE_OFFSET + 24
_OPTIONAL_HEADER_SIZE = 0xF0
_SECTION_TABLE_OFFSET = _OPTIONAL_HEADER_OFFSET + _OPTIONAL_HEADER_SIZE
_SIZE_OF_HEADERS = 0x200
_CERTIFICATE_TABLE_OFFSET = 0x400
_SECURITY_DIRECTORY_OFFSET = _OPTIONAL_HEADER_OFFSET + 144


def _align_to_eight(value: int) -> int:
    return (value + 7) & ~7


def _build_pe(
    *,
    der: bytes = b"\x30\x03\x02\x01\x00",
    declared_padding: bytes = b"",
    certificate_table_offset: int = _CERTIFICATE_TABLE_OFFSET,
    raw_sections: tuple[tuple[int, int], ...] = ((0x200, 0x200),),
) -> bytes:
    win_certificate_length = 8 + len(der) + len(declared_padding)
    certificate_table_size = _align_to_eight(win_certificate_length)
    file_size = certificate_table_offset + certificate_table_size
    image = bytearray(file_size)

    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, _PE_OFFSET)
    image[_PE_OFFSET : _PE_OFFSET + 4] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        image,
        _PE_OFFSET + 4,
        0x8664,
        len(raw_sections),
        0,
        0,
        0,
        _OPTIONAL_HEADER_SIZE,
        0,
    )

    struct.pack_into("<H", image, _OPTIONAL_HEADER_OFFSET, 0x020B)
    struct.pack_into("<I", image, _OPTIONAL_HEADER_OFFSET + 36, 0x200)
    struct.pack_into("<I", image, _OPTIONAL_HEADER_OFFSET + 60, _SIZE_OF_HEADERS)
    struct.pack_into("<I", image, _OPTIONAL_HEADER_OFFSET + 108, 16)
    struct.pack_into(
        "<II",
        image,
        _SECURITY_DIRECTORY_OFFSET,
        certificate_table_offset,
        certificate_table_size,
    )

    for index, (raw_offset, raw_size) in enumerate(raw_sections):
        section_offset = _SECTION_TABLE_OFFSET + (index * 40)
        image[section_offset : section_offset + 8] = f".s{index}".encode("ascii").ljust(
            8, b"\x00"
        )
        struct.pack_into("<I", image, section_offset + 16, raw_size)
        struct.pack_into("<I", image, section_offset + 20, raw_offset)

    struct.pack_into(
        "<IHH",
        image,
        certificate_table_offset,
        win_certificate_length,
        0x0200,
        0x0002,
    )
    payload_offset = certificate_table_offset + 8
    image[payload_offset : payload_offset + len(der)] = der
    padding_offset = payload_offset + len(der)
    image[padding_offset : padding_offset + len(declared_padding)] = declared_padding
    return bytes(image)


def _format_error(value: bytes) -> AuthenticodePeError:
    with pytest.raises(AuthenticodePeError) as failure:
        parse_embedded_authenticode_pe(value)
    assert failure.value.code is AuthenticodePeErrorCode.FORMAT_INVALID
    return failure.value


def _mutate_u16(value: bytes, offset: int, replacement: int) -> bytes:
    changed = bytearray(value)
    struct.pack_into("<H", changed, offset, replacement)
    return bytes(changed)


def _mutate_u32(value: bytes, offset: int, replacement: int) -> bytes:
    changed = bytearray(value)
    struct.pack_into("<I", changed, offset, replacement)
    return bytes(changed)


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


def test_parses_strict_single_embedded_authenticode_layout() -> None:
    value = _build_pe()

    evidence = parse_embedded_authenticode_pe(value)

    assert evidence.file_size == len(value)
    assert evidence.section_count == 1
    assert evidence.image_end_offset == _CERTIFICATE_TABLE_OFFSET
    assert evidence.certificate_table_offset == _CERTIFICATE_TABLE_OFFSET
    assert evidence.certificate_table_size == 16
    assert evidence.win_certificate_length == 13
    assert evidence.pkcs7_der_offset == _CERTIFICATE_TABLE_OFFSET + 8
    assert evidence.pkcs7_der_size == 5
    assert evidence.machine == "amd64"
    assert evidence.optional_header_kind == "pe32_plus"
    assert evidence.certificate_count == 1


def test_result_is_frozen_and_repr_is_redacted() -> None:
    evidence = parse_embedded_authenticode_pe(_build_pe())

    with pytest.raises(FrozenInstanceError):
        evidence.file_size = 1  # type: ignore[misc]

    rendered = repr(evidence)
    assert rendered == (
        "EmbeddedAuthenticodePe(" "machine='amd64', certificate_count=1, <redacted>)"
    )
    assert str(_CERTIFICATE_TABLE_OFFSET) not in rendered


def test_injected_reader_is_bounded_and_matches_bytes_result() -> None:
    value = _build_pe()
    reader = _RecordingReader(value)

    evidence = parse_embedded_authenticode_pe(reader)

    assert evidence == parse_embedded_authenticode_pe(value)
    assert reader.calls
    assert all(0 < length <= MAX_RANDOM_READ_BYTES for _, length in reader.calls)
    assert all(
        0 <= offset <= len(value) and length <= len(value) - offset
        for offset, length in reader.calls
    )
    assert max(length for _, length in reader.calls) < len(value)


@pytest.mark.parametrize(
    ("offset", "replacement"),
    (
        (_PE_OFFSET + 4, 0x014C),
        (_PE_OFFSET + 6, 0),
        (_PE_OFFSET + 6, 97),
        (_PE_OFFSET + 20, 151),
        (_PE_OFFSET + 20, 4097),
        (_OPTIONAL_HEADER_OFFSET, 0x010B),
    ),
)
def test_rejects_wrong_machine_section_count_and_optional_header(
    offset: int, replacement: int
) -> None:
    _format_error(_mutate_u16(_build_pe(), offset, replacement))


def test_rejects_invalid_dos_and_pe_headers() -> None:
    value = bytearray(_build_pe())
    value[:2] = b"NZ"
    _format_error(bytes(value))

    value = bytearray(_build_pe())
    value[_PE_OFFSET : _PE_OFFSET + 4] = b"PX\x00\x00"
    _format_error(bytes(value))

    _format_error(_mutate_u32(_build_pe(), 0x3C, 0xFFFFFFFF))
    _format_error(b"MZ")


def test_rejects_missing_or_inconsistent_security_directory() -> None:
    value = _build_pe()
    _format_error(_mutate_u32(value, _SECURITY_DIRECTORY_OFFSET, 0))
    _format_error(_mutate_u32(value, _SECURITY_DIRECTORY_OFFSET + 4, 0))
    _format_error(_mutate_u32(value, _OPTIONAL_HEADER_OFFSET + 108, 4))
    _format_error(_mutate_u32(value, _OPTIONAL_HEADER_OFFSET + 108, 17))


def test_rejects_unaligned_out_of_bounds_and_oversized_certificate_table() -> None:
    _format_error(_build_pe(certificate_table_offset=0x401))

    value = _build_pe()
    value = _mutate_u32(value, _SECURITY_DIRECTORY_OFFSET, 0xFFFFFFF8)
    _format_error(value)

    value = _mutate_u32(
        _build_pe(),
        _SECURITY_DIRECTORY_OFFSET + 4,
        MAX_CERTIFICATE_TABLE_BYTES + 1,
    )
    with pytest.raises(AuthenticodePeError) as failure:
        parse_embedded_authenticode_pe(value)
    assert failure.value.code is AuthenticodePeErrorCode.RESOURCE_LIMIT


def test_rejects_overlay_after_certificate_table() -> None:
    _format_error(_build_pe() + b"untrusted-overlay")


def test_rejects_certificate_table_that_does_not_reach_eof() -> None:
    value = _build_pe()
    changed = _mutate_u32(value, _SECURITY_DIRECTORY_OFFSET + 4, len(value) - 1 - 0x400)
    _format_error(changed)


def test_rejects_large_or_nonzero_pre_table_gap() -> None:
    _format_error(_build_pe(raw_sections=((0x200, 0x1F8),)))

    value = bytearray(_build_pe(raw_sections=((0x200, 0x1FF),)))
    value[0x3FF] = 1
    _format_error(bytes(value))


def test_accepts_at_most_seven_zero_pre_table_alignment_bytes() -> None:
    evidence = parse_embedded_authenticode_pe(_build_pe(raw_sections=((0x200, 0x1F9),)))

    assert evidence.image_end_offset == 0x3F9
    assert evidence.certificate_table_offset - evidence.image_end_offset == 7


def test_rejects_headers_or_sections_overlapping_certificate_table() -> None:
    value = _mutate_u32(_build_pe(), _OPTIONAL_HEADER_OFFSET + 60, 0x408)
    _format_error(value)

    value = _mutate_u32(_build_pe(), _SECTION_TABLE_OFFSET + 16, 0x208)
    _format_error(value)

    value = _mutate_u32(_build_pe(), _SECTION_TABLE_OFFSET + 20, _SIZE_OF_HEADERS - 1)
    _format_error(value)


def test_rejects_overlapping_section_raw_ranges() -> None:
    value = _build_pe(raw_sections=((0x200, 0x180), (0x300, 0x100)))
    _format_error(value)


@pytest.mark.parametrize(
    ("field_offset", "replacement"),
    (
        (0, 9),
        (0, 17),
        (0, 0xFFFFFFFF),
        (4, 0x0100),
        (4, 0x0201),
        (6, 0x0001),
        (6, 0x0003),
    ),
)
def test_rejects_invalid_win_certificate_header(
    field_offset: int, replacement: int
) -> None:
    value = _build_pe()
    absolute_offset = _CERTIFICATE_TABLE_OFFSET + field_offset
    if field_offset == 0:
        changed = _mutate_u32(value, absolute_offset, replacement)
    else:
        changed = _mutate_u16(value, absolute_offset, replacement)
    _format_error(changed)


def test_rejects_multiple_win_certificate_entries() -> None:
    value = _build_pe()
    first_entry = value[_CERTIFICATE_TABLE_OFFSET:]
    changed = bytearray(value + first_entry)
    struct.pack_into(
        "<I",
        changed,
        _SECURITY_DIRECTORY_OFFSET + 4,
        len(first_entry) * 2,
    )

    _format_error(bytes(changed))


def test_rejects_nonzero_certificate_alignment_or_declared_padding() -> None:
    value = bytearray(_build_pe())
    value[-1] = 1
    _format_error(bytes(value))

    _format_error(_build_pe(declared_padding=b"\x01"))


@pytest.mark.parametrize(
    "der",
    (
        b"\x31\x03\x02\x01\x00",
        b"\x30\x80\x00\x00",
        b"\x30\x81\x01\x00",
        b"\x30\x82\x00\x80" + (b"\x00" * 128),
        b"\x30\x85\x01\x00\x00\x00\x00",
        b"\x30\x82\x01\x00",
        b"\x30\x00",
    ),
)
def test_rejects_non_der_or_noncanonical_outer_object(der: bytes) -> None:
    _format_error(_build_pe(der=der))


def test_accepts_definite_canonical_long_form_der_length() -> None:
    der = b"\x30\x81\x80" + (b"\x00" * 128)

    evidence = parse_embedded_authenticode_pe(_build_pe(der=der))

    assert evidence.pkcs7_der_size == len(der)


def test_reader_failures_are_fail_closed_and_sanitized() -> None:
    class FailingReader:
        size = len(_build_pe())

        def read_at(self, offset: int, length: int) -> bytes:
            raise OSError(r"SECRET C:\private\runtime.exe")

    with pytest.raises(AuthenticodePeError) as failure:
        parse_embedded_authenticode_pe(FailingReader())

    assert failure.value.code is AuthenticodePeErrorCode.SOURCE_INVALID
    assert "SECRET" not in str(failure.value)
    assert "private" not in repr(failure.value)


def test_reader_rejects_short_or_nonbytes_reads() -> None:
    class ShortReader(_RecordingReader):
        def read_at(self, offset: int, length: int) -> bytes:
            return super().read_at(offset, length)[:-1]

    class NonBytesReader(_RecordingReader):
        def read_at(self, offset: int, length: int) -> bytes:  # type: ignore[override]
            super().read_at(offset, length)
            return bytearray(length)  # type: ignore[return-value]

    for reader in (ShortReader(_build_pe()), NonBytesReader(_build_pe())):
        with pytest.raises(AuthenticodePeError) as failure:
            parse_embedded_authenticode_pe(reader)
        assert failure.value.code is AuthenticodePeErrorCode.SOURCE_INVALID


def test_reader_rejects_invalid_or_excessive_declared_size() -> None:
    class InvalidSizeReader:
        size = True

        def read_at(self, offset: int, length: int) -> bytes:
            return b""

    class ExcessiveSizeReader:
        size = MAX_EXECUTABLE_BYTES + 1

        def read_at(self, offset: int, length: int) -> bytes:
            return b""

    with pytest.raises(AuthenticodePeError) as invalid:
        parse_embedded_authenticode_pe(InvalidSizeReader())
    assert invalid.value.code is AuthenticodePeErrorCode.SOURCE_INVALID

    with pytest.raises(AuthenticodePeError) as excessive:
        parse_embedded_authenticode_pe(ExcessiveSizeReader())
    assert excessive.value.code is AuthenticodePeErrorCode.RESOURCE_LIMIT


def test_module_has_no_filesystem_process_native_or_ctypes_imports() -> None:
    source = Path(authenticode_pe_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.partition(".")[0])

    assert imported_roots.isdisjoint(
        {"ctypes", "os", "pathlib", "shutil", "subprocess", "winreg"}
    )
