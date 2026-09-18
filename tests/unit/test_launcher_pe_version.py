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

import towerscout_launcher.pe_version as pe_version_module  # noqa: E402
from towerscout_launcher.pe_version import (  # noqa: E402
    MAX_RANDOM_READ_BYTES,
    MAX_VERSION_RESOURCE_BYTES,
    PeVersionError,
    PeVersionErrorCode,
    parse_pe_version_resource,
)

_PE_OFFSET = 0x80
_OPTIONAL_OFFSET = _PE_OFFSET + 24
_OPTIONAL_SIZE = 0xF0
_SECTION_OFFSET = _OPTIONAL_OFFSET + _OPTIONAL_SIZE
_RAW_OFFSET = 0x200
_RESOURCE_RVA = 0x1000
_RESOURCE_DIRECTORY_OFFSET = _OPTIONAL_OFFSET + 128
_FIELDS = {
    "CompanyName": "Docker Inc",
    "ProductName": "Docker Client",
    "OriginalFilename": "docker-windows-amd64.exe",
    "FileVersion": "29.7.2",
    "ProductVersion": "29.7.2",
}


def _align_four(value: bytearray) -> None:
    value.extend(b"\x00" * ((-len(value)) % 4))


def _block(
    key: str,
    *,
    value_type: int,
    value: bytes = b"",
    children: tuple[bytes, ...] = (),
    value_length: int | None = None,
) -> bytes:
    result = bytearray(b"\x00" * 6)
    result.extend(key.encode("utf-16-le") + b"\x00\x00")
    _align_four(result)
    result.extend(value)
    if children:
        _align_four(result)
        for index, child in enumerate(children):
            if index:
                _align_four(result)
            result.extend(child)
    declared_value_length = (
        value_length
        if value_length is not None
        else len(value) // 2 if value_type == 1 else len(value)
    )
    struct.pack_into("<HHH", result, 0, len(result), declared_value_length, value_type)
    return bytes(result)


def _string_block(key: str, value: str) -> bytes:
    encoded = value.encode("utf-16-le") + b"\x00\x00"
    return _block(key, value_type=1, value=encoded)


def _version_blob(
    *,
    fields: dict[str, str] | None = None,
    tables: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] | None = None,
    translations: tuple[tuple[int, int], ...] = ((0x0409, 0x04B0),),
    fixed_file: tuple[int, int, int, int] = (29, 7, 2, 17),
    fixed_product: tuple[int, int, int, int] = (29, 7, 2, 19),
) -> bytes:
    selected = dict(_FIELDS if fields is None else fields)
    if tables is None:
        tables = (
            (
                "040904B0",
                tuple((name, selected[name]) for name in selected),
            ),
        )
    table_blocks = tuple(
        _block(
            table_key,
            value_type=1,
            children=tuple(_string_block(name, value) for name, value in items),
        )
        for table_key, items in tables
    )
    string_info = _block("StringFileInfo", value_type=1, children=table_blocks)
    translation_bytes = b"".join(
        struct.pack("<HH", language, code_page) for language, code_page in translations
    )
    translation = _block("Translation", value_type=0, value=translation_bytes)
    var_info = _block("VarFileInfo", value_type=1, children=(translation,))
    fixed = struct.pack(
        "<13I",
        0xFEEF04BD,
        0x00010000,
        (fixed_file[0] << 16) | fixed_file[1],
        (fixed_file[2] << 16) | fixed_file[3],
        (fixed_product[0] << 16) | fixed_product[1],
        (fixed_product[2] << 16) | fixed_product[3],
        0x3F,
        0,
        0x00040004,
        1,
        0,
        0,
        0,
    )
    return _block(
        "VS_VERSION_INFO",
        value_type=0,
        value=fixed,
        children=(string_info, var_info),
    )


def _build_pe(blobs: tuple[bytes, ...] | None = None) -> bytes:
    selected_blobs = blobs or (_version_blob(),)
    type_directory = 0x20
    language_directories = tuple(
        0x40 + (index * 0x18) for index in range(len(selected_blobs))
    )
    data_entries_start = 0x40 + (len(selected_blobs) * 0x18)
    data_entries = tuple(
        data_entries_start + (index * 0x10) for index in range(len(selected_blobs))
    )
    blob_cursor = max(0x100, data_entries_start + (len(selected_blobs) * 0x10))
    blob_offsets: list[int] = []
    for blob in selected_blobs:
        blob_cursor = (blob_cursor + 3) & ~3
        blob_offsets.append(blob_cursor)
        blob_cursor += len(blob)
    resource_size = max(0x200, (blob_cursor + 0x1FF) & ~0x1FF)
    resources = bytearray(resource_size)

    struct.pack_into("<HH", resources, 12, 0, 1)
    struct.pack_into("<II", resources, 16, 16, 0x80000000 | type_directory)
    struct.pack_into("<HH", resources, type_directory + 12, 0, len(selected_blobs))
    for index, (language_directory, data_entry, blob_offset, blob) in enumerate(
        zip(
            language_directories,
            data_entries,
            blob_offsets,
            selected_blobs,
            strict=True,
        )
    ):
        struct.pack_into(
            "<II",
            resources,
            type_directory + 16 + (index * 8),
            index + 1,
            0x80000000 | language_directory,
        )
        struct.pack_into("<HH", resources, language_directory + 12, 0, 1)
        struct.pack_into(
            "<II",
            resources,
            language_directory + 16,
            0x0409 + index,
            data_entry,
        )
        struct.pack_into(
            "<IIII",
            resources,
            data_entry,
            _RESOURCE_RVA + blob_offset,
            len(blob),
            1200,
            0,
        )
        resources[blob_offset : blob_offset + len(blob)] = blob

    image = bytearray(_RAW_OFFSET + resource_size)
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
    struct.pack_into("<I", image, _OPTIONAL_OFFSET + 60, _RAW_OFFSET)
    struct.pack_into("<I", image, _OPTIONAL_OFFSET + 108, 16)
    struct.pack_into(
        "<II",
        image,
        _RESOURCE_DIRECTORY_OFFSET,
        _RESOURCE_RVA,
        resource_size,
    )
    image[_SECTION_OFFSET : _SECTION_OFFSET + 8] = b".rsrc\x00\x00\x00"
    struct.pack_into(
        "<IIII",
        image,
        _SECTION_OFFSET + 8,
        resource_size,
        _RESOURCE_RVA,
        resource_size,
        _RAW_OFFSET,
    )
    image[_RAW_OFFSET:] = resources
    return bytes(image)


class _RecordingReader:
    def __init__(self, value: bytes) -> None:
        self.value = value
        self.calls: list[tuple[int, int]] = []

    @property
    def size(self) -> int:
        return len(self.value)

    def read_at(self, offset: int, length: int) -> bytes:
        self.calls.append((offset, length))
        return self.value[offset : offset + length]


def _format_error(value: bytes) -> PeVersionError:
    with pytest.raises(PeVersionError) as failure:
        parse_pe_version_resource(value)
    assert failure.value.code is PeVersionErrorCode.FORMAT_INVALID
    return failure.value


def test_parses_one_strict_pe_version_resource() -> None:
    evidence = parse_pe_version_resource(_build_pe())

    assert evidence.company_name == "Docker Inc"
    assert evidence.product_name == "Docker Client"
    assert evidence.original_filename == "docker-windows-amd64.exe"
    assert evidence.file_version == "29.7.2"
    assert evidence.product_version == "29.7.2"
    assert evidence.fixed_file_version == (29, 7, 2, 17)
    assert evidence.fixed_product_version == (29, 7, 2, 19)
    assert evidence.translations == ((0x0409, 0x04B0),)
    assert evidence.machine == "amd64"
    assert evidence.optional_header_kind == "pe32_plus"
    assert len(evidence.resource_sha256) == 64


def test_result_is_frozen_and_repr_does_not_expose_resource_hash() -> None:
    evidence = parse_pe_version_resource(_build_pe())

    with pytest.raises(FrozenInstanceError):
        evidence.product_version = "29.7.3"  # type: ignore[misc]
    assert evidence.resource_sha256 not in repr(evidence)
    assert "29.7.2" in repr(evidence)


def test_handle_style_reader_is_bounded() -> None:
    value = _build_pe()
    reader = _RecordingReader(value)

    assert parse_pe_version_resource(reader) == parse_pe_version_resource(value)
    assert reader.calls
    assert all(0 <= offset <= len(value) for offset, _ in reader.calls)
    assert all(0 <= length <= MAX_RANDOM_READ_BYTES for _, length in reader.calls)


@pytest.mark.parametrize(
    ("offset", "replacement"),
    (
        (_PE_OFFSET + 4, 0x014C),
        (_OPTIONAL_OFFSET, 0x010B),
        (_OPTIONAL_OFFSET + 108, 2),
    ),
)
def test_rejects_wrong_machine_header_or_directory_count(
    offset: int, replacement: int
) -> None:
    changed = bytearray(_build_pe())
    struct.pack_into(
        "<H" if offset != _OPTIONAL_OFFSET + 108 else "<I", changed, offset, replacement
    )
    _format_error(bytes(changed))


def test_rejects_missing_or_oversized_resource_directory() -> None:
    missing = bytearray(_build_pe())
    struct.pack_into("<II", missing, _RESOURCE_DIRECTORY_OFFSET, 0, 0)
    _format_error(bytes(missing))

    oversized = bytearray(_build_pe())
    struct.pack_into("<I", oversized, _RESOURCE_DIRECTORY_OFFSET + 4, 0xFFFFFFFF)
    _format_error(bytes(oversized))


def test_rejects_multiple_version_names_even_when_bytes_are_identical() -> None:
    _format_error(_build_pe((_version_blob(), _version_blob())))


def test_rejects_string_named_version_resource_without_following_its_pointer() -> None:
    value = bytearray(_build_pe())
    struct.pack_into("<I", value, _RAW_OFFSET + 0x30, 0x80000070)

    _format_error(bytes(value))


@pytest.mark.parametrize("directory_offset", (0, 0x20, 0x40))
def test_rejects_resource_entry_in_wrong_named_or_id_partition(
    directory_offset: int,
) -> None:
    value = bytearray(_build_pe())
    struct.pack_into(
        "<HH",
        value,
        _RAW_OFFSET + directory_offset + 12,
        1,
        0,
    )

    _format_error(bytes(value))


def test_rejects_unsorted_or_out_of_range_numeric_resource_ids() -> None:
    unsorted = bytearray(_build_pe())
    struct.pack_into("<HH", unsorted, _RAW_OFFSET + 12, 0, 2)
    struct.pack_into(
        "<II",
        unsorted,
        _RAW_OFFSET + 24,
        1,
        0x80000020,
    )
    _format_error(bytes(unsorted))

    out_of_range = bytearray(_build_pe())
    struct.pack_into("<I", out_of_range, _RAW_OFFSET + 0x30, 0x00010001)
    _format_error(bytes(out_of_range))


def test_rejects_conflicting_or_duplicate_string_tables() -> None:
    first = tuple((name, value) for name, value in _FIELDS.items())
    conflicting = tuple(
        (name, "Docker Client Changed" if name == "ProductName" else value)
        for name, value in _FIELDS.items()
    )
    blob = _version_blob(
        tables=(("040904B0", first), ("040C04E4", conflicting)),
        translations=((0x0409, 0x04B0), (0x040C, 0x04E4)),
    )
    _format_error(_build_pe((blob,)))

    duplicate = _version_blob(
        tables=(("040904B0", first), ("040904B0", first)),
        translations=((0x0409, 0x04B0),),
    )
    _format_error(_build_pe((duplicate,)))


def test_rejects_duplicate_or_missing_required_string_keys() -> None:
    values = tuple((name, value) for name, value in _FIELDS.items())
    duplicate = values + (("CompanyName", "Docker Inc"),)
    _format_error(_build_pe((_version_blob(tables=(("040904B0", duplicate),)),)))

    missing = tuple(item for item in values if item[0] != "ProductVersion")
    _format_error(_build_pe((_version_blob(tables=(("040904B0", missing),)),)))


def test_rejects_translation_table_mismatch_and_duplicate_translation() -> None:
    _format_error(_build_pe((_version_blob(translations=((0x040C, 0x04E4),)),)))
    _format_error(
        _build_pe((_version_blob(translations=((0x0409, 0x04B0), (0x0409, 0x04B0))),))
    )


def test_rejects_invalid_fixed_header_signature_and_root_length() -> None:
    value = bytearray(_build_pe())
    resource_blob = value.find(struct.pack("<I", 0xFEEF04BD))
    assert resource_blob > 0
    struct.pack_into("<I", value, resource_blob, 0)
    _format_error(bytes(value))

    value = bytearray(_build_pe())
    root = value.find("VS_VERSION_INFO".encode("utf-16-le")) - 6
    assert root > 0
    struct.pack_into("<H", value, root, 5)
    _format_error(bytes(value))


@pytest.mark.parametrize(
    ("field_index", "invalid_value"),
    (
        (6, 0x3E),
        (7, 1),
        (8, 0x00040000),
        (9, 2),
        (10, 1),
        (11, 1),
        (12, 1),
    ),
)
def test_rejects_unsafe_fixed_file_attributes(
    field_index: int,
    invalid_value: int,
) -> None:
    value = bytearray(_build_pe())
    fixed = value.find(struct.pack("<I", 0xFEEF04BD))
    assert fixed > 0
    struct.pack_into("<I", value, fixed + (field_index * 4), invalid_value)

    _format_error(bytes(value))


def test_rejects_nonzero_alignment_padding_and_truncation() -> None:
    value = bytearray(_build_pe())
    root = value.find("VS_VERSION_INFO".encode("utf-16-le")) - 6
    key_end = root + 6 + len("VS_VERSION_INFO".encode("utf-16-le")) + 2
    padding_end = (key_end + 3) & ~3
    assert padding_end > key_end
    value[key_end] = 1
    _format_error(bytes(value))

    _format_error(_build_pe()[:-1])


def test_rejects_oversized_version_data_entry_before_reading() -> None:
    value = bytearray(_build_pe())
    data_entry = _RAW_OFFSET + 0x58
    struct.pack_into("<I", value, data_entry + 4, MAX_VERSION_RESOURCE_BYTES + 1)
    with pytest.raises(PeVersionError) as failure:
        parse_pe_version_resource(bytes(value))
    assert failure.value.code is PeVersionErrorCode.RESOURCE_LIMIT


def test_reader_failure_and_short_read_are_sanitized() -> None:
    class FailingReader:
        size = len(_build_pe())

        def read_at(self, offset: int, length: int) -> bytes:
            raise OSError(r"SECRET C:\private\runtime.exe")

    class ShortReader(_RecordingReader):
        def read_at(self, offset: int, length: int) -> bytes:
            return super().read_at(offset, length)[:-1]

    for reader in (FailingReader(), ShortReader(_build_pe())):
        with pytest.raises(PeVersionError) as failure:
            parse_pe_version_resource(reader)
        assert failure.value.code is PeVersionErrorCode.SOURCE_INVALID
        assert "SECRET" not in str(failure.value)
        assert "private" not in repr(failure.value)


def test_pure_parser_has_no_filesystem_native_process_or_registry_imports() -> None:
    source = Path(pe_version_module.__file__).read_text(encoding="utf-8")
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
