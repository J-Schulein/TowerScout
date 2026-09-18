"""Bounded, filesystem-free parsing of one PE ``RT_VERSION`` resource.

The parser accepts immutable bytes or a random-access reader backed by an
already-held executable handle.  It never opens a path, consults Windows
version APIs, or assigns product trust.  Successful parsing proves only that
one AMD64 PE32+ image contains an unambiguous, internally consistent version
resource whose facts can be matched by the higher-level runtime policy.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn, Protocol

MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
MAX_VERSION_RESOURCE_BYTES = 256 * 1024
MAX_RANDOM_READ_BYTES = 64 * 1024

_MAX_PE_HEADER_OFFSET = 1024 * 1024
_MAX_OPTIONAL_HEADER_BYTES = 4096
_MAX_SECTION_COUNT = 96
_MAX_RESOURCE_DIRECTORY_BYTES = 16 * 1024 * 1024
_MAX_DIRECTORY_ENTRIES = 128
_MAX_VERSION_RESOURCES = 16
_MAX_VERSION_BLOCKS = 256
_MAX_VERSION_TEXT_CHARACTERS = 1024
_DOS_HEADER_BYTES = 64
_PE_FIXED_HEADER_BYTES = 24
_SECTION_HEADER_BYTES = 40
_PE32_PLUS_MINIMUM_OPTIONAL_HEADER_BYTES = 152
_PE32_PLUS_DATA_DIRECTORY_OFFSET = 112
_RESOURCE_DIRECTORY_OFFSET = _PE32_PLUS_DATA_DIRECTORY_OFFSET + (2 * 8)
_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_PE32_PLUS_MAGIC = 0x020B
_RT_VERSION = 16
_VS_FIXEDFILEINFO_SIGNATURE = 0xFEEF04BD
_VS_FIXEDFILEINFO_VERSION = 0x00010000
_VS_FIXEDFILEINFO_BYTES = 52
_REQUIRED_STRING_FIELDS = (
    "CompanyName",
    "ProductName",
    "OriginalFilename",
    "FileVersion",
    "ProductVersion",
)
_STRING_TABLE_KEY = re.compile(r"^[0-9A-Fa-f]{8}$")


class RandomAccessReader(Protocol):
    """Small random-access interface suitable for a held Windows handle."""

    @property
    def size(self) -> int: ...

    def read_at(self, offset: int, length: int) -> bytes: ...


class PeVersionErrorCode(str, Enum):
    SOURCE_INVALID = "source_invalid"
    RESOURCE_LIMIT = "resource_limit"
    FORMAT_INVALID = "format_invalid"


class PeVersionError(ValueError):
    """Sanitized failure raised for malformed or unavailable PE evidence."""

    _MESSAGES = {
        PeVersionErrorCode.SOURCE_INVALID: (
            "The executable byte source is unavailable."
        ),
        PeVersionErrorCode.RESOURCE_LIMIT: (
            "The executable version resource exceeds fixed safety limits."
        ),
        PeVersionErrorCode.FORMAT_INVALID: (
            "The executable version resource is invalid."
        ),
    }

    def __init__(self, code: PeVersionErrorCode) -> None:
        if type(code) is not PeVersionErrorCode:
            raise ValueError("Unknown PE version error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"PeVersionError(code={self.code.value!r})"


@dataclass(frozen=True, slots=True, repr=False)
class PeVersionResource:
    """Public-safe product/version facts from all consistent translations."""

    company_name: str
    product_name: str
    original_filename: str
    file_version: str
    product_version: str
    fixed_file_version: tuple[int, int, int, int]
    fixed_product_version: tuple[int, int, int, int]
    translations: tuple[tuple[int, int], ...]
    resource_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        texts = (
            self.company_name,
            self.product_name,
            self.original_filename,
            self.file_version,
            self.product_version,
        )
        versions = (self.fixed_file_version, self.fixed_product_version)
        if (
            any(
                type(value) is not str
                or not value
                or len(value) > _MAX_VERSION_TEXT_CHARACTERS
                or "\x00" in value
                for value in texts
            )
            or any(
                type(value) is not tuple
                or len(value) != 4
                or any(
                    type(part) is not int or not 0 <= part <= 0xFFFF for part in value
                )
                for value in versions
            )
            or type(self.translations) is not tuple
            or not self.translations
            or len(self.translations) > _MAX_VERSION_RESOURCES
            or tuple(sorted(set(self.translations))) != self.translations
            or any(
                type(item) is not tuple
                or len(item) != 2
                or any(
                    type(part) is not int or not 0 <= part <= 0xFFFF for part in item
                )
                for item in self.translations
            )
            or type(self.resource_sha256) is not str
            or len(self.resource_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.resource_sha256
            )
        ):
            raise ValueError("PE version evidence is invalid.")

    @property
    def machine(self) -> str:
        return "amd64"

    @property
    def optional_header_kind(self) -> str:
        return "pe32_plus"

    def __repr__(self) -> str:
        return (
            "PeVersionResource("
            f"version={self.product_version!r}, translations="
            f"{len(self.translations)}, <redacted>)"
        )


class _BytesReader:
    __slots__ = ("_value",)

    def __init__(self, value: bytes) -> None:
        self._value = value

    @property
    def size(self) -> int:
        return len(self._value)

    def read_at(self, offset: int, length: int) -> bytes:
        return self._value[offset : offset + length]


class _CheckedReader:
    __slots__ = ("_read_at", "size")

    def __init__(self, source: bytes | RandomAccessReader) -> None:
        reader: RandomAccessReader
        if isinstance(source, bytes):
            reader = _BytesReader(source)
        else:
            reader = source
        try:
            size = reader.size
            read_at = reader.read_at
        except Exception:
            _fail(PeVersionErrorCode.SOURCE_INVALID)
        if type(size) is not int or size < 0 or not callable(read_at):
            _fail(PeVersionErrorCode.SOURCE_INVALID)
        if size > MAX_EXECUTABLE_BYTES:
            _fail(PeVersionErrorCode.RESOURCE_LIMIT)
        self.size = size
        self._read_at = read_at

    def read_exact(self, offset: int, length: int) -> bytes:
        if (
            type(offset) is not int
            or type(length) is not int
            or offset < 0
            or length < 0
            or length > MAX_RANDOM_READ_BYTES
            or offset > self.size
            or length > self.size - offset
        ):
            _fail(PeVersionErrorCode.FORMAT_INVALID)
        try:
            value = self._read_at(offset, length)
        except Exception:
            _fail(PeVersionErrorCode.SOURCE_INVALID)
        if not isinstance(value, bytes) or len(value) != length:
            _fail(PeVersionErrorCode.SOURCE_INVALID)
        return value

    def read_bounded(self, offset: int, length: int, maximum: int) -> bytes:
        if type(length) is not int or length < 0 or length > maximum:
            _fail(PeVersionErrorCode.RESOURCE_LIMIT)
        result = bytearray()
        cursor = offset
        remaining = length
        while remaining:
            amount = min(remaining, MAX_RANDOM_READ_BYTES)
            result.extend(self.read_exact(cursor, amount))
            cursor += amount
            remaining -= amount
        return bytes(result)


@dataclass(frozen=True, slots=True)
class _Section:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclass(frozen=True, slots=True)
class _PeLayout:
    reader: _CheckedReader
    sections: tuple[_Section, ...]
    resource_rva: int
    resource_size: int

    def map_rva(self, rva: int, length: int) -> int:
        if (
            type(rva) is not int
            or type(length) is not int
            or rva < 0
            or length < 0
            or rva > 0xFFFFFFFF
            or length > 0xFFFFFFFF - rva
        ):
            _fail(PeVersionErrorCode.FORMAT_INVALID)
        matches: list[int] = []
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if not section.virtual_address <= rva < section.virtual_address + span:
                continue
            delta = rva - section.virtual_address
            if delta > section.raw_size or length > section.raw_size - delta:
                continue
            raw = section.raw_offset + delta
            if raw > self.reader.size or length > self.reader.size - raw:
                continue
            matches.append(raw)
        if len(matches) != 1:
            _fail(PeVersionErrorCode.FORMAT_INVALID)
        return matches[0]

    def read_resource_relative(self, relative: int, length: int) -> bytes:
        if (
            type(relative) is not int
            or type(length) is not int
            or relative < 0
            or length < 0
            or relative > self.resource_size
            or length > self.resource_size - relative
        ):
            _fail(PeVersionErrorCode.FORMAT_INVALID)
        offset = self.map_rva(self.resource_rva + relative, length)
        return self.reader.read_exact(offset, length)


@dataclass(frozen=True, slots=True)
class _VersionBlock:
    start: int
    end: int
    value_length: int
    value_type: int
    key: str
    value_offset: int
    value_size: int
    children_offset: int


def _fail(code: PeVersionErrorCode) -> NoReturn:
    raise PeVersionError(code)


def _checked_end(offset: int, length: int, upper_bound: int) -> int:
    if (
        type(offset) is not int
        or type(length) is not int
        or type(upper_bound) is not int
        or offset < 0
        or length < 0
        or upper_bound < 0
        or offset > upper_bound
        or length > upper_bound - offset
    ):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    return offset + length


def _align_four(value: int, upper_bound: int) -> int:
    if type(value) is not int or value < 0 or value > upper_bound:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    aligned = (value + 3) & ~3
    if aligned > upper_bound:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    return aligned


def _require_zero(value: bytes) -> None:
    if any(value):
        _fail(PeVersionErrorCode.FORMAT_INVALID)


def _parse_layout(reader: _CheckedReader) -> _PeLayout:
    if reader.size < _DOS_HEADER_BYTES:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    dos = reader.read_exact(0, _DOS_HEADER_BYTES)
    if dos[:2] != b"MZ":
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    if pe_offset < _DOS_HEADER_BYTES or pe_offset > _MAX_PE_HEADER_OFFSET:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    _checked_end(pe_offset, _PE_FIXED_HEADER_BYTES, reader.size)
    fixed = reader.read_exact(pe_offset, _PE_FIXED_HEADER_BYTES)
    if fixed[:4] != b"PE\x00\x00":
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    machine, section_count = struct.unpack_from("<HH", fixed, 4)
    if machine != _IMAGE_FILE_MACHINE_AMD64 or not 0 < section_count <= (
        _MAX_SECTION_COUNT
    ):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    optional_size = struct.unpack_from("<H", fixed, 20)[0]
    if not (
        _PE32_PLUS_MINIMUM_OPTIONAL_HEADER_BYTES
        <= optional_size
        <= _MAX_OPTIONAL_HEADER_BYTES
    ):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    optional_offset = pe_offset + _PE_FIXED_HEADER_BYTES
    optional_end = _checked_end(optional_offset, optional_size, reader.size)
    optional = reader.read_exact(optional_offset, optional_size)
    if struct.unpack_from("<H", optional, 0)[0] != _PE32_PLUS_MAGIC:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    directory_count = struct.unpack_from("<I", optional, 108)[0]
    available = (optional_size - _PE32_PLUS_DATA_DIRECTORY_OFFSET) // 8
    if directory_count < 3 or directory_count > available:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    resource_rva, resource_size = struct.unpack_from(
        "<II", optional, _RESOURCE_DIRECTORY_OFFSET
    )
    if (
        resource_rva == 0
        or resource_size < 16
        or resource_size > _MAX_RESOURCE_DIRECTORY_BYTES
        or resource_rva > 0xFFFFFFFF - resource_size
    ):
        _fail(PeVersionErrorCode.FORMAT_INVALID)

    table_size = section_count * _SECTION_HEADER_BYTES
    table_end = _checked_end(optional_end, table_size, reader.size)
    section_bytes = reader.read_exact(optional_end, table_size)
    sections: list[_Section] = []
    raw_intervals: list[tuple[int, int]] = []
    virtual_intervals: list[tuple[int, int]] = []
    for index in range(section_count):
        offset = index * _SECTION_HEADER_BYTES
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", section_bytes, offset + 8
        )
        if raw_size:
            raw_end = _checked_end(raw_offset, raw_size, reader.size)
            if raw_offset < table_end:
                _fail(PeVersionErrorCode.FORMAT_INVALID)
            raw_intervals.append((raw_offset, raw_end))
        span = max(virtual_size, raw_size)
        if span:
            if virtual_address > 0xFFFFFFFF - span:
                _fail(PeVersionErrorCode.FORMAT_INVALID)
            virtual_intervals.append((virtual_address, virtual_address + span))
        sections.append(
            _Section(
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
            )
        )
    for intervals in (raw_intervals, virtual_intervals):
        intervals.sort()
        if any(
            current[0] < previous[1]
            for previous, current in zip(intervals, intervals[1:])
        ):
            _fail(PeVersionErrorCode.FORMAT_INVALID)
    layout = _PeLayout(reader, tuple(sections), resource_rva, resource_size)
    layout.map_rva(resource_rva, resource_size)
    return layout


def _record_resource_range(
    ranges: set[tuple[int, int]], start: int, length: int
) -> None:
    end = _checked_end(start, length, 0xFFFFFFFF)
    if any(
        start < prior_end and prior_start < end for prior_start, prior_end in ranges
    ):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    ranges.add((start, end))


def _directory_entries(
    layout: _PeLayout,
    relative: int,
    ranges: set[tuple[int, int]],
) -> tuple[tuple[int, int], ...]:
    header = layout.read_resource_relative(relative, 16)
    named, identified = struct.unpack_from("<HH", header, 12)
    count = named + identified
    if count == 0 or count > _MAX_DIRECTORY_ENTRIES:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    size = count * 8
    _record_resource_range(ranges, relative, 16 + size)
    raw = layout.read_resource_relative(relative + 16, size)
    entries = tuple(struct.unpack_from("<II", raw, index * 8) for index in range(count))
    if any(
        bool(name & 0x80000000) != (index < named)
        for index, (name, _offset) in enumerate(entries)
    ):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    numeric_ids = tuple(name for name, _offset in entries[named:])
    if any(value > 0xFFFF for value in numeric_ids) or any(
        current <= previous for previous, current in zip(numeric_ids, numeric_ids[1:])
    ):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    return entries


def _version_resource_blobs(layout: _PeLayout) -> tuple[bytes, ...]:
    metadata_ranges: set[tuple[int, int]] = set()
    root = _directory_entries(layout, 0, metadata_ranges)
    type_entries = [
        offset for name, offset in root if not name & 0x80000000 and name == _RT_VERSION
    ]
    if len(type_entries) != 1 or not type_entries[0] & 0x80000000:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    name_directory = type_entries[0] & 0x7FFFFFFF
    names = _directory_entries(layout, name_directory, metadata_ranges)
    if len(names) != 1:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    blobs: list[bytes] = []
    data_ranges: set[tuple[int, int]] = set()
    for resource_name, language_directory_value in names:
        if resource_name & 0x80000000 or not language_directory_value & 0x80000000:
            _fail(PeVersionErrorCode.FORMAT_INVALID)
        languages = _directory_entries(
            layout,
            language_directory_value & 0x7FFFFFFF,
            metadata_ranges,
        )
        if len(languages) != 1:
            _fail(PeVersionErrorCode.FORMAT_INVALID)
        for language, data_entry_value in languages:
            if language & 0x80000000 or data_entry_value & 0x80000000:
                _fail(PeVersionErrorCode.FORMAT_INVALID)
            _record_resource_range(metadata_ranges, data_entry_value, 16)
            data_entry = layout.read_resource_relative(data_entry_value, 16)
            data_rva, size, _code_page, reserved = struct.unpack("<IIII", data_entry)
            if (
                reserved != 0
                or size == 0
                or size > MAX_VERSION_RESOURCE_BYTES
                or len(blobs) >= _MAX_VERSION_RESOURCES
            ):
                _fail(PeVersionErrorCode.RESOURCE_LIMIT)
            offset = layout.map_rva(data_rva, size)
            metadata_raw_ranges = tuple(
                (
                    layout.map_rva(layout.resource_rva + start, end - start),
                    end - start,
                )
                for start, end in metadata_ranges
            )
            if any(
                offset < metadata_offset + metadata_size
                and metadata_offset < offset + size
                for metadata_offset, metadata_size in metadata_raw_ranges
            ):
                _fail(PeVersionErrorCode.FORMAT_INVALID)
            identity = (offset, size)
            if identity in data_ranges:
                _fail(PeVersionErrorCode.FORMAT_INVALID)
            data_ranges.add(identity)
            blobs.append(
                layout.reader.read_bounded(offset, size, MAX_VERSION_RESOURCE_BYTES)
            )
    if not blobs:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    return tuple(blobs)


def _read_utf16_key(value: bytes, offset: int, end: int) -> tuple[str, int]:
    cursor = offset
    characters = 0
    while cursor + 2 <= end:
        if value[cursor : cursor + 2] == b"\x00\x00":
            raw = value[offset:cursor]
            try:
                key = raw.decode("utf-16-le", errors="strict")
            except UnicodeDecodeError:
                _fail(PeVersionErrorCode.FORMAT_INVALID)
            if not key or "\x00" in key:
                _fail(PeVersionErrorCode.FORMAT_INVALID)
            return key, cursor + 2
        cursor += 2
        characters += 1
        if characters > 128:
            _fail(PeVersionErrorCode.RESOURCE_LIMIT)
    _fail(PeVersionErrorCode.FORMAT_INVALID)


def _parse_block(value: bytes, start: int, parent_end: int) -> _VersionBlock:
    if start % 4 != 0 or parent_end > len(value):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    header_end = _checked_end(start, 6, parent_end)
    length, value_length, value_type = struct.unpack_from("<HHH", value, start)
    if length < 6 or value_type not in {0, 1}:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    end = _checked_end(start, length, parent_end)
    key, key_end = _read_utf16_key(value, header_end, end)
    value_offset = _align_four(key_end, end)
    _require_zero(value[key_end:value_offset])
    value_size = value_length * 2 if value_type == 1 else value_length
    value_end = _checked_end(value_offset, value_size, end)
    children_offset = value_end if value_end == end else _align_four(value_end, end)
    _require_zero(value[value_end:children_offset])
    return _VersionBlock(
        start=start,
        end=end,
        value_length=value_length,
        value_type=value_type,
        key=key,
        value_offset=value_offset,
        value_size=value_size,
        children_offset=children_offset,
    )


def _children(value: bytes, parent: _VersionBlock) -> tuple[_VersionBlock, ...]:
    cursor = parent.children_offset
    result: list[_VersionBlock] = []
    while cursor < parent.end:
        remaining = parent.end - cursor
        if remaining < 6:
            _require_zero(value[cursor : parent.end])
            break
        child = _parse_block(value, cursor, parent.end)
        result.append(child)
        if len(result) > _MAX_VERSION_BLOCKS:
            _fail(PeVersionErrorCode.RESOURCE_LIMIT)
        if child.end == parent.end:
            cursor = parent.end
            continue
        aligned = _align_four(child.end, parent.end)
        _require_zero(value[child.end : aligned])
        if aligned <= cursor:
            _fail(PeVersionErrorCode.FORMAT_INVALID)
        cursor = aligned
    return tuple(result)


def _decode_string_value(value: bytes, block: _VersionBlock) -> str:
    if block.value_type != 1 or block.value_size < 2:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    raw = value[block.value_offset : block.value_offset + block.value_size]
    if raw[-2:] != b"\x00\x00" or b"\x00\x00" in raw[:-2]:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    try:
        decoded = raw[:-2].decode("utf-16-le", errors="strict")
    except UnicodeDecodeError:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    if not decoded or len(decoded) > _MAX_VERSION_TEXT_CHARACTERS or "\x00" in decoded:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    return decoded


def _fixed_version(value: int, lower: int) -> tuple[int, int, int, int]:
    return (value >> 16, value & 0xFFFF, lower >> 16, lower & 0xFFFF)


def _parse_version_blob(value: bytes) -> tuple[
    tuple[str, str, str, str, str],
    tuple[int, int, int, int],
    tuple[int, int, int, int],
    tuple[tuple[int, int], ...],
]:
    root = _parse_block(value, 0, len(value))
    if (
        root.end != len(value)
        or root.key != "VS_VERSION_INFO"
        or root.value_type != 0
        or root.value_length != _VS_FIXEDFILEINFO_BYTES
    ):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    fixed = struct.unpack_from("<13I", value, root.value_offset)
    if (
        fixed[0] != _VS_FIXEDFILEINFO_SIGNATURE
        or fixed[1] != _VS_FIXEDFILEINFO_VERSION
        or fixed[6] != 0x3F
        or fixed[7] != 0
        or fixed[8] != 0x00040004
        or fixed[9] != 1
        or fixed[10] != 0
        or fixed[11] != 0
        or fixed[12] != 0
    ):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    file_version = _fixed_version(fixed[2], fixed[3])
    product_version = _fixed_version(fixed[4], fixed[5])

    root_children = _children(value, root)
    string_infos = [child for child in root_children if child.key == "StringFileInfo"]
    var_infos = [child for child in root_children if child.key == "VarFileInfo"]
    if len(root_children) != 2 or len(string_infos) != 1 or len(var_infos) != 1:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    string_info = string_infos[0]
    if string_info.value_length != 0 or string_info.value_type != 1:
        _fail(PeVersionErrorCode.FORMAT_INVALID)

    field_values: dict[str, set[str]] = {
        field_name: set() for field_name in _REQUIRED_STRING_FIELDS
    }
    table_translations: set[tuple[int, int]] = set()
    tables = _children(value, string_info)
    if not tables or len(tables) > _MAX_VERSION_RESOURCES:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    for table in tables:
        if (
            table.value_length != 0
            or table.value_type != 1
            or not _STRING_TABLE_KEY.fullmatch(table.key)
        ):
            _fail(PeVersionErrorCode.FORMAT_INVALID)
        translation = (int(table.key[:4], 16), int(table.key[4:], 16))
        if translation in table_translations:
            _fail(PeVersionErrorCode.FORMAT_INVALID)
        table_translations.add(translation)
        observed_keys: set[str] = set()
        observed_required: set[str] = set()
        for string_block in _children(value, table):
            normalized_key = string_block.key.casefold()
            if normalized_key in observed_keys or _children(value, string_block):
                _fail(PeVersionErrorCode.FORMAT_INVALID)
            observed_keys.add(normalized_key)
            if string_block.key in field_values:
                field_values[string_block.key].add(
                    _decode_string_value(value, string_block)
                )
                observed_required.add(string_block.key)
        if observed_required != set(_REQUIRED_STRING_FIELDS):
            _fail(PeVersionErrorCode.FORMAT_INVALID)

    var_info = var_infos[0]
    if var_info.value_length != 0 or var_info.value_type != 1:
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    translations = _children(value, var_info)
    if len(translations) != 1 or translations[0].key != "Translation":
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    translation_block = translations[0]
    if (
        translation_block.value_type != 0
        or translation_block.value_size == 0
        or translation_block.value_size % 4 != 0
        or _children(value, translation_block)
    ):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    raw_translations = value[
        translation_block.value_offset : (
            translation_block.value_offset + translation_block.value_size
        )
    ]
    declared_translations = {
        struct.unpack_from("<HH", raw_translations, offset)
        for offset in range(0, len(raw_translations), 4)
    }
    if (
        len(declared_translations) * 4 != len(raw_translations)
        or declared_translations != table_translations
    ):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    if any(len(values) != 1 for values in field_values.values()):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    texts = tuple(next(iter(field_values[name])) for name in _REQUIRED_STRING_FIELDS)
    return (
        texts,  # type: ignore[return-value]
        file_version,
        product_version,
        tuple(sorted(table_translations)),
    )


def parse_pe_version_resource(
    source: bytes | RandomAccessReader,
) -> PeVersionResource:
    """Parse one unambiguous AMD64 PE32+ product/version resource."""

    reader = _CheckedReader(source)
    layout = _parse_layout(reader)
    blobs = _version_resource_blobs(layout)
    parsed = tuple(_parse_version_blob(blob) for blob in blobs)
    if any(item != parsed[0] for item in parsed[1:]):
        _fail(PeVersionErrorCode.FORMAT_INVALID)
    texts, fixed_file, fixed_product, translations = parsed[0]
    digest = hashlib.sha256()
    for blob in blobs:
        digest.update(struct.pack(">Q", len(blob)))
        digest.update(blob)
    return PeVersionResource(
        company_name=texts[0],
        product_name=texts[1],
        original_filename=texts[2],
        file_version=texts[3],
        product_version=texts[4],
        fixed_file_version=fixed_file,
        fixed_product_version=fixed_product,
        translations=translations,
        resource_sha256=digest.hexdigest(),
    )
