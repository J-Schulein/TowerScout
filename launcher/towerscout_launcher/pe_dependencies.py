"""Pure, bounded inspection of AMD64 PE dependency leaf names.

The parser is intentionally inert.  It reads the ordinary and delay-load
import descriptor tables from immutable bytes or a caller-owned random-access
reader.  Successful parsing identifies declared dependency leaf names only;
it does not resolve a DLL, authenticate a publisher, or prove that a program
does not call a dynamic loader at runtime.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn, Protocol

MAX_PE_DEPENDENCY_FILE_BYTES = 1024 * 1024 * 1024
MAX_PE_DEPENDENCY_READ_BYTES = 64 * 1024
MAX_PE_DEPENDENCY_COUNT = 512

_DOS_HEADER_BYTES = 64
_PE_FIXED_HEADER_BYTES = 24
_IMAGE_FILE_MACHINE_I386 = 0x014C
_PE32_PLUS_MAGIC = 0x020B
_PE32_MAGIC = 0x010B
_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_IMAGE_FILE_MACHINE_ARM64 = 0xAA64
_MAX_PE_HEADER_OFFSET = 1024 * 1024
_MAX_OPTIONAL_HEADER_BYTES = 4096
_MAX_SECTION_COUNT = 96
_SECTION_HEADER_BYTES = 40
_PE32_PLUS_MINIMUM_OPTIONAL_HEADER_BYTES = 112
_DATA_DIRECTORY_OFFSET = 112
_EXPORT_DIRECTORY_INDEX = 0
_IMPORT_DIRECTORY_INDEX = 1
_BOUND_IMPORT_DIRECTORY_INDEX = 11
_DELAY_IMPORT_DIRECTORY_INDEX = 13
_COM_DESCRIPTOR_DIRECTORY_INDEX = 14
_SECURITY_DIRECTORY_INDEX = 4
_IMPORT_DESCRIPTOR_BYTES = 20
_DELAY_IMPORT_DESCRIPTOR_BYTES = 32
_EXPORT_DIRECTORY_BYTES = 40
_MAX_DEPENDENCY_NAME_BYTES = 255
_MAX_FORWARDER_BYTES = 512
_MAX_EXPORT_FUNCTION_COUNT = 16_384
_EVIDENCE_DOMAIN = b"TowerScout.PeDependencyManifest.v1"


class RandomAccessReader(Protocol):
    @property
    def size(self) -> int: ...

    def read_at(self, offset: int, length: int) -> bytes: ...


class PeDependencyErrorCode(str, Enum):
    SOURCE_INVALID = "source_invalid"
    RESOURCE_LIMIT = "resource_limit"
    FORMAT_INVALID = "format_invalid"


class PeDependencyError(ValueError):
    """Sanitized, fail-closed dependency-table parsing error."""

    _MESSAGES = {
        PeDependencyErrorCode.SOURCE_INVALID: (
            "The executable dependency byte source is unavailable."
        ),
        PeDependencyErrorCode.RESOURCE_LIMIT: (
            "The executable dependency table exceeds fixed safety limits."
        ),
        PeDependencyErrorCode.FORMAT_INVALID: (
            "The executable dependency table is invalid."
        ),
    }

    def __init__(self, code: PeDependencyErrorCode) -> None:
        if type(code) is not PeDependencyErrorCode:
            raise ValueError("Unknown PE dependency error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"PeDependencyError(code={self.code.value!r})"


@dataclass(frozen=True, slots=True, repr=False)
class PeDependencyManifest:
    direct_imports: tuple[str, ...]
    delay_imports: tuple[str, ...]
    forwarded_imports: tuple[str, ...]
    evidence_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        all_names = self.direct_imports + self.delay_imports + self.forwarded_imports
        if (
            type(self.direct_imports) is not tuple
            or type(self.delay_imports) is not tuple
            or type(self.forwarded_imports) is not tuple
            or any(
                type(name) is not str or _canonical_leaf(name) != name
                for name in all_names
            )
            or tuple(sorted(self.direct_imports)) != self.direct_imports
            or tuple(sorted(self.delay_imports)) != self.delay_imports
            or tuple(sorted(self.forwarded_imports)) != self.forwarded_imports
            or len(set(all_names)) != len(all_names)
            or len(all_names) > MAX_PE_DEPENDENCY_COUNT
            or type(self.evidence_sha256) is not str
            or len(self.evidence_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.evidence_sha256
            )
            or self.evidence_sha256
            != _evidence_digest(
                self.direct_imports,
                self.delay_imports,
                self.forwarded_imports,
            )
        ):
            raise ValueError("PE dependency evidence is invalid.")

    def __repr__(self) -> str:
        return (
            "PeDependencyManifest("
            f"direct_count={len(self.direct_imports)}, "
            f"delay_count={len(self.delay_imports)}, "
            f"forwarded_count={len(self.forwarded_imports)}, <redacted>)"
        )


@dataclass(frozen=True, slots=True)
class PeImageMetadata:
    """Minimal same-byte-source facts needed before dependency validation."""

    machine_code: int
    embedded_certificate_table_present: bool

    def __post_init__(self) -> None:
        if (
            self.machine_code
            not in {
                _IMAGE_FILE_MACHINE_I386,
                _IMAGE_FILE_MACHINE_AMD64,
                _IMAGE_FILE_MACHINE_ARM64,
            }
            or type(self.embedded_certificate_table_present) is not bool
        ):
            raise ValueError("PE image metadata is invalid.")


class _BytesReader:
    def __init__(self, value: bytes) -> None:
        self._value = value

    @property
    def size(self) -> int:
        return len(self._value)

    def read_at(self, offset: int, length: int) -> bytes:
        return self._value[offset : offset + length]


class _CheckedReader:
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
            _fail(PeDependencyErrorCode.SOURCE_INVALID)
        if type(size) is not int or size < 0 or not callable(read_at):
            _fail(PeDependencyErrorCode.SOURCE_INVALID)
        if size > MAX_PE_DEPENDENCY_FILE_BYTES:
            _fail(PeDependencyErrorCode.RESOURCE_LIMIT)
        self.size = size
        self._read_at = read_at

    def read_exact(self, offset: int, length: int) -> bytes:
        if (
            type(offset) is not int
            or type(length) is not int
            or offset < 0
            or length < 0
            or length > MAX_PE_DEPENDENCY_READ_BYTES
            or offset > self.size
            or length > self.size - offset
        ):
            _fail(PeDependencyErrorCode.FORMAT_INVALID)
        try:
            value = self._read_at(offset, length)
        except Exception:
            _fail(PeDependencyErrorCode.SOURCE_INVALID)
        if not isinstance(value, bytes) or len(value) != length:
            _fail(PeDependencyErrorCode.SOURCE_INVALID)
        return value


@dataclass(frozen=True, slots=True)
class _Section:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


def _fail(code: PeDependencyErrorCode) -> NoReturn:
    raise PeDependencyError(code)


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
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    return offset + length


def _checked_product(left: int, right: int, upper_bound: int) -> int:
    if (
        type(left) is not int
        or type(right) is not int
        or type(upper_bound) is not int
        or left < 0
        or right < 0
        or upper_bound < 0
        or (left != 0 and right > upper_bound // left)
    ):
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    return left * right


def _canonical_leaf(value: str) -> str:
    if (
        type(value) is not str
        or not 5 <= len(value) <= _MAX_DEPENDENCY_NAME_BYTES
        or value.endswith((".", " "))
        or any(character in value for character in ("\\", "/", ":", "\x00"))
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
        or not value.casefold().endswith(".dll")
    ):
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    return value.casefold()


def _directory(optional: bytes, index: int, count: int) -> tuple[int, int]:
    if index >= count:
        return (0, 0)
    offset = _DATA_DIRECTORY_OFFSET + (index * 8)
    return struct.unpack_from("<II", optional, offset)


def _rva_mapping(
    rva: int, length: int, sections: tuple[_Section, ...]
) -> tuple[int, int]:
    if type(rva) is not int or type(length) is not int or rva <= 0 or length < 0:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    candidates: list[tuple[int, int]] = []
    for section in sections:
        if rva < section.virtual_address:
            continue
        delta = rva - section.virtual_address
        if delta > section.raw_size or length > section.raw_size - delta:
            continue
        candidates.append((section.raw_offset + delta, section.raw_size - delta))
    if len(candidates) != 1:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    return candidates[0]


def _read_leaf(reader: _CheckedReader, rva: int, sections: tuple[_Section, ...]) -> str:
    offset, capacity = _rva_mapping(rva, 1, sections)
    length = min(capacity, _MAX_DEPENDENCY_NAME_BYTES + 1)
    value = reader.read_exact(offset, length)
    terminator = value.find(b"\x00")
    if terminator <= 0 or terminator > _MAX_DEPENDENCY_NAME_BYTES:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    try:
        decoded = value[:terminator].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    return _canonical_leaf(decoded)


def _read_forwarder_leaf(
    reader: _CheckedReader, rva: int, sections: tuple[_Section, ...]
) -> str:
    offset, capacity = _rva_mapping(rva, 1, sections)
    length = min(capacity, _MAX_FORWARDER_BYTES + 1)
    value = reader.read_exact(offset, length)
    terminator = value.find(b"\x00")
    if terminator <= 0 or terminator > _MAX_FORWARDER_BYTES:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    try:
        decoded = value[:terminator].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    module, separator, target = decoded.partition(".")
    if (
        separator != "."
        or not module
        or not target
        or "." in module
        or any(character in target for character in ("\\", "/", ":", "\x00"))
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in target)
    ):
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    return _canonical_leaf(module + ".dll")


def _parse_export_forwarders(
    reader: _CheckedReader,
    *,
    rva: int,
    size: int,
    sections: tuple[_Section, ...],
) -> tuple[str, ...]:
    if (rva == 0) != (size == 0):
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    if rva == 0:
        return ()
    if size < _EXPORT_DIRECTORY_BYTES:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    directory_offset, capacity = _rva_mapping(rva, size, sections)
    if size > capacity:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    directory = reader.read_exact(directory_offset, _EXPORT_DIRECTORY_BYTES)
    function_count = struct.unpack_from("<I", directory, 20)[0]
    function_table_rva = struct.unpack_from("<I", directory, 28)[0]
    if function_count > _MAX_EXPORT_FUNCTION_COUNT:
        _fail(PeDependencyErrorCode.RESOURCE_LIMIT)
    if function_count == 0:
        return ()
    function_table_bytes = _checked_product(
        function_count, 4, MAX_PE_DEPENDENCY_READ_BYTES
    )
    function_offset, _ = _rva_mapping(
        function_table_rva, function_table_bytes, sections
    )
    functions = reader.read_exact(function_offset, function_table_bytes)
    directory_end = _checked_end(rva, size, 2**32)
    names: set[str] = set()
    for index in range(function_count):
        function_rva = struct.unpack_from("<I", functions, index * 4)[0]
        if rva <= function_rva < directory_end:
            names.add(_read_forwarder_leaf(reader, function_rva, sections))
    return tuple(sorted(names))


def _parse_descriptor_table(
    reader: _CheckedReader,
    *,
    rva: int,
    size: int,
    descriptor_bytes: int,
    name_offset: int,
    required_attributes: int | None,
    sections: tuple[_Section, ...],
) -> tuple[str, ...]:
    if (rva == 0) != (size == 0):
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    if rva == 0:
        return ()
    if size < descriptor_bytes or size > descriptor_bytes * (
        MAX_PE_DEPENDENCY_COUNT + 1
    ):
        _fail(PeDependencyErrorCode.RESOURCE_LIMIT)
    table_offset, capacity = _rva_mapping(rva, size, sections)
    if size > capacity:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)

    names: list[str] = []
    cursor = 0
    while cursor + descriptor_bytes <= size:
        descriptor = reader.read_exact(table_offset + cursor, descriptor_bytes)
        if not any(descriptor):
            break
        if len(names) >= MAX_PE_DEPENDENCY_COUNT:
            _fail(PeDependencyErrorCode.RESOURCE_LIMIT)
        if (
            required_attributes is not None
            and struct.unpack_from("<I", descriptor, 0)[0] != required_attributes
        ):
            _fail(PeDependencyErrorCode.FORMAT_INVALID)
        name_rva = struct.unpack_from("<I", descriptor, name_offset)[0]
        names.append(_read_leaf(reader, name_rva, sections))
        cursor += descriptor_bytes
    else:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)

    if len(names) != len(set(names)):
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    return tuple(sorted(names))


def _evidence_digest(
    direct_imports: tuple[str, ...],
    delay_imports: tuple[str, ...],
    forwarded_imports: tuple[str, ...],
) -> str:
    digest = hashlib.sha256()
    values: tuple[bytes | str, ...] = (
        _EVIDENCE_DOMAIN,
        *direct_imports,
        b"delay",
        *delay_imports,
        b"forwarded",
        *forwarded_imports,
    )
    for value in values:
        encoded = value if isinstance(value, bytes) else value.encode("ascii")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()


def parse_pe_dependencies(
    source: bytes | RandomAccessReader,
) -> PeDependencyManifest:
    """Return declared direct and delay-load DLL leaves from one AMD64 PE."""

    reader = _CheckedReader(source)
    if reader.size < _DOS_HEADER_BYTES:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    dos = reader.read_exact(0, _DOS_HEADER_BYTES)
    if dos[:2] != b"MZ":
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    if pe_offset < _DOS_HEADER_BYTES or pe_offset > _MAX_PE_HEADER_OFFSET:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    _checked_end(pe_offset, _PE_FIXED_HEADER_BYTES, reader.size)

    fixed = reader.read_exact(pe_offset, _PE_FIXED_HEADER_BYTES)
    if fixed[:4] != b"PE\x00\x00":
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    machine, section_count = struct.unpack_from("<HH", fixed, 4)
    if (
        machine != _IMAGE_FILE_MACHINE_AMD64
        or not 0 < section_count <= _MAX_SECTION_COUNT
    ):
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    optional_size = struct.unpack_from("<H", fixed, 20)[0]
    if (
        not _PE32_PLUS_MINIMUM_OPTIONAL_HEADER_BYTES
        <= optional_size
        <= _MAX_OPTIONAL_HEADER_BYTES
    ):
        _fail(PeDependencyErrorCode.FORMAT_INVALID)

    optional_offset = pe_offset + _PE_FIXED_HEADER_BYTES
    optional_end = _checked_end(optional_offset, optional_size, reader.size)
    optional = reader.read_exact(optional_offset, optional_size)
    if struct.unpack_from("<H", optional, 0)[0] != _PE32_PLUS_MAGIC:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    size_of_headers = struct.unpack_from("<I", optional, 60)[0]
    directory_count = struct.unpack_from("<I", optional, 108)[0]
    available = (optional_size - _DATA_DIRECTORY_OFFSET) // 8
    if directory_count > available:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)

    section_table_size = _checked_product(
        section_count, _SECTION_HEADER_BYTES, reader.size
    )
    section_table_end = _checked_end(optional_end, section_table_size, reader.size)
    if size_of_headers < section_table_end or size_of_headers > reader.size:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    table = reader.read_exact(optional_end, section_table_size)
    sections: list[_Section] = []
    raw_intervals: list[tuple[int, int]] = []
    virtual_intervals: list[tuple[int, int]] = []
    for index in range(section_count):
        offset = index * _SECTION_HEADER_BYTES
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", table, offset + 8
        )
        if raw_size == 0:
            continue
        if raw_offset < size_of_headers:
            _fail(PeDependencyErrorCode.FORMAT_INVALID)
        raw_end = _checked_end(raw_offset, raw_size, reader.size)
        virtual_span = max(virtual_size, raw_size)
        virtual_end = _checked_end(virtual_address, virtual_span, 2**32)
        if virtual_address == 0:
            _fail(PeDependencyErrorCode.FORMAT_INVALID)
        sections.append(_Section(virtual_address, virtual_size, raw_offset, raw_size))
        raw_intervals.append((raw_offset, raw_end))
        virtual_intervals.append((virtual_address, virtual_end))
    if not sections:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    for intervals in (raw_intervals, virtual_intervals):
        intervals.sort()
        if any(
            current[0] < previous[1]
            for previous, current in zip(intervals, intervals[1:])
        ):
            _fail(PeDependencyErrorCode.FORMAT_INVALID)
    section_tuple = tuple(sections)

    for unsupported_index in (
        _BOUND_IMPORT_DIRECTORY_INDEX,
        _COM_DESCRIPTOR_DIRECTORY_INDEX,
    ):
        if _directory(optional, unsupported_index, directory_count) != (0, 0):
            _fail(PeDependencyErrorCode.FORMAT_INVALID)

    export_rva, export_size = _directory(
        optional, _EXPORT_DIRECTORY_INDEX, directory_count
    )
    forwarded = _parse_export_forwarders(
        reader,
        rva=export_rva,
        size=export_size,
        sections=section_tuple,
    )
    import_rva, import_size = _directory(
        optional, _IMPORT_DIRECTORY_INDEX, directory_count
    )
    direct = _parse_descriptor_table(
        reader,
        rva=import_rva,
        size=import_size,
        descriptor_bytes=_IMPORT_DESCRIPTOR_BYTES,
        name_offset=12,
        required_attributes=None,
        sections=section_tuple,
    )
    delay_rva, delay_size = _directory(
        optional, _DELAY_IMPORT_DIRECTORY_INDEX, directory_count
    )
    delay = _parse_descriptor_table(
        reader,
        rva=delay_rva,
        size=delay_size,
        descriptor_bytes=_DELAY_IMPORT_DESCRIPTOR_BYTES,
        name_offset=4,
        # VC7+ delay descriptors use dlattrRva so their address fields are
        # RVAs on both 32- and 64-bit images.  Reject the legacy pointer form
        # and unknown flag bits rather than guess how to resolve them.
        required_attributes=1,
        sections=section_tuple,
    )
    all_names = direct + delay + forwarded
    if len(all_names) > MAX_PE_DEPENDENCY_COUNT or len(all_names) != len(
        set(all_names)
    ):
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    return PeDependencyManifest(
        direct_imports=direct,
        delay_imports=delay,
        forwarded_imports=forwarded,
        evidence_sha256=_evidence_digest(direct, delay, forwarded),
    )


def inspect_pe_image_metadata(source: bytes | RandomAccessReader) -> PeImageMetadata:
    """Inspect the PE machine and embedded-certificate table fail closed.

    Absence means the image has no embedded WIN_CERTIFICATE table. It never
    treats an Authenticode verification failure as proof that a file is
    unsigned.
    """

    reader = _CheckedReader(source)
    if reader.size < _DOS_HEADER_BYTES:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    dos = reader.read_exact(0, _DOS_HEADER_BYTES)
    if dos[:2] != b"MZ":
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    if pe_offset < _DOS_HEADER_BYTES or pe_offset > _MAX_PE_HEADER_OFFSET:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    _checked_end(pe_offset, _PE_FIXED_HEADER_BYTES, reader.size)
    fixed = reader.read_exact(pe_offset, _PE_FIXED_HEADER_BYTES)
    if fixed[:4] != b"PE\x00\x00":
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    machine = struct.unpack_from("<H", fixed, 4)[0]
    optional_size = struct.unpack_from("<H", fixed, 20)[0]
    if (
        machine
        not in {
            _IMAGE_FILE_MACHINE_I386,
            _IMAGE_FILE_MACHINE_AMD64,
            _IMAGE_FILE_MACHINE_ARM64,
        }
        or not 0 < optional_size <= _MAX_OPTIONAL_HEADER_BYTES
    ):
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    optional_offset = pe_offset + _PE_FIXED_HEADER_BYTES
    _checked_end(optional_offset, optional_size, reader.size)
    optional = reader.read_exact(optional_offset, optional_size)
    if len(optional) < 2:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    magic = struct.unpack_from("<H", optional, 0)[0]
    if machine == _IMAGE_FILE_MACHINE_I386:
        directory_offset, count_offset = 96, 92
        if magic != _PE32_MAGIC:
            _fail(PeDependencyErrorCode.FORMAT_INVALID)
    else:
        directory_offset, count_offset = 112, 108
        if magic != _PE32_PLUS_MAGIC:
            _fail(PeDependencyErrorCode.FORMAT_INVALID)
    if optional_size < directory_offset:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    directory_count = struct.unpack_from("<I", optional, count_offset)[0]
    available = (optional_size - directory_offset) // 8
    if directory_count > available:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    if directory_count <= _SECURITY_DIRECTORY_INDEX:
        return PeImageMetadata(machine, False)
    certificate_offset, certificate_size = struct.unpack_from(
        "<II", optional, directory_offset + (_SECURITY_DIRECTORY_INDEX * 8)
    )
    if (certificate_offset == 0) != (certificate_size == 0):
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    if certificate_size == 0:
        return PeImageMetadata(machine, False)
    if certificate_offset % 8 != 0 or certificate_size < 8:
        _fail(PeDependencyErrorCode.FORMAT_INVALID)
    _checked_end(certificate_offset, certificate_size, reader.size)
    return PeImageMetadata(machine, True)


__all__ = [
    "MAX_PE_DEPENDENCY_COUNT",
    "MAX_PE_DEPENDENCY_FILE_BYTES",
    "MAX_PE_DEPENDENCY_READ_BYTES",
    "PeDependencyError",
    "PeDependencyErrorCode",
    "PeDependencyManifest",
    "PeImageMetadata",
    "RandomAccessReader",
    "parse_pe_dependencies",
    "inspect_pe_image_metadata",
]
