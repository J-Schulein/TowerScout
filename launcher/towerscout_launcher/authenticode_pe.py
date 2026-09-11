"""Pure, bounded PE layout validation for embedded Authenticode signatures.

The parser in this module is intentionally inert.  It performs no filesystem,
native trust, certificate, catalog, or process operations.  Callers may supply
immutable bytes or a small random-access reader backed by an already-held file
handle.  Successful parsing establishes only the strict PE/container layout;
it does not establish signature or publisher trust.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum
from typing import NoReturn, Protocol

MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
MAX_CERTIFICATE_TABLE_BYTES = 16 * 1024 * 1024
MAX_RANDOM_READ_BYTES = 64 * 1024

_MAX_PE_HEADER_OFFSET = 1024 * 1024
_MAX_OPTIONAL_HEADER_BYTES = 4096
_MAX_SECTION_COUNT = 96
_DOS_HEADER_BYTES = 64
_PE_FIXED_HEADER_BYTES = 24
_SECTION_HEADER_BYTES = 40
_PE32_PLUS_MINIMUM_OPTIONAL_HEADER_BYTES = 152
_PE32_PLUS_DATA_DIRECTORY_OFFSET = 112
_SECURITY_DIRECTORY_OFFSET = _PE32_PLUS_DATA_DIRECTORY_OFFSET + (4 * 8)
_WIN_CERTIFICATE_HEADER_BYTES = 8
_WIN_CERTIFICATE_REVISION_2_0 = 0x0200
_WIN_CERTIFICATE_TYPE_PKCS_SIGNED_DATA = 0x0002
_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_PE32_PLUS_MAGIC = 0x020B


class RandomAccessReader(Protocol):
    """Bounded random-access source suitable for an already-held file handle."""

    @property
    def size(self) -> int: ...

    def read_at(self, offset: int, length: int) -> bytes: ...


class AuthenticodePeErrorCode(str, Enum):
    SOURCE_INVALID = "source_invalid"
    RESOURCE_LIMIT = "resource_limit"
    FORMAT_INVALID = "format_invalid"


class AuthenticodePeError(ValueError):
    """Sanitized, fail-closed PE signature-container error."""

    _MESSAGES = {
        AuthenticodePeErrorCode.SOURCE_INVALID: (
            "The executable byte source is unavailable."
        ),
        AuthenticodePeErrorCode.RESOURCE_LIMIT: (
            "The executable exceeds signature-parser safety limits."
        ),
        AuthenticodePeErrorCode.FORMAT_INVALID: (
            "The executable embedded-signature container is invalid."
        ),
    }

    def __init__(self, code: AuthenticodePeErrorCode) -> None:
        if type(code) is not AuthenticodePeErrorCode:
            raise ValueError("Unknown Authenticode PE error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"AuthenticodePeError(code={self.code.value!r})"


@dataclass(frozen=True, slots=True, repr=False)
class EmbeddedAuthenticodePe:
    """Immutable offsets for one structurally valid embedded PKCS#7 object."""

    file_size: int
    section_count: int
    image_end_offset: int
    certificate_table_offset: int
    certificate_table_size: int
    win_certificate_length: int
    pkcs7_der_offset: int
    pkcs7_der_size: int

    def __post_init__(self) -> None:
        integer_values = (
            self.file_size,
            self.section_count,
            self.image_end_offset,
            self.certificate_table_offset,
            self.certificate_table_size,
            self.win_certificate_length,
            self.pkcs7_der_offset,
            self.pkcs7_der_size,
        )
        if any(type(value) is not int for value in integer_values):
            raise ValueError("Embedded Authenticode PE evidence is invalid.")
        if (
            not 0 < self.file_size <= MAX_EXECUTABLE_BYTES
            or not 0 < self.section_count <= _MAX_SECTION_COUNT
            or not 0 <= self.image_end_offset <= self.certificate_table_offset
            or self.certificate_table_offset - self.image_end_offset > 7
            or self.certificate_table_offset % 8 != 0
            or not 0 < self.certificate_table_size <= MAX_CERTIFICATE_TABLE_BYTES
            or self.certificate_table_offset + self.certificate_table_size
            != self.file_size
            or not _WIN_CERTIFICATE_HEADER_BYTES
            < self.win_certificate_length
            <= self.certificate_table_size
            or ((self.win_certificate_length + 7) & ~7) != self.certificate_table_size
            or self.pkcs7_der_offset
            != self.certificate_table_offset + _WIN_CERTIFICATE_HEADER_BYTES
            or self.pkcs7_der_size < 3
            or self.pkcs7_der_offset + self.pkcs7_der_size
            > self.certificate_table_offset + self.win_certificate_length
        ):
            raise ValueError("Embedded Authenticode PE evidence is invalid.")

    @property
    def machine(self) -> str:
        return "amd64"

    @property
    def optional_header_kind(self) -> str:
        return "pe32_plus"

    @property
    def certificate_count(self) -> int:
        return 1

    def __repr__(self) -> str:
        return (
            "EmbeddedAuthenticodePe("
            "machine='amd64', certificate_count=1, <redacted>)"
        )


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
        if isinstance(source, bytes):
            reader: RandomAccessReader = _BytesReader(source)
        else:
            reader = source

        try:
            size = reader.size
            read_at = reader.read_at
        except Exception:
            _fail(AuthenticodePeErrorCode.SOURCE_INVALID)

        if type(size) is not int or size < 0 or not callable(read_at):
            _fail(AuthenticodePeErrorCode.SOURCE_INVALID)
        if size > MAX_EXECUTABLE_BYTES:
            _fail(AuthenticodePeErrorCode.RESOURCE_LIMIT)

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
            _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
        if length == 0:
            return b""

        try:
            value = self._read_at(offset, length)
        except Exception:
            _fail(AuthenticodePeErrorCode.SOURCE_INVALID)
        if not isinstance(value, bytes) or len(value) != length:
            _fail(AuthenticodePeErrorCode.SOURCE_INVALID)
        return value

    def require_zero_range(self, offset: int, length: int) -> None:
        if (
            type(offset) is not int
            or type(length) is not int
            or offset < 0
            or length < 0
            or offset > self.size
            or length > self.size - offset
        ):
            _fail(AuthenticodePeErrorCode.FORMAT_INVALID)

        cursor = offset
        remaining = length
        while remaining:
            chunk_length = min(remaining, MAX_RANDOM_READ_BYTES)
            if any(self.read_exact(cursor, chunk_length)):
                _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
            cursor += chunk_length
            remaining -= chunk_length


def _fail(code: AuthenticodePeErrorCode) -> NoReturn:
    raise AuthenticodePeError(code)


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
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
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
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    return left * right


def _align_to_eight(value: int, upper_bound: int) -> int:
    if type(value) is not int or value < 0 or value > upper_bound:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    padding = (-value) % 8
    return _checked_end(value, padding, upper_bound)


def _parse_der_outer_sequence(
    reader: _CheckedReader, offset: int, capacity: int
) -> int:
    if capacity < 2:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)

    prefix = reader.read_exact(offset, 2)
    if prefix[0] != 0x30:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)

    first_length_octet = prefix[1]
    if first_length_octet < 0x80:
        length_octets = 0
        content_length = first_length_octet
    else:
        length_octets = first_length_octet & 0x7F
        if length_octets == 0 or length_octets > 4:
            _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
        if 2 + length_octets > capacity:
            _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
        encoded_length = reader.read_exact(offset + 2, length_octets)
        if encoded_length[0] == 0:
            _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
        content_length = int.from_bytes(encoded_length, "big")
        if content_length < 0x80:
            _fail(AuthenticodePeErrorCode.FORMAT_INVALID)

    if content_length == 0:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    header_length = 2 + length_octets
    der_length = _checked_end(header_length, content_length, capacity)
    return der_length


def parse_embedded_authenticode_pe(
    source: bytes | RandomAccessReader,
) -> EmbeddedAuthenticodePe:
    """Validate one AMD64 PE32+ embedded Authenticode container.

    The returned offsets remain bound to the supplied byte source.  This
    function does not parse PKCS#7 internals or establish cryptographic trust.
    Callers using a mutable handle-backed reader must independently keep the
    handle open and revalidate its stable identity and content hash.
    """

    reader = _CheckedReader(source)
    if reader.size < _DOS_HEADER_BYTES:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)

    dos_header = reader.read_exact(0, _DOS_HEADER_BYTES)
    if dos_header[:2] != b"MZ":
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
    if pe_offset < _DOS_HEADER_BYTES or pe_offset > _MAX_PE_HEADER_OFFSET:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    _checked_end(pe_offset, _PE_FIXED_HEADER_BYTES, reader.size)

    fixed_header = reader.read_exact(pe_offset, _PE_FIXED_HEADER_BYTES)
    if fixed_header[:4] != b"PE\x00\x00":
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    machine, section_count = struct.unpack_from("<HH", fixed_header, 4)
    if machine != _IMAGE_FILE_MACHINE_AMD64:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    if not 0 < section_count <= _MAX_SECTION_COUNT:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)

    optional_header_size = struct.unpack_from("<H", fixed_header, 20)[0]
    if not (
        _PE32_PLUS_MINIMUM_OPTIONAL_HEADER_BYTES
        <= optional_header_size
        <= _MAX_OPTIONAL_HEADER_BYTES
    ):
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    optional_header_offset = pe_offset + _PE_FIXED_HEADER_BYTES
    optional_header_end = _checked_end(
        optional_header_offset, optional_header_size, reader.size
    )
    optional_header = reader.read_exact(optional_header_offset, optional_header_size)
    if struct.unpack_from("<H", optional_header, 0)[0] != _PE32_PLUS_MAGIC:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)

    size_of_headers = struct.unpack_from("<I", optional_header, 60)[0]
    directory_count = struct.unpack_from("<I", optional_header, 108)[0]
    available_directories = (
        optional_header_size - _PE32_PLUS_DATA_DIRECTORY_OFFSET
    ) // 8
    if directory_count < 5 or directory_count > available_directories:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)

    certificate_table_offset, certificate_table_size = struct.unpack_from(
        "<II", optional_header, _SECURITY_DIRECTORY_OFFSET
    )
    if certificate_table_offset == 0 or certificate_table_size == 0:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    if certificate_table_offset % 8 != 0:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    if certificate_table_size > MAX_CERTIFICATE_TABLE_BYTES:
        _fail(AuthenticodePeErrorCode.RESOURCE_LIMIT)
    certificate_table_end = _checked_end(
        certificate_table_offset, certificate_table_size, reader.size
    )
    if certificate_table_end != reader.size:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)

    section_table_size = _checked_product(
        section_count, _SECTION_HEADER_BYTES, reader.size
    )
    section_table_end = _checked_end(
        optional_header_end, section_table_size, reader.size
    )
    if (
        size_of_headers < section_table_end
        or size_of_headers > certificate_table_offset
    ):
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    section_table = reader.read_exact(optional_header_end, section_table_size)

    image_end_offset = size_of_headers
    section_intervals: list[tuple[int, int]] = []
    for index in range(section_count):
        section_offset = index * _SECTION_HEADER_BYTES
        raw_size, raw_offset = struct.unpack_from(
            "<II", section_table, section_offset + 16
        )
        if raw_size == 0:
            continue
        if raw_offset < size_of_headers:
            _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
        raw_end = _checked_end(raw_offset, raw_size, certificate_table_offset)
        section_intervals.append((raw_offset, raw_end))
        image_end_offset = max(image_end_offset, raw_end)

    section_intervals.sort()
    for previous, current in zip(section_intervals, section_intervals[1:]):
        if current[0] < previous[1]:
            _fail(AuthenticodePeErrorCode.FORMAT_INVALID)

    pre_table_gap = certificate_table_offset - image_end_offset
    if pre_table_gap > 7:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    reader.require_zero_range(image_end_offset, pre_table_gap)

    if certificate_table_size < _WIN_CERTIFICATE_HEADER_BYTES + 2:
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    certificate_header = reader.read_exact(
        certificate_table_offset, _WIN_CERTIFICATE_HEADER_BYTES
    )
    win_certificate_length, revision, certificate_type = struct.unpack(
        "<IHH", certificate_header
    )
    if (
        win_certificate_length < _WIN_CERTIFICATE_HEADER_BYTES + 2
        or win_certificate_length > certificate_table_size
        or revision != _WIN_CERTIFICATE_REVISION_2_0
        or certificate_type != _WIN_CERTIFICATE_TYPE_PKCS_SIGNED_DATA
    ):
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)
    if (
        _align_to_eight(win_certificate_length, certificate_table_size)
        != certificate_table_size
    ):
        _fail(AuthenticodePeErrorCode.FORMAT_INVALID)

    pkcs7_der_offset = certificate_table_offset + _WIN_CERTIFICATE_HEADER_BYTES
    certificate_payload_size = win_certificate_length - _WIN_CERTIFICATE_HEADER_BYTES
    pkcs7_der_size = _parse_der_outer_sequence(
        reader, pkcs7_der_offset, certificate_payload_size
    )
    padding_offset = pkcs7_der_offset + pkcs7_der_size
    padding_size = certificate_table_end - padding_offset
    reader.require_zero_range(padding_offset, padding_size)

    return EmbeddedAuthenticodePe(
        file_size=reader.size,
        section_count=section_count,
        image_end_offset=image_end_offset,
        certificate_table_offset=certificate_table_offset,
        certificate_table_size=certificate_table_size,
        win_certificate_length=win_certificate_length,
        pkcs7_der_offset=pkcs7_der_offset,
        pkcs7_der_size=pkcs7_der_size,
    )
