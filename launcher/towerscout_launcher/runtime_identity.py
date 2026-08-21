"""Inert, handle-owning Windows runtime identity foundations.

This module has two deliberately separate responsibilities:

* match a PE product and exact reviewed string version from one already-held
  file handle; and
* nominate one executable only from the package policy's exact Windows
  installation records.

Installation records are nomination sources, not trust roots.  The returned
candidate owns its still-open handle but is not a ``RuntimeIdentity`` and is
not executable.  Nothing here imports launcher discovery, repair, or process
execution.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import struct
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PureWindowsPath
from typing import NoReturn, Protocol, Sequence

from .pe_version import (
    MAX_EXECUTABLE_BYTES,
    MAX_RANDOM_READ_BYTES,
    PeVersionResource,
    parse_pe_version_resource,
)
from .runtime_policy import (
    InstallRecordPolicy,
    LocationKind,
    ProductPolicy,
    RuntimePolicy,
    RuntimePolicyError,
    RuntimeProductId,
    VersionEvidenceKind,
    load_package_bound_runtime_policy,
)
from .windows_security import (
    FileCapturePolicy,
    FileSnapshot,
    HandleBoundFile,
    StableFileIdentity,
    WindowsFileApi,
    WindowsSecurityError,
    capture_handle_bound_file,
)

_MAX_REGISTRY_VALUE_CHARACTERS = 32_767
_MAX_INSTALL_PATH_CHARACTERS = 32_767
_MAX_REGISTRY_SELECTORS = 16
_PE_EVIDENCE_DOMAIN = b"TowerScout.VerifiedPeProduct.v1"
_INSTALL_RESOLUTION_DOMAIN = b"TowerScout.InstallResolution.v1"
_INSTALL_EVIDENCE_DOMAIN = b"TowerScout.InstallCandidate.v1"
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:$")
_SAFE_LEAF = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_INVALID_PATH_CHARACTERS = frozenset('<>"|?*')
_RESERVED_LEAVES = frozenset(
    {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


class RuntimeIdentityErrorCode(str, Enum):
    VERIFICATION_UNAVAILABLE = "verification_unavailable"
    RUNTIME_IDENTITY_INVALID = "runtime_identity_invalid"
    RUNTIME_REPLACED = "runtime_replaced"
    INSTALLATION_NOT_FOUND = "installation_not_found"
    INSTALL_RECORD_INVALID = "install_record_invalid"
    INSTALLATION_AMBIGUOUS = "installation_ambiguous"


class RuntimeIdentityVerificationError(RuntimeError):
    """Sanitized failure for PE identity or installation nomination."""

    _MESSAGES = {
        RuntimeIdentityErrorCode.VERIFICATION_UNAVAILABLE: (
            "Secure Windows runtime verification is unavailable."
        ),
        RuntimeIdentityErrorCode.RUNTIME_IDENTITY_INVALID: (
            "The runtime executable product and version are not approved."
        ),
        RuntimeIdentityErrorCode.RUNTIME_REPLACED: (
            "The runtime executable or installation record changed during review."
        ),
        RuntimeIdentityErrorCode.INSTALLATION_NOT_FOUND: (
            "No reviewed installation record identified the requested runtime."
        ),
        RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID: (
            "A reviewed runtime installation record is invalid or unsafe."
        ),
        RuntimeIdentityErrorCode.INSTALLATION_AMBIGUOUS: (
            "More than one distinct reviewed runtime installation is present."
        ),
    }

    def __init__(self, code: RuntimeIdentityErrorCode) -> None:
        if type(code) is not RuntimeIdentityErrorCode:
            raise ValueError("Unknown runtime identity error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RuntimeIdentityVerificationError(code={self.code.value!r})"


def _fail(code: RuntimeIdentityErrorCode) -> NoReturn:
    raise RuntimeIdentityVerificationError(code)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_strict_utf8(value: str) -> bool:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return True


def _canonical_digest(domain: bytes, fields: Sequence[bytes]) -> str:
    digest = hashlib.sha256()
    for value in (domain, *fields):
        if not isinstance(value, bytes) or len(value) > 128 * 1024:
            raise ValueError("Runtime identity evidence field is invalid.")
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _identity_fields(identity: StableFileIdentity) -> tuple[bytes, bytes]:
    return (identity.volume_serial.to_bytes(8, "big"), identity.file_id)


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedPeProductEvidence:
    """Exact package-policy match derived from one held executable."""

    product_id: RuntimeProductId
    exact_version: str
    policy_sha256: str = field(repr=False)
    file_identity: StableFileIdentity = field(repr=False)
    file_sha256: str = field(repr=False)
    resource_sha256: str = field(repr=False)
    fixed_file_version: tuple[int, int, int, int] = field(repr=False)
    fixed_product_version: tuple[int, int, int, int] = field(repr=False)
    evidence_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        fixed_versions = (self.fixed_file_version, self.fixed_product_version)
        if (
            type(self.product_id) is not RuntimeProductId
            or type(self.exact_version) is not str
            or not _VERSION.fullmatch(self.exact_version)
            or not _is_sha256(self.policy_sha256)
            or type(self.file_identity) is not StableFileIdentity
            or not _is_sha256(self.file_sha256)
            or not _is_sha256(self.resource_sha256)
            or any(
                type(version) is not tuple
                or len(version) != 4
                or any(
                    type(part) is not int or not 0 <= part <= 0xFFFF for part in version
                )
                for version in fixed_versions
            )
        ):
            raise ValueError("Verified PE product evidence is invalid.")
        fixed_fields = tuple(
            part.to_bytes(2, "big") for version in fixed_versions for part in version
        )
        object.__setattr__(
            self,
            "evidence_sha256",
            _canonical_digest(
                _PE_EVIDENCE_DOMAIN,
                (
                    self.product_id.value.encode("ascii"),
                    self.exact_version.encode("ascii"),
                    self.policy_sha256.encode("ascii"),
                    *_identity_fields(self.file_identity),
                    self.file_sha256.encode("ascii"),
                    self.resource_sha256.encode("ascii"),
                    *fixed_fields,
                ),
            ),
        )

    def __repr__(self) -> str:
        return (
            "VerifiedPeProductEvidence("
            f"product={self.product_id.value!r}, version={self.exact_version!r}, "
            "<redacted>)"
        )


class PeProductBackend(Protocol):
    """Read the PE version resource through an existing handle."""

    @property
    def supported(self) -> bool: ...

    def inspect_open_file(
        self, *, handle: object, snapshot: FileSnapshot
    ) -> PeVersionResource: ...


class _NativeHeldFileReader:
    __slots__ = ("_handle", "_kernel32", "_size")

    def __init__(self, handle: object, size: int) -> None:
        if os.name != "nt" or type(handle) is not int or handle <= 0:
            raise OSError("Native held-file reading is unavailable.")
        if type(size) is not int or not 0 <= size <= MAX_EXECUTABLE_BYTES:
            raise ValueError("Native held-file size is invalid.")
        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            raise OSError("Native held-file reading is unavailable.")
        self._kernel32 = win_dll("kernel32", use_last_error=True)
        self._handle = ctypes.c_void_p(handle)
        self._size = size
        self._kernel32.SetFilePointerEx.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int64,
            ctypes.POINTER(ctypes.c_int64),
            ctypes.c_uint32,
        )
        self._kernel32.SetFilePointerEx.restype = ctypes.c_int
        self._kernel32.ReadFile.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        )
        self._kernel32.ReadFile.restype = ctypes.c_int

    @property
    def size(self) -> int:
        return self._size

    def read_at(self, offset: int, length: int) -> bytes:
        if (
            type(offset) is not int
            or type(length) is not int
            or offset < 0
            or length < 0
            or length > MAX_RANDOM_READ_BYTES
            or offset > self._size
            or length > self._size - offset
        ):
            raise ValueError("Native held-file read range is invalid.")
        position = ctypes.c_int64()
        if (
            not self._kernel32.SetFilePointerEx(
                self._handle,
                ctypes.c_int64(offset),
                ctypes.byref(position),
                0,
            )
            or int(position.value) != offset
        ):
            raise OSError("Native held-file positioning failed.")
        result = bytearray()
        remaining = length
        while remaining:
            amount = min(remaining, MAX_RANDOM_READ_BYTES)
            buffer = ctypes.create_string_buffer(amount)
            read = ctypes.c_uint32()
            if not self._kernel32.ReadFile(
                self._handle,
                buffer,
                amount,
                ctypes.byref(read),
                None,
            ):
                raise OSError("Native held-file reading failed.")
            if read.value == 0 or read.value > amount:
                raise OSError("Native held-file reading was incomplete.")
            result.extend(buffer.raw[: read.value])
            remaining -= int(read.value)
        return bytes(result)


class NativeHeldPeProductBackend:
    """Native adapter that parses ``RT_VERSION`` without reopening a path."""

    __slots__ = ()

    @property
    def supported(self) -> bool:
        return os.name == "nt" and getattr(ctypes, "WinDLL", None) is not None

    def inspect_open_file(
        self, *, handle: object, snapshot: FileSnapshot
    ) -> PeVersionResource:
        if self.supported is not True or type(snapshot) is not FileSnapshot:
            raise WindowsSecurityError(
                "file_inspection_failed",
                "The Windows file could not be inspected safely.",
            )
        try:
            return parse_pe_version_resource(
                _NativeHeldFileReader(handle, snapshot.size)
            )
        except Exception:
            raise WindowsSecurityError(
                "file_inspection_failed",
                "The Windows file could not be inspected safely.",
            ) from None

    def __repr__(self) -> str:
        state = "supported" if self.supported else "unavailable"
        return f"NativeHeldPeProductBackend(state={state!r})"


def _final_leaf(final_path: str) -> str:
    try:
        leaf = PureWindowsPath(final_path).name
    except (TypeError, ValueError):
        _fail(RuntimeIdentityErrorCode.RUNTIME_IDENTITY_INVALID)
    if type(leaf) is not str or not _SAFE_LEAF.fullmatch(leaf):
        _fail(RuntimeIdentityErrorCode.RUNTIME_IDENTITY_INVALID)
    return leaf


def _product_matches(
    product: ProductPolicy,
    *,
    leaf: str,
    facts: PeVersionResource,
) -> bool:
    evidence = product.version_evidence
    try:
        fixed_prefix = tuple(int(part, 10) for part in product.exact_version.split("."))
    except (AttributeError, TypeError, ValueError):
        return False
    if len(fixed_prefix) != 3 or any(not 0 <= part <= 0xFFFF for part in fixed_prefix):
        return False
    return not (
        evidence.kind is not VersionEvidenceKind.PE_VERSION_RESOURCE
        or product.architecture != facts.machine
        or product.executable_name != leaf
        or evidence.company_name != facts.company_name
        or evidence.product_name != facts.product_name
        or evidence.original_filename != facts.original_filename
        or evidence.file_version != facts.file_version
        or evidence.product_version != facts.product_version
        or product.exact_version != facts.file_version
        or product.exact_version != facts.product_version
        or facts.fixed_file_version[:3] != fixed_prefix
        or facts.fixed_product_version[:3] != fixed_prefix
    )


def verify_package_bound_pe_product(
    bound_file: HandleBoundFile,
    *,
    backend: PeProductBackend | None = None,
) -> VerifiedPeProductEvidence:
    """Derive one exact PE product/version without a caller product assertion."""

    if type(bound_file) is not HandleBoundFile:
        _fail(RuntimeIdentityErrorCode.RUNTIME_IDENTITY_INVALID)
    try:
        policy = load_package_bound_runtime_policy()
    except RuntimePolicyError:
        _fail(RuntimeIdentityErrorCode.VERIFICATION_UNAVAILABLE)
    selected_backend = backend if backend is not None else NativeHeldPeProductBackend()
    try:
        supported = selected_backend.supported is True
    except Exception:
        supported = False
    if not supported:
        _fail(RuntimeIdentityErrorCode.VERIFICATION_UNAVAILABLE)
    try:
        facts = bound_file.inspect_same_handle(
            lambda handle, snapshot: selected_backend.inspect_open_file(
                handle=handle, snapshot=snapshot
            )
        )
    except WindowsSecurityError as error:
        if error.category in {"file_identity_changed", "file_handle_closed"}:
            _fail(RuntimeIdentityErrorCode.RUNTIME_REPLACED)
        _fail(RuntimeIdentityErrorCode.RUNTIME_IDENTITY_INVALID)
    except Exception:
        _fail(RuntimeIdentityErrorCode.RUNTIME_IDENTITY_INVALID)
    if type(facts) is not PeVersionResource:
        _fail(RuntimeIdentityErrorCode.RUNTIME_IDENTITY_INVALID)
    leaf = _final_leaf(bound_file.snapshot.final_path)
    matching = tuple(
        product
        for product in policy.products
        if _product_matches(product, leaf=leaf, facts=facts)
    )
    if len(matching) != 1:
        _fail(RuntimeIdentityErrorCode.RUNTIME_IDENTITY_INVALID)
    product = matching[0]
    return VerifiedPeProductEvidence(
        product_id=product.product_id,
        exact_version=product.exact_version,
        policy_sha256=policy.content_sha256,
        file_identity=bound_file.snapshot.identity,
        file_sha256=bound_file.snapshot.sha256,
        resource_sha256=facts.resource_sha256,
        fixed_file_version=facts.fixed_file_version,
        fixed_product_version=facts.fixed_product_version,
    )


@dataclass(frozen=True, slots=True)
class RegistryValueSelector:
    subkey: str
    name: str

    def __post_init__(self) -> None:
        if (
            type(self.subkey) is not str
            or type(self.name) is not str
            or not self.name
            or "\x00" in self.subkey
            or "\x00" in self.name
        ):
            raise ValueError("Registry value selector is invalid.")


@dataclass(frozen=True, slots=True, repr=False)
class RegistryStringValues:
    """Exact ``REG_SZ`` values returned in requested selector order."""

    values: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.values) is not tuple
            or len(self.values) > _MAX_REGISTRY_SELECTORS
            or any(
                type(value) is not str
                or not value
                or len(value) > _MAX_REGISTRY_VALUE_CHARACTERS
                or "\x00" in value
                or not _is_strict_utf8(value)
                for value in self.values
            )
        ):
            raise ValueError("Registry string evidence is invalid.")

    def __repr__(self) -> str:
        return f"RegistryStringValues(count={len(self.values)}, <redacted>)"


class InstallationRecordBackend(Protocol):
    """Exact registry and Known Folder seam; it performs no discovery."""

    @property
    def supported(self) -> bool: ...

    def read_string_values(
        self,
        *,
        hive: str,
        view: str,
        key: str,
        selectors: tuple[RegistryValueSelector, ...],
    ) -> RegistryStringValues | None: ...

    def known_folder_path(self, known_folder: str) -> str: ...


class _Guid(ctypes.Structure):
    _fields_ = (
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    )

    @classmethod
    def from_text(cls, value: str) -> "_Guid":
        raw = uuid.UUID(value).bytes_le
        return cls(
            int.from_bytes(raw[0:4], "little"),
            int.from_bytes(raw[4:6], "little"),
            int.from_bytes(raw[6:8], "little"),
            (ctypes.c_ubyte * 8).from_buffer_copy(raw[8:16]),
        )


_KNOWN_FOLDER_IDS = {
    "local_app_data": _Guid.from_text("f1b32785-6fba-4fcf-9d55-7b8e7f157091"),
    # The policy is AMD64-only, so do not let process redirection select the
    # 32-bit Program Files view on a future host or builder.
    "program_files": _Guid.from_text("6d809377-6af0-444b-8957-a3773f02200e"),
}


class NativeWindowsInstallationBackend:
    """Read exact 64-bit ``REG_SZ`` records and approved Known Folders."""

    __slots__ = ("_advapi32", "_ole32", "_shell32")

    def __init__(self) -> None:
        self._advapi32 = None
        self._ole32 = None
        self._shell32 = None
        if os.name != "nt":
            return
        try:
            win_dll = getattr(ctypes, "WinDLL")
            self._advapi32 = win_dll("advapi32", use_last_error=True)
            self._shell32 = win_dll("shell32", use_last_error=True)
            self._ole32 = win_dll("ole32", use_last_error=True)
            self._configure_signatures()
        except (AttributeError, OSError, TypeError, ValueError):
            self._advapi32 = None
            self._ole32 = None
            self._shell32 = None

    @property
    def supported(self) -> bool:
        return (
            self._advapi32 is not None
            and self._shell32 is not None
            and self._ole32 is not None
        )

    def _configure_signatures(self) -> None:
        if not self.supported:
            raise OSError("Native installation-record APIs are unavailable.")
        advapi32 = self._advapi32
        shell32 = self._shell32
        ole32 = self._ole32
        if advapi32 is None or shell32 is None or ole32 is None:
            raise OSError("Native installation-record APIs are unavailable.")
        advapi32.RegOpenKeyExW.argtypes = (
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        )
        advapi32.RegOpenKeyExW.restype = ctypes.c_long
        advapi32.RegGetValueW.argtypes = (
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        )
        advapi32.RegGetValueW.restype = ctypes.c_long
        advapi32.RegCloseKey.argtypes = (ctypes.c_void_p,)
        advapi32.RegCloseKey.restype = ctypes.c_long
        shell32.SHGetKnownFolderPath.argtypes = (
            ctypes.POINTER(_Guid),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_wchar_p),
        )
        shell32.SHGetKnownFolderPath.restype = ctypes.c_long
        ole32.CoTaskMemFree.argtypes = (ctypes.c_void_p,)
        ole32.CoTaskMemFree.restype = None

    @staticmethod
    def _hive_handle(hive: str) -> ctypes.c_void_p:
        values = {
            "HKEY_CURRENT_USER": 0x80000001,
            "HKEY_LOCAL_MACHINE": 0x80000002,
        }
        if hive not in values:
            raise ValueError("Registry hive is not approved.")
        return ctypes.c_void_p(ctypes.c_int32(values[hive]).value)

    def _open_key(
        self, hive: str, key: str, *, absent_allowed: bool
    ) -> ctypes.c_void_p | None:
        if self._advapi32 is None:
            raise OSError("Native registry access is unavailable.")
        handle = ctypes.c_void_p()
        status = int(
            self._advapi32.RegOpenKeyExW(
                self._hive_handle(hive),
                key,
                0,
                0x0001 | 0x0100,  # KEY_QUERY_VALUE | KEY_WOW64_64KEY
                ctypes.byref(handle),
            )
        )
        if status == 2 and absent_allowed:  # ERROR_FILE_NOT_FOUND
            return None
        if status != 0 or not handle.value:
            raise OSError(status, "Native registry key access failed.")
        return handle

    def _read_reg_sz(self, handle: ctypes.c_void_p, name: str) -> str:
        if self._advapi32 is None:
            raise OSError("Native registry access is unavailable.")
        flags = 0x00000002 | 0x10000000 | 0x20000000
        value_type = ctypes.c_uint32()
        required = ctypes.c_uint32()
        status = int(
            self._advapi32.RegGetValueW(
                handle,
                None,
                name,
                flags,
                ctypes.byref(value_type),
                None,
                ctypes.byref(required),
            )
        )
        if (
            status != 0
            or value_type.value != 1  # REG_SZ only, never REG_EXPAND_SZ
            or required.value < 2
            or required.value % ctypes.sizeof(ctypes.c_wchar) != 0
            or required.value
            > (_MAX_REGISTRY_VALUE_CHARACTERS + 1) * ctypes.sizeof(ctypes.c_wchar)
        ):
            raise ValueError("Registry value is not an approved string.")
        characters = required.value // ctypes.sizeof(ctypes.c_wchar)
        buffer = ctypes.create_unicode_buffer(characters)
        supplied = ctypes.c_uint32(required.value)
        status = int(
            self._advapi32.RegGetValueW(
                handle,
                None,
                name,
                flags,
                ctypes.byref(value_type),
                buffer,
                ctypes.byref(supplied),
            )
        )
        if status != 0 or value_type.value != 1 or supplied.value != required.value:
            raise ValueError("Registry value is not an approved string.")
        raw_value = "".join(buffer[:characters])
        if (
            not raw_value.endswith("\x00")
            or "\x00" in raw_value[:-1]
            or not raw_value[:-1]
        ):
            raise ValueError("Registry value is not an approved string.")
        return raw_value[:-1]

    def _read_once(
        self,
        *,
        hive: str,
        key: str,
        selectors: tuple[RegistryValueSelector, ...],
    ) -> RegistryStringValues | None:
        base = self._open_key(hive, key, absent_allowed=True)
        if base is None:
            return None
        handles: dict[str, ctypes.c_void_p] = {"": base}
        try:
            values: list[str] = []
            for selector in selectors:
                handle = handles.get(selector.subkey)
                if handle is None:
                    joined = key + "\\" + selector.subkey
                    handle = self._open_key(hive, joined, absent_allowed=False)
                    if handle is None:
                        raise ValueError("Required registry subkey is missing.")
                    handles[selector.subkey] = handle
                values.append(self._read_reg_sz(handle, selector.name))
            return RegistryStringValues(tuple(values))
        finally:
            if self._advapi32 is not None:
                for handle in handles.values():
                    self._advapi32.RegCloseKey(handle)

    def read_string_values(
        self,
        *,
        hive: str,
        view: str,
        key: str,
        selectors: tuple[RegistryValueSelector, ...],
    ) -> RegistryStringValues | None:
        if (
            not self.supported
            or view != "registry64"
            or type(selectors) is not tuple
            or not selectors
            or len(selectors) > _MAX_REGISTRY_SELECTORS
            or any(
                type(selector) is not RegistryValueSelector for selector in selectors
            )
        ):
            raise ValueError("Registry read request is invalid.")
        first = self._read_once(hive=hive, key=key, selectors=selectors)
        second = self._read_once(hive=hive, key=key, selectors=selectors)
        if first != second:
            raise RuntimeError("Registry values changed during inspection.")
        return first

    def known_folder_path(self, known_folder: str) -> str:
        if not self.supported or known_folder not in _KNOWN_FOLDER_IDS:
            raise ValueError("Known Folder request is invalid.")
        shell32 = self._shell32
        ole32 = self._ole32
        if shell32 is None or ole32 is None:
            raise OSError("Known Folder resolution is unavailable.")
        result = ctypes.c_wchar_p()
        status = int(
            shell32.SHGetKnownFolderPath(
                ctypes.byref(_KNOWN_FOLDER_IDS[known_folder]),
                0,
                None,
                ctypes.byref(result),
            )
        )
        try:
            if status != 0 or not result.value:
                raise OSError(status, "Known Folder resolution failed.")
            return result.value
        finally:
            if result:
                ole32.CoTaskMemFree(ctypes.cast(result, ctypes.c_void_p))

    def __repr__(self) -> str:
        state = "supported" if self.supported else "unavailable"
        return f"NativeWindowsInstallationBackend(state={state!r})"


@dataclass(frozen=True, slots=True, repr=False)
class InstallationCandidateEvidence:
    """Record nomination evidence; this is explicitly not runtime trust."""

    product_id: RuntimeProductId
    record_ids: tuple[str, ...]
    policy_sha256: str = field(repr=False)
    resolution_sha256: str = field(repr=False)
    file_identity: StableFileIdentity = field(repr=False)
    file_sha256: str = field(repr=False)
    evidence_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.product_id) is not RuntimeProductId
            or type(self.record_ids) is not tuple
            or not self.record_ids
            or len(set(self.record_ids)) != len(self.record_ids)
            or any(type(value) is not str or not value for value in self.record_ids)
            or not _is_sha256(self.policy_sha256)
            or not _is_sha256(self.resolution_sha256)
            or type(self.file_identity) is not StableFileIdentity
            or not _is_sha256(self.file_sha256)
        ):
            raise ValueError("Installation candidate evidence is invalid.")
        object.__setattr__(
            self,
            "evidence_sha256",
            _canonical_digest(
                _INSTALL_EVIDENCE_DOMAIN,
                (
                    self.product_id.value.encode("ascii"),
                    len(self.record_ids).to_bytes(2, "big"),
                    *(value.encode("ascii") for value in self.record_ids),
                    self.policy_sha256.encode("ascii"),
                    self.resolution_sha256.encode("ascii"),
                    *_identity_fields(self.file_identity),
                    self.file_sha256.encode("ascii"),
                ),
            ),
        )

    def __repr__(self) -> str:
        return (
            "InstallationCandidateEvidence("
            f"product={self.product_id.value!r}, records={len(self.record_ids)}, "
            "trust='unverified', <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _InstallObservation:
    record: InstallRecordPolicy
    candidate_path: str = field(repr=False)


def _record_selectors(
    record: InstallRecordPolicy,
) -> tuple[RegistryValueSelector, ...]:
    selectors = [
        RegistryValueSelector(value.subkey, value.name)
        for value in record.registry.required_values
    ]
    location = record.location
    if location.kind in {
        LocationKind.REGISTRY_DIRECTORY_RELATIVE,
        LocationKind.REGISTRY_FILE,
    }:
        location_selector = RegistryValueSelector(
            location.value_subkey, location.value_name
        )
        if location_selector not in selectors:
            selectors.append(location_selector)
    if not selectors or len(selectors) > _MAX_REGISTRY_SELECTORS:
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    return tuple(selectors)


def _canonical_absolute_windows_path(value: str, *, directory: bool) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_INSTALL_PATH_CHARACTERS
        or "\x00" in value
        or not _is_strict_utf8(value)
        or "%" in value
        or any(ord(character) < 0x20 for character in value)
        or any(character in _INVALID_PATH_CHARACTERS for character in value)
        or "/" in value
        or value.startswith("\\\\")
    ):
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    candidate = value
    if directory and len(candidate) > 3 and candidate.endswith("\\"):
        candidate = candidate[:-1]
    if candidate.endswith("\\") and len(candidate) > 3:
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    try:
        parsed = PureWindowsPath(candidate)
    except (TypeError, ValueError):
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    if (
        not parsed.is_absolute()
        or not _WINDOWS_DRIVE.fullmatch(parsed.drive)
        or parsed.root != "\\"
        or str(parsed) != candidate
    ):
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    for part in parsed.parts[1:]:
        if (
            not part
            or part in {".", ".."}
            or part.endswith((" ", "."))
            or ":" in part
            or part.casefold().partition(".")[0] in _RESERVED_LEAVES
        ):
            _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    return candidate


def _candidate_path(
    record: InstallRecordPolicy,
    selectors: tuple[RegistryValueSelector, ...],
    values: RegistryStringValues,
    backend: InstallationRecordBackend,
) -> str:
    if len(values.values) != len(selectors):
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    observed = dict(zip(selectors, values.values, strict=True))
    if len(observed) != len(selectors):
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    for required in record.registry.required_values:
        selector = RegistryValueSelector(required.subkey, required.name)
        if observed.get(selector) != required.equals:
            _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    location = record.location
    if location.kind is LocationKind.REGISTRY_DIRECTORY_RELATIVE:
        base = observed.get(
            RegistryValueSelector(location.value_subkey, location.value_name)
        )
        if base is None:
            _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
        canonical_base = _canonical_absolute_windows_path(base, directory=True)
        combined = str(PureWindowsPath(canonical_base) / location.relative_path)
        return _canonical_absolute_windows_path(combined, directory=False)
    if location.kind is LocationKind.REGISTRY_FILE:
        candidate = observed.get(
            RegistryValueSelector(location.value_subkey, location.value_name)
        )
        if candidate is None:
            _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
        canonical = _canonical_absolute_windows_path(candidate, directory=False)
        if PureWindowsPath(canonical).name != location.required_leaf_name:
            _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
        return canonical
    if location.kind is not LocationKind.KNOWN_FOLDER_RELATIVE:
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    try:
        known = backend.known_folder_path(location.known_folder)
    except Exception:
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    canonical_known = _canonical_absolute_windows_path(known, directory=True)
    combined = str(PureWindowsPath(canonical_known) / location.relative_path)
    return _canonical_absolute_windows_path(combined, directory=False)


def _scan_install_records(
    product: ProductPolicy,
    backend: InstallationRecordBackend,
) -> tuple[tuple[_InstallObservation, ...], str]:
    observations: list[_InstallObservation] = []
    digest_fields: list[bytes] = [product.product_id.value.encode("ascii")]
    for record in product.install_records:
        selectors = _record_selectors(record)
        try:
            result = backend.read_string_values(
                hive=record.registry.hive,
                view=record.registry.view,
                key=record.registry.key,
                selectors=selectors,
            )
        except RuntimeIdentityVerificationError:
            raise
        except Exception:
            _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
        digest_fields.extend((record.record_id.encode("ascii"),))
        if result is None:
            digest_fields.append(b"absent")
            continue
        if type(result) is not RegistryStringValues:
            _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
        candidate = _candidate_path(record, selectors, result, backend)
        digest_fields.extend(
            (
                b"present",
                len(selectors).to_bytes(2, "big"),
                *(
                    field
                    for selector, value in zip(selectors, result.values, strict=True)
                    for field in (
                        selector.subkey.encode("utf-8"),
                        selector.name.encode("utf-8"),
                        value.encode("utf-8"),
                    )
                ),
                candidate.encode("utf-8"),
            )
        )
        observations.append(_InstallObservation(record, candidate))
    return (
        tuple(observations),
        _canonical_digest(_INSTALL_RESOLUTION_DOMAIN, tuple(digest_fields)),
    )


def _product(policy: RuntimePolicy, product_id: RuntimeProductId) -> ProductPolicy:
    matching = tuple(
        product for product in policy.products if product.product_id is product_id
    )
    if len(matching) != 1:
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    return matching[0]


def _close_all(values: Sequence[HandleBoundFile]) -> None:
    for value in values:
        try:
            value.close()
        except BaseException:
            pass


def _candidate_key(bound: HandleBoundFile) -> tuple[object, ...]:
    snapshot = bound.snapshot
    return (
        snapshot.identity.volume_serial,
        snapshot.identity.file_id,
        snapshot.sha256,
        snapshot.final_path,
    )


class BoundInstallationCandidate:
    """Own one nominated executable handle until explicit close/context exit."""

    __slots__ = (
        "_backend",
        "_bound_file",
        "_evidence",
        "_product",
        "_resolution_sha256",
    )

    def __init__(
        self,
        *,
        backend: InstallationRecordBackend,
        bound_file: HandleBoundFile,
        evidence: InstallationCandidateEvidence,
        product: ProductPolicy,
        resolution_sha256: str,
    ) -> None:
        self._backend = backend
        self._bound_file = bound_file
        self._evidence = evidence
        self._product = product
        self._resolution_sha256 = resolution_sha256

    @property
    def evidence(self) -> InstallationCandidateEvidence:
        return self._evidence

    @property
    def bound_file(self) -> HandleBoundFile:
        if self.closed:
            _fail(RuntimeIdentityErrorCode.RUNTIME_REPLACED)
        return self._bound_file

    @property
    def closed(self) -> bool:
        return bool(self._bound_file.closed)

    def assert_unchanged(self) -> FileSnapshot:
        if self.closed:
            _fail(RuntimeIdentityErrorCode.RUNTIME_REPLACED)
        try:
            observations, digest = _scan_install_records(self._product, self._backend)
        except RuntimeIdentityVerificationError:
            _fail(RuntimeIdentityErrorCode.RUNTIME_REPLACED)
        if (
            digest != self._resolution_sha256
            or tuple(item.record.record_id for item in observations)
            != self._evidence.record_ids
        ):
            _fail(RuntimeIdentityErrorCode.RUNTIME_REPLACED)
        try:
            snapshot = self._bound_file.assert_unchanged()
        except WindowsSecurityError:
            _fail(RuntimeIdentityErrorCode.RUNTIME_REPLACED)
        if (
            snapshot.identity != self._evidence.file_identity
            or snapshot.sha256 != self._evidence.file_sha256
        ):
            _fail(RuntimeIdentityErrorCode.RUNTIME_REPLACED)
        return snapshot

    def close(self) -> None:
        self._bound_file.close()

    def __enter__(self) -> "BoundInstallationCandidate":
        if self.closed:
            _fail(RuntimeIdentityErrorCode.RUNTIME_REPLACED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return (
            "BoundInstallationCandidate("
            f"product={self._evidence.product_id.value!r}, state={state!r}, "
            "trust='unverified', <redacted>)"
        )


def open_package_bound_installation(
    product_id: RuntimeProductId,
    *,
    backend: InstallationRecordBackend | None = None,
    file_api: WindowsFileApi | None = None,
) -> BoundInstallationCandidate:
    """Open exactly one policy-record candidate and retain its held handle.

    The caller supplies only the closed product enum.  Every reviewed record is
    inspected in fixed policy order.  A present malformed record poisons the
    result, and distinct candidates fail closed rather than selecting a
    preferred scope.
    """

    if type(product_id) is not RuntimeProductId:
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    try:
        policy = load_package_bound_runtime_policy()
    except RuntimePolicyError:
        _fail(RuntimeIdentityErrorCode.VERIFICATION_UNAVAILABLE)
    product = _product(policy, product_id)
    selected_backend = (
        backend if backend is not None else NativeWindowsInstallationBackend()
    )
    try:
        supported = selected_backend.supported is True
    except Exception:
        supported = False
    if not supported:
        _fail(RuntimeIdentityErrorCode.VERIFICATION_UNAVAILABLE)
    observations, resolution_sha256 = _scan_install_records(product, selected_backend)
    if not observations:
        _fail(RuntimeIdentityErrorCode.INSTALLATION_NOT_FOUND)

    held: list[HandleBoundFile] = []
    observation_by_bound: list[_InstallObservation] = []
    try:
        for observation in observations:
            bound = capture_handle_bound_file(
                Path(observation.candidate_path),
                api=file_api,
                policy=FileCapturePolicy(
                    max_bytes=MAX_EXECUTABLE_BYTES,
                    require_single_link=False,
                ),
            )
            held.append(bound)
            if _final_leaf(bound.snapshot.final_path) != product.executable_name:
                bound.close()
                _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
            observation_by_bound.append(observation)
    except RuntimeIdentityVerificationError:
        _close_all(held)
        raise
    except WindowsSecurityError:
        _close_all(held)
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    except Exception:
        _close_all(held)
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    except BaseException:
        _close_all(held)
        raise

    try:
        current_observations, current_digest = _scan_install_records(
            product, selected_backend
        )
        if current_digest != resolution_sha256 or current_observations != observations:
            _fail(RuntimeIdentityErrorCode.RUNTIME_REPLACED)
        keys = tuple(_candidate_key(bound) for bound in held)
        if len(set(keys)) != 1:
            _fail(RuntimeIdentityErrorCode.INSTALLATION_AMBIGUOUS)
        selected = held[0]
        for duplicate in held[1:]:
            duplicate.close()
        evidence = InstallationCandidateEvidence(
            product_id=product.product_id,
            record_ids=tuple(
                observation.record.record_id for observation in observation_by_bound
            ),
            policy_sha256=policy.content_sha256,
            resolution_sha256=resolution_sha256,
            file_identity=selected.snapshot.identity,
            file_sha256=selected.snapshot.sha256,
        )
        return BoundInstallationCandidate(
            backend=selected_backend,
            bound_file=selected,
            evidence=evidence,
            product=product,
            resolution_sha256=resolution_sha256,
        )
    except RuntimeIdentityVerificationError:
        _close_all(held)
        raise
    except Exception:
        _close_all(held)
        _fail(RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID)
    except BaseException:
        _close_all(held)
        raise
