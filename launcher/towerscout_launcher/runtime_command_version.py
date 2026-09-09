"""Authenticated command-version evidence for retained Windows runtimes.

This module is intentionally isolated from launcher discovery, target planning,
and repair.  It extends the package-bound installation and Authenticode proofs
only for products whose reviewed version evidence is a fixed command.  The
returned owner remains non-executable and keeps the nominated file handle open
until explicit close.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any, NoReturn, Protocol, Sequence

from .authenticode import (
    AuthenticodeBackend,
    AuthenticodeErrorCode,
    AuthenticodeVerificationError,
    VerificationClock,
    VerifiedAuthenticodeEvidence,
    verify_package_bound_authenticode_signer,
)
from .runtime_identity import (
    _BoundFileTransferSlot,
    BoundInstallationCandidate,
    InstallationCandidateEvidence,
    InstallationRecordBackend,
    RuntimeIdentityErrorCode,
    RuntimeIdentityVerificationError,
    open_package_bound_installation,
)
from .runtime_policy import (
    ProductPolicy,
    RuntimePolicy,
    RuntimePolicyError,
    RuntimeProductId,
    VersionEvidenceKind,
    load_package_bound_runtime_policy,
)
from .windows_security import (
    FileSnapshot,
    StableFileIdentity,
    WindowsFileApi,
)

COMMAND_TIMEOUT_MS = 15_000
COMMAND_STDOUT_LIMIT_BYTES = 64 * 1024
COMMAND_STDERR_LIMIT_BYTES = 16 * 1024

_COMMAND_PRODUCTS = frozenset(
    {RuntimeProductId.DOCKER_COMPOSE, RuntimeProductId.PODMAN_CLI}
)
_COMMAND_KINDS = frozenset(
    {
        VersionEvidenceKind.AUTHENTICATED_COMMAND_TEXT,
        VersionEvidenceKind.AUTHENTICATED_COMMAND_JSON,
    }
)
_COMMAND_EVIDENCE_DOMAIN = b"TowerScout.VerifiedCommandVersion.v1"
_COMBINED_EVIDENCE_DOMAIN = b"TowerScout.CombinedCommandRuntimeEvidence.v1"
_PATH_EVIDENCE_DOMAIN = b"TowerScout.CommandExecutablePath.v1"
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_NORMAL_DRIVE = re.compile(r"^[A-Za-z]:$")
_EXTENDED_DRIVE = re.compile(r"^\\\\\?\\[A-Za-z]:$")
_ENVIRONMENT_NAMES = ("SystemRoot", "WINDIR")
_MAX_ARGUMENTS = 8
_MAX_ARGUMENT_CHARACTERS = 256
_MAX_PATH_CHARACTERS = 32_767
_MAX_JSON_DEPTH = 8
_MAX_JSON_NODES = 512
_MAX_JSON_COLLECTION_ITEMS = 128
_MAX_JSON_STRING_CHARACTERS = 4096
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


class CommandExecutionErrorCode(str, Enum):
    UNAVAILABLE = "unavailable"
    START_FAILED = "start_failed"
    OUTPUT_LIMIT = "output_limit"
    TIMEOUT = "timeout"
    CONTAINMENT_FAILED = "containment_failed"


class CommandExecutionError(RuntimeError):
    """Sanitized error from the bounded native process boundary."""

    _MESSAGES = {
        CommandExecutionErrorCode.UNAVAILABLE: (
            "Secure Windows command execution is unavailable."
        ),
        CommandExecutionErrorCode.START_FAILED: (
            "The authenticated Windows command could not be started safely."
        ),
        CommandExecutionErrorCode.OUTPUT_LIMIT: (
            "The authenticated Windows command exceeded its output limit."
        ),
        CommandExecutionErrorCode.TIMEOUT: (
            "The authenticated Windows command exceeded its time limit."
        ),
        CommandExecutionErrorCode.CONTAINMENT_FAILED: (
            "The authenticated Windows command could not be contained safely."
        ),
    }

    def __init__(self, code: CommandExecutionErrorCode) -> None:
        if type(code) is not CommandExecutionErrorCode:
            raise ValueError("Unknown command-execution error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"CommandExecutionError(code={self.code.value!r})"


class RuntimeCommandVerificationErrorCode(str, Enum):
    VERIFICATION_UNAVAILABLE = "verification_unavailable"
    RUNTIME_IDENTITY_INVALID = "runtime_identity_invalid"
    RUNTIME_REPLACED = "runtime_replaced"
    RUNTIME_OUTPUT_LIMIT = "runtime_output_limit"
    RUNTIME_TIMEOUT = "runtime_timeout"


class RuntimeCommandVerificationError(RuntimeError):
    """Sanitized command-version verification failure."""

    _MESSAGES = {
        RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE: (
            "Secure Windows runtime command verification is unavailable."
        ),
        RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID: (
            "The runtime installation, command version, or signer is not approved."
        ),
        RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED: (
            "The runtime executable or installation record changed during review."
        ),
        RuntimeCommandVerificationErrorCode.RUNTIME_OUTPUT_LIMIT: (
            "The runtime command exceeded the fixed safe output bound."
        ),
        RuntimeCommandVerificationErrorCode.RUNTIME_TIMEOUT: (
            "The runtime command exceeded the fixed safe time bound."
        ),
    }

    def __init__(self, code: RuntimeCommandVerificationErrorCode) -> None:
        if type(code) is not RuntimeCommandVerificationErrorCode:
            raise ValueError("Unknown runtime command-verification error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RuntimeCommandVerificationError(code={self.code.value!r})"


def _fail(code: RuntimeCommandVerificationErrorCode) -> NoReturn:
    raise RuntimeCommandVerificationError(code)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_digest(domain: bytes, fields: Sequence[bytes]) -> str:
    digest = hashlib.sha256()
    for value in (domain, *fields):
        if type(value) is not bytes or len(value) > 128 * 1024:
            raise ValueError("Runtime command evidence is invalid.")
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _identity_fields(identity: StableFileIdentity) -> tuple[bytes, bytes]:
    return (identity.volume_serial.to_bytes(8, "big"), identity.file_id)


def _path_sha256(value: PureWindowsPath) -> str:
    return _canonical_digest(
        _PATH_EVIDENCE_DOMAIN,
        (str(value).encode("utf-16-le", errors="strict"),),
    )


def _valid_argument(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= _MAX_ARGUMENT_CHARACTERS
        and "\x00" not in value
        and value == value.strip()
        and all(0x20 <= ord(character) < 0x7F for character in value)
    )


def _is_local_drive(drive: str) -> bool:
    return bool(_NORMAL_DRIVE.fullmatch(drive) or _EXTENDED_DRIVE.fullmatch(drive))


def _canonical_windows_path(
    value: object,
    *,
    required_leaf: str | None = None,
    allow_extended: bool,
) -> PureWindowsPath:
    invalid_scan_start = 4 if type(value) is str and value.startswith("\\\\?\\") else 2
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_PATH_CHARACTERS
        or "\x00" in value
        or "%" in value
        or "/" in value
        or any(ord(character) < 0x20 for character in value)
        or any(
            character in _INVALID_PATH_CHARACTERS
            for character in value[invalid_scan_start:]
        )
    ):
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    try:
        path = PureWindowsPath(value)
    except (TypeError, ValueError):
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    if (
        not path.is_absolute()
        or not _is_local_drive(path.drive)
        or (not allow_extended and _EXTENDED_DRIVE.fullmatch(path.drive))
        or path.root != "\\"
        or str(path) != value
        or value.endswith("\\")
    ):
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    for part in path.parts[1:]:
        if (
            not part
            or part in {".", ".."}
            or part.endswith((" ", "."))
            or ":" in part
            or part.casefold().partition(".")[0] in _RESERVED_LEAVES
        ):
            _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    if required_leaf is not None and path.name != required_leaf:
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    return path


@dataclass(frozen=True, slots=True, repr=False)
class CommandProcessRequest:
    """Fixed, minimal process request accepted by the contained backend."""

    executable_path: PureWindowsPath = field(repr=False)
    arguments: tuple[str, ...]
    environment: tuple[tuple[str, str], ...] = field(repr=False)
    working_directory: PureWindowsPath = field(repr=False)
    timeout_ms: int
    stdout_limit_bytes: int
    stderr_limit_bytes: int
    stdin_closed: bool = True
    shell: bool = False

    def __post_init__(self) -> None:
        paths_valid = False
        if (
            type(self.executable_path) is PureWindowsPath
            and type(self.working_directory) is PureWindowsPath
            and type(self.environment) is tuple
            and len(self.environment) == len(_ENVIRONMENT_NAMES)
            and all(
                type(item) is tuple
                and len(item) == 2
                and type(item[0]) is str
                and type(item[1]) is str
                and bool(item[1])
                and "\x00" not in item[1]
                for item in self.environment
            )
        ):
            try:
                executable = _canonical_windows_path(
                    str(self.executable_path), allow_extended=True
                )
                working = _canonical_windows_path(
                    str(self.working_directory), allow_extended=False
                )
                windows = _canonical_windows_path(
                    self.environment[0][1], allow_extended=False
                )
                paths_valid = (
                    str(executable) == str(self.executable_path)
                    and str(working) == str(self.working_directory)
                    and self.environment[0][1] == self.environment[1][1]
                    and working.parent == windows
                    and working.name == "System32"
                    and windows.name == "Windows"
                )
            except RuntimeCommandVerificationError:
                paths_valid = False
        if (
            not paths_valid
            or type(self.arguments) is not tuple
            or not 1 <= len(self.arguments) <= _MAX_ARGUMENTS
            or any(not _valid_argument(value) for value in self.arguments)
            or type(self.environment) is not tuple
            or len(self.environment) != len(_ENVIRONMENT_NAMES)
            or tuple(item[0] for item in self.environment) != _ENVIRONMENT_NAMES
            or self.timeout_ms != COMMAND_TIMEOUT_MS
            or self.stdout_limit_bytes != COMMAND_STDOUT_LIMIT_BYTES
            or self.stderr_limit_bytes != COMMAND_STDERR_LIMIT_BYTES
            or self.stdin_closed is not True
            or self.shell is not False
        ):
            raise ValueError("Contained command request is invalid.")

    def __repr__(self) -> str:
        return (
            "CommandProcessRequest("
            f"arguments={len(self.arguments)}, timeout_ms={self.timeout_ms}, "
            "environment='minimal', path='<redacted>')"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CommandProcessResult:
    """Bounded bytes and containment facts returned by a command backend."""

    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    exit_code: int
    stdin_closed: bool
    stdout_streamed: bool
    stderr_streamed: bool
    process_tree_contained: bool
    process_tree_empty: bool

    def __post_init__(self) -> None:
        if (
            type(self.stdout) is not bytes
            or len(self.stdout) > COMMAND_STDOUT_LIMIT_BYTES
            or type(self.stderr) is not bytes
            or len(self.stderr) > COMMAND_STDERR_LIMIT_BYTES
            or type(self.exit_code) is not int
            or isinstance(self.exit_code, bool)
            or not -(2**31) <= self.exit_code < 2**32
            or any(
                value is not True
                for value in (
                    self.stdin_closed,
                    self.stdout_streamed,
                    self.stderr_streamed,
                    self.process_tree_contained,
                    self.process_tree_empty,
                )
            )
        ):
            raise ValueError("Contained command result is invalid.")

    def __repr__(self) -> str:
        return (
            "CommandProcessResult("
            f"exit_code={self.exit_code}, stdout_bytes={len(self.stdout)}, "
            f"stderr_bytes={len(self.stderr)}, containment='verified')"
        )


class CommandVersionBackend(Protocol):
    """Injectable platform/process seam; implementations must not use ambient env."""

    @property
    def supported(self) -> bool: ...

    def windows_directory(self) -> str: ...

    def system_directory(self) -> str: ...

    def execute(self, request: CommandProcessRequest) -> CommandProcessResult: ...


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedCommandVersionEvidence:
    """Exact command-version proof bound to one retained executable snapshot."""

    product_id: RuntimeProductId
    exact_version: str
    evidence_kind: VersionEvidenceKind
    arguments: tuple[str, ...]
    policy_sha256: str = field(repr=False)
    file_identity: StableFileIdentity = field(repr=False)
    file_sha256: str = field(repr=False)
    executable_path_sha256: str = field(repr=False)
    output_sha256: str = field(repr=False)
    evidence_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            self.product_id not in _COMMAND_PRODUCTS
            or self.evidence_kind not in _COMMAND_KINDS
            or type(self.exact_version) is not str
            or not _VERSION.fullmatch(self.exact_version)
            or type(self.arguments) is not tuple
            or not 1 <= len(self.arguments) <= _MAX_ARGUMENTS
            or any(not _valid_argument(value) for value in self.arguments)
            or not _is_sha256(self.policy_sha256)
            or type(self.file_identity) is not StableFileIdentity
            or not _is_sha256(self.file_sha256)
            or not _is_sha256(self.executable_path_sha256)
            or not _is_sha256(self.output_sha256)
        ):
            raise ValueError("Verified command-version evidence is invalid.")
        object.__setattr__(
            self,
            "evidence_sha256",
            _canonical_digest(
                _COMMAND_EVIDENCE_DOMAIN,
                (
                    self.product_id.value.encode("ascii"),
                    self.exact_version.encode("ascii"),
                    self.evidence_kind.value.encode("ascii"),
                    len(self.arguments).to_bytes(1, "big"),
                    *(value.encode("ascii") for value in self.arguments),
                    self.policy_sha256.encode("ascii"),
                    *_identity_fields(self.file_identity),
                    self.file_sha256.encode("ascii"),
                    self.executable_path_sha256.encode("ascii"),
                    self.output_sha256.encode("ascii"),
                ),
            ),
        )

    def __repr__(self) -> str:
        return (
            "VerifiedCommandVersionEvidence("
            f"product={self.product_id.value!r}, version={self.exact_version!r}, "
            "path='<redacted>', output='<redacted>')"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CombinedCommandRuntimeEvidence:
    """Installation, signer, and command-version proof for one held file."""

    installation: InstallationCandidateEvidence = field(repr=False)
    authenticode: VerifiedAuthenticodeEvidence = field(repr=False)
    command: VerifiedCommandVersionEvidence = field(repr=False)
    product_id: RuntimeProductId = field(init=False)
    exact_version: str = field(init=False)
    policy_sha256: str = field(init=False, repr=False)
    file_identity: StableFileIdentity = field(init=False, repr=False)
    file_sha256: str = field(init=False, repr=False)
    executable_path_sha256: str = field(init=False, repr=False)
    evidence_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.installation) is not InstallationCandidateEvidence
            or type(self.authenticode) is not VerifiedAuthenticodeEvidence
            or type(self.command) is not VerifiedCommandVersionEvidence
        ):
            raise ValueError("Combined command runtime evidence is invalid.")
        product_id = self.command.product_id
        policies = (
            self.installation.policy_sha256,
            self.authenticode.policy_sha256,
            self.command.policy_sha256,
        )
        identities = (
            self.installation.file_identity,
            self.authenticode.file_identity,
            self.command.file_identity,
        )
        file_hashes = (
            self.installation.file_sha256,
            self.authenticode.file_sha256,
            self.command.file_sha256,
        )
        evidence_hashes = (
            self.installation.evidence_sha256,
            self.authenticode.evidence_sha256,
            self.command.evidence_sha256,
        )
        if (
            self.installation.product_id is not product_id
            or product_id not in self.authenticode.signer_policy_product_ids
            or len(set(policies)) != 1
            or len(set(identities)) != 1
            or len(set(file_hashes)) != 1
            or any(not _is_sha256(value) for value in (*policies, *file_hashes))
            or any(not _is_sha256(value) for value in evidence_hashes)
        ):
            raise ValueError("Combined command runtime evidence is invalid.")
        identity = identities[0]
        object.__setattr__(self, "product_id", product_id)
        object.__setattr__(self, "exact_version", self.command.exact_version)
        object.__setattr__(self, "policy_sha256", policies[0])
        object.__setattr__(self, "file_identity", identity)
        object.__setattr__(self, "file_sha256", file_hashes[0])
        object.__setattr__(
            self, "executable_path_sha256", self.command.executable_path_sha256
        )
        object.__setattr__(
            self,
            "evidence_sha256",
            _canonical_digest(
                _COMBINED_EVIDENCE_DOMAIN,
                (
                    product_id.value.encode("ascii"),
                    self.command.exact_version.encode("ascii"),
                    policies[0].encode("ascii"),
                    *_identity_fields(identity),
                    file_hashes[0].encode("ascii"),
                    self.command.executable_path_sha256.encode("ascii"),
                    *(value.encode("ascii") for value in evidence_hashes),
                ),
            ),
        )

    def __repr__(self) -> str:
        return (
            "CombinedCommandRuntimeEvidence("
            f"product={self.product_id.value!r}, version={self.exact_version!r}, "
            "state='non-executable', <redacted>)"
        )


def combine_command_runtime_evidence(
    installation: InstallationCandidateEvidence,
    authenticode: VerifiedAuthenticodeEvidence,
    command: VerifiedCommandVersionEvidence,
) -> CombinedCommandRuntimeEvidence:
    try:
        return CombinedCommandRuntimeEvidence(installation, authenticode, command)
    except (TypeError, ValueError):
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)


def _single_terminal_eol(data: bytes) -> bytes:
    if data.endswith(b"\r\n"):
        value = data[:-2]
    elif data.endswith(b"\n"):
        value = data[:-1]
    else:
        value = data
    if not value or value.endswith((b"\r", b"\n")):
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    return value


class _JsonFailure(Exception):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise _JsonFailure
        result[key] = value
    return result


def _strict_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 19:
        raise _JsonFailure
    try:
        return int(value, 10)
    except (TypeError, ValueError, OverflowError):
        raise _JsonFailure from None


def _reject_json_number(_value: str) -> NoReturn:
    raise _JsonFailure


def _walk_json(value: Any, *, depth: int, nodes: list[int]) -> None:
    nodes[0] += 1
    if nodes[0] > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
        raise _JsonFailure
    if value is None or type(value) in {bool, int}:
        if type(value) is int and not -(2**63) <= value < 2**63:
            raise _JsonFailure
        return
    if type(value) is str:
        if len(value) > _MAX_JSON_STRING_CHARACTERS or "\x00" in value:
            raise _JsonFailure
        return
    if type(value) is list:
        if len(value) > _MAX_JSON_COLLECTION_ITEMS:
            raise _JsonFailure
        for item in value:
            _walk_json(item, depth=depth + 1, nodes=nodes)
        return
    if type(value) is dict:
        if len(value) > _MAX_JSON_COLLECTION_ITEMS:
            raise _JsonFailure
        for key, item in value.items():
            _walk_json(key, depth=depth + 1, nodes=nodes)
            _walk_json(item, depth=depth + 1, nodes=nodes)
        return
    raise _JsonFailure


def _decode_output(data: bytes) -> str:
    if not data or data.startswith(b"\xef\xbb\xbf") or b"\x00" in data:
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeError:
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)


def _parse_text_version(data: bytes, expected: str) -> str:
    value = _decode_output(_single_terminal_eol(data))
    if value != expected or not _VERSION.fullmatch(value):
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    return value


def _parse_json_version(data: bytes, pointer: str, expected: str) -> str:
    text = _decode_output(_single_terminal_eol(data))
    if text != text.lstrip() or text != text.rstrip():
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_int=_strict_integer,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
        _walk_json(value, depth=0, nodes=[0])
        if type(value) is not dict or not pointer.startswith("/") or "~" in pointer:
            raise _JsonFailure
        selected: Any = value
        for token in pointer[1:].split("/"):
            if type(selected) is not dict or not token or token not in selected:
                raise _JsonFailure
            selected = selected[token]
        if type(selected) is not str or selected != expected:
            raise _JsonFailure
    except (
        UnicodeError,
        json.JSONDecodeError,
        OverflowError,
        RecursionError,
        TypeError,
        ValueError,
        _JsonFailure,
    ):
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    return selected


def _map_identity_error(error: RuntimeIdentityVerificationError) -> NoReturn:
    if error.code is RuntimeIdentityErrorCode.VERIFICATION_UNAVAILABLE:
        _fail(RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    if error.code is RuntimeIdentityErrorCode.RUNTIME_REPLACED:
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
    _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)


def _map_authenticode_error(error: AuthenticodeVerificationError) -> NoReturn:
    if error.code is AuthenticodeErrorCode.VERIFICATION_UNAVAILABLE:
        _fail(RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    if error.code is AuthenticodeErrorCode.RUNTIME_REPLACED:
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
    _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)


def _map_execution_error(error: CommandExecutionError) -> NoReturn:
    if error.code is CommandExecutionErrorCode.OUTPUT_LIMIT:
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_OUTPUT_LIMIT)
    if error.code is CommandExecutionErrorCode.TIMEOUT:
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_TIMEOUT)
    _fail(RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE)


def _load_command_product_policy(
    product_id: RuntimeProductId,
) -> tuple[RuntimePolicy, ProductPolicy]:
    if type(product_id) is not RuntimeProductId:
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    try:
        policy = load_package_bound_runtime_policy()
    except RuntimePolicyError:
        _fail(RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    products = tuple(
        product for product in policy.products if product.product_id is product_id
    )
    if len(products) != 1:
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    product = products[0]
    if product_id not in _COMMAND_PRODUCTS or product.version_evidence.kind not in (
        _COMMAND_KINDS
    ):
        _fail(RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    return policy, product


def _minimal_process_context(
    backend: CommandVersionBackend,
) -> tuple[tuple[tuple[str, str], ...], PureWindowsPath]:
    try:
        windows_text = backend.windows_directory()
        system_text = backend.system_directory()
        windows_path = _canonical_windows_path(windows_text, allow_extended=False)
        system_path = _canonical_windows_path(system_text, allow_extended=False)
    except RuntimeCommandVerificationError:
        raise
    except Exception:
        _fail(RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    if (
        system_path.parent != windows_path
        or system_path.name != "System32"
        or windows_path.name != "Windows"
    ):
        _fail(RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    return (
        tuple((name, str(windows_path)) for name in _ENVIRONMENT_NAMES),
        system_path,
    )


def _snapshot_matches(
    snapshot: FileSnapshot,
    evidence: CombinedCommandRuntimeEvidence,
) -> bool:
    if (
        type(snapshot) is not FileSnapshot
        or snapshot.identity != evidence.file_identity
        or snapshot.sha256 != evidence.file_sha256
    ):
        return False
    try:
        path = _canonical_windows_path(snapshot.final_path, allow_extended=True)
    except RuntimeCommandVerificationError:
        return False
    return _path_sha256(path) == evidence.executable_path_sha256


class BoundCommandRuntimeEvidence:
    """Own inert command-version evidence and its retained executable handle."""

    __slots__ = ("_active_owner", "_candidate", "_evidence", "_lifetime_lock")

    def __init__(
        self,
        *,
        candidate: BoundInstallationCandidate,
        evidence: CombinedCommandRuntimeEvidence,
    ) -> None:
        if (
            type(candidate) is not BoundInstallationCandidate
            or type(evidence) is not CombinedCommandRuntimeEvidence
            or candidate.evidence != evidence.installation
            or candidate.closed
        ):
            raise ValueError("Bound command runtime evidence is invalid.")
        self._candidate = candidate
        self._evidence = evidence
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None

    @property
    def evidence(self) -> CombinedCommandRuntimeEvidence:
        return self._evidence

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            return bool(self._candidate.closed)

    def assert_unchanged(self) -> CombinedCommandRuntimeEvidence:
        self._lifetime_lock.acquire()
        if self._active_owner is not None or self._candidate.closed:
            self._lifetime_lock.release()
            _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
        self._active_owner = threading.get_ident()
        try:
            try:
                snapshot = self._candidate.assert_unchanged()
            except RuntimeIdentityVerificationError as error:
                _map_identity_error(error)
            except Exception:
                _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
            if not _snapshot_matches(snapshot, self._evidence):
                _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
            return self._evidence
        finally:
            self._active_owner = None
            self._lifetime_lock.release()

    def _transfer_bound_file(self, slot: _BoundFileTransferSlot) -> None:
        """Transfer into an armed internal slot after final revalidation."""

        if type(slot) is not _BoundFileTransferSlot:
            _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
        self._lifetime_lock.acquire()
        if self._active_owner is not None or self._candidate.closed:
            self._lifetime_lock.release()
            _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
        self._active_owner = threading.get_ident()
        try:
            try:
                snapshot = self._candidate.assert_unchanged()
            except RuntimeIdentityVerificationError as error:
                _map_identity_error(error)
            except Exception:
                _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
            if not _snapshot_matches(snapshot, self._evidence):
                _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
            try:
                self._candidate._release_bound_file(slot)  # noqa: SLF001
                slot.bound_file
            except RuntimeIdentityVerificationError as error:
                _map_identity_error(error)
            except BaseException as error:
                if isinstance(error, Exception):
                    _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
                raise
        finally:
            self._active_owner = None
            self._lifetime_lock.release()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
            try:
                self._candidate.close()
            except Exception:
                _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)

    def __enter__(self) -> "BoundCommandRuntimeEvidence":
        if self.closed:
            _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return (
            "BoundCommandRuntimeEvidence("
            f"product={self._evidence.product_id.value!r}, state={state!r}, "
            "capability='non-executable', <redacted>)"
        )


def _close_candidate(candidate: BoundInstallationCandidate | None) -> None:
    if candidate is None:
        return
    try:
        candidate.close()
    except BaseException:
        pass


def _execute_version_command(
    *,
    backend: CommandVersionBackend,
    product: ProductPolicy,
    executable_path: PureWindowsPath,
    environment: tuple[tuple[str, str], ...],
    working_directory: PureWindowsPath,
) -> tuple[str, CommandProcessResult]:
    version_policy = product.version_evidence
    try:
        result = backend.execute(
            CommandProcessRequest(
                executable_path=executable_path,
                arguments=version_policy.arguments,
                environment=environment,
                working_directory=working_directory,
                timeout_ms=COMMAND_TIMEOUT_MS,
                stdout_limit_bytes=COMMAND_STDOUT_LIMIT_BYTES,
                stderr_limit_bytes=COMMAND_STDERR_LIMIT_BYTES,
            )
        )
    except CommandExecutionError as error:
        _map_execution_error(error)
    except Exception:
        _fail(RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    if (
        type(result) is not CommandProcessResult
        or result.exit_code != 0
        or result.stderr
        or result.stdin_closed is not True
        or result.stdout_streamed is not True
        or result.stderr_streamed is not True
        or result.process_tree_contained is not True
        or result.process_tree_empty is not True
    ):
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    if version_policy.kind is VersionEvidenceKind.AUTHENTICATED_COMMAND_TEXT:
        return _parse_text_version(result.stdout, version_policy.exact_output), result
    if version_policy.kind is VersionEvidenceKind.AUTHENTICATED_COMMAND_JSON:
        return (
            _parse_json_version(
                result.stdout,
                version_policy.json_pointer,
                product.exact_version,
            ),
            result,
        )
    _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)


def open_package_bound_command_runtime_evidence(
    product_id: RuntimeProductId,
    *,
    installation_backend: InstallationRecordBackend | None = None,
    file_api: WindowsFileApi | None = None,
    authenticode_backend: AuthenticodeBackend | None = None,
    command_backend: CommandVersionBackend | None = None,
    clock: VerificationClock | None = None,
) -> BoundCommandRuntimeEvidence:
    """Authenticate, execute one fixed version command, and retain its handle."""

    policy, product = _load_command_product_policy(product_id)
    if command_backend is None:
        try:
            from .runtime_command_native import NativeWindowsCommandVersionBackend

            selected_backend: CommandVersionBackend = (
                NativeWindowsCommandVersionBackend()
            )
        except Exception:
            _fail(RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    else:
        selected_backend = command_backend
    try:
        supported = selected_backend.supported is True
    except Exception:
        supported = False
    if not supported:
        _fail(RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    environment, working_directory = _minimal_process_context(selected_backend)

    candidate: BoundInstallationCandidate | None = None
    transferred = False
    try:
        candidate = open_package_bound_installation(
            product_id,
            backend=installation_backend,
            file_api=file_api,
        )
        bound_file = candidate.bound_file
        executable_path = _canonical_windows_path(
            bound_file.snapshot.final_path,
            required_leaf=product.executable_name,
            allow_extended=True,
        )
        path_sha256 = _path_sha256(executable_path)
        authenticode = verify_package_bound_authenticode_signer(
            bound_file,
            backend=authenticode_backend,
            clock=clock,
        )
        if (
            product_id not in authenticode.signer_policy_product_ids
            or authenticode.policy_sha256 != policy.content_sha256
            or authenticode.file_identity != candidate.evidence.file_identity
            or authenticode.file_sha256 != candidate.evidence.file_sha256
        ):
            _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)

        pre_command_snapshot = candidate.assert_unchanged()
        if (
            candidate.bound_file is not bound_file
            or _path_sha256(
                _canonical_windows_path(
                    pre_command_snapshot.final_path,
                    required_leaf=product.executable_name,
                    allow_extended=True,
                )
            )
            != path_sha256
        ):
            _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)

        exact_version, result = _execute_version_command(
            backend=selected_backend,
            product=product,
            executable_path=executable_path,
            environment=environment,
            working_directory=working_directory,
        )
        if exact_version != product.exact_version:
            _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
        command = VerifiedCommandVersionEvidence(
            product_id=product_id,
            exact_version=exact_version,
            evidence_kind=product.version_evidence.kind,
            arguments=product.version_evidence.arguments,
            policy_sha256=policy.content_sha256,
            file_identity=candidate.evidence.file_identity,
            file_sha256=candidate.evidence.file_sha256,
            executable_path_sha256=path_sha256,
            output_sha256=hashlib.sha256(result.stdout).hexdigest(),
        )
        evidence = combine_command_runtime_evidence(
            candidate.evidence,
            authenticode,
            command,
        )
        final_snapshot = candidate.assert_unchanged()
        if not _snapshot_matches(final_snapshot, evidence):
            _fail(RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED)
        owner = BoundCommandRuntimeEvidence(candidate=candidate, evidence=evidence)
        transferred = True
        return owner
    except RuntimeCommandVerificationError:
        raise
    except RuntimeIdentityVerificationError as error:
        _map_identity_error(error)
    except AuthenticodeVerificationError as error:
        _map_authenticode_error(error)
    except (TypeError, ValueError):
        _fail(RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    except Exception:
        _fail(RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    finally:
        if not transferred:
            _close_candidate(candidate)


__all__ = [
    "BoundCommandRuntimeEvidence",
    "CommandExecutionError",
    "CommandExecutionErrorCode",
    "CommandProcessResult",
    "CommandVersionBackend",
    "CombinedCommandRuntimeEvidence",
    "RuntimeCommandVerificationError",
    "RuntimeCommandVerificationErrorCode",
    "VerifiedCommandVersionEvidence",
    "combine_command_runtime_evidence",
    "open_package_bound_command_runtime_evidence",
]
