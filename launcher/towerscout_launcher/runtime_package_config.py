"""Handle-bound package configuration needed by secure runtime resolution.

This module deliberately reads only the Podman machine selector from an
existing package ``.env`` file.  The source file and its package-root hierarchy
remain held while the value is consumed, and neither the value nor unrelated
configuration is exposed through evidence, representations, or errors.

An absent ``.env`` remains a fail-closed condition here.  The later atomic
replacement slice owns authenticated ``.env.example`` fallback and secure
absence proof.
"""

from __future__ import annotations

import hashlib
import ntpath
import re
import struct
import sys
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PureWindowsPath
from typing import Callable, NoReturn, Sequence, TypeVar

from .target_contracts import FileIdentity
from .windows_path_trust import (
    PathHierarchyTrust,
    PathTrustPurpose,
    WindowsPathTrustApi,
    capture_path_hierarchy,
)
from .windows_security import (
    FileCapturePolicy,
    FileSnapshot,
    HandleBoundFile,
    RandomAccessFileReader,
    StableFileIdentity,
    WindowsFileApi,
    WindowsSecurityError,
    capture_handle_bound_file,
)

_MACHINE_SETTING = "TOWERSCOUT_PODMAN_MACHINE"
_MACHINE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_ENV_BYTES = 262_144
_READ_CHUNK_BYTES = 65_536
_BINDING_DOMAIN = b"TowerScout.PackagePodmanMachine.v1"
_Result = TypeVar("_Result")


class _ConfigurationOperationFailure(BaseException):
    """Keep callback failures distinct from failures of the held config leases."""

    def __init__(self, error: BaseException) -> None:
        self.error = error
        super().__init__()


class PackageConfigurationErrorCode(str, Enum):
    VERIFICATION_UNAVAILABLE = "verification_unavailable"
    CONFIGURATION_INVALID = "configuration_invalid"
    CONFIGURATION_CHANGED = "configuration_changed"


class PackageConfigurationError(RuntimeError):
    """Sanitized package-configuration verification failure."""

    _MESSAGES = {
        PackageConfigurationErrorCode.VERIFICATION_UNAVAILABLE: (
            "Secure package configuration verification is unavailable."
        ),
        PackageConfigurationErrorCode.CONFIGURATION_INVALID: (
            "The package Podman machine setting is missing or invalid."
        ),
        PackageConfigurationErrorCode.CONFIGURATION_CHANGED: (
            "The package configuration changed during verification."
        ),
    }

    def __init__(self, code: PackageConfigurationErrorCode) -> None:
        if type(code) is not PackageConfigurationErrorCode:
            raise ValueError("Unknown package configuration error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"PackageConfigurationError(code={self.code.value!r})"


def _fail(code: PackageConfigurationErrorCode) -> NoReturn:
    raise PackageConfigurationError(code)


def _digest(domain: bytes, fields: Sequence[bytes]) -> str:
    digest = hashlib.sha256()
    for value in (domain, *fields):
        if type(value) is not bytes or len(value) > _MAX_ENV_BYTES:
            raise ValueError("Package configuration evidence field is invalid.")
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _path_key(path: PureWindowsPath) -> str:
    value = str(path)
    if value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def _snapshot_identity(snapshot: FileSnapshot) -> FileIdentity:
    return FileIdentity(
        logical_name=".env",
        final_path=PureWindowsPath(snapshot.final_path),
        volume_serial=snapshot.identity.volume_serial,
        file_id=snapshot.identity.file_id,
        sha256=snapshot.sha256,
        size_bytes=snapshot.size,
    )


def _snapshot_matches(snapshot: FileSnapshot, identity: FileIdentity) -> bool:
    try:
        return (
            type(snapshot) is FileSnapshot
            and type(identity) is FileIdentity
            and identity.logical_name == ".env"
            and not identity.is_directory
            and snapshot.identity.volume_serial == identity.volume_serial
            and snapshot.identity.file_id == identity.file_id
            and snapshot.sha256 == identity.sha256
            and snapshot.size == identity.size_bytes
            and _path_key(PureWindowsPath(snapshot.final_path))
            == _path_key(identity.final_path)
        )
    except (TypeError, ValueError, UnicodeError):
        return False


def _read_all(reader: RandomAccessFileReader, _snapshot: FileSnapshot) -> bytes:
    if not 1 <= reader.size <= _MAX_ENV_BYTES:
        _fail(PackageConfigurationErrorCode.CONFIGURATION_INVALID)
    offset = 0
    chunks: list[bytes] = []
    while offset < reader.size:
        amount = min(_READ_CHUNK_BYTES, reader.size - offset)
        chunk = reader.read_at(offset, amount)
        if type(chunk) is not bytes or len(chunk) != amount:
            _fail(PackageConfigurationErrorCode.CONFIGURATION_INVALID)
        chunks.append(chunk)
        offset += amount
    return b"".join(chunks)


def _parse_machine(contents: bytes) -> str:
    if type(contents) is not bytes or not 1 <= len(contents) <= _MAX_ENV_BYTES:
        _fail(PackageConfigurationErrorCode.CONFIGURATION_INVALID)
    try:
        text = contents.decode("utf-8", errors="strict")
    except UnicodeError:
        _fail(PackageConfigurationErrorCode.CONFIGURATION_INVALID)
    if (
        text.startswith("\ufeff")
        or "\x00" in text
        or any(character in text for character in ("\x85", "\u2028", "\u2029"))
        or any(
            ord(character) < 0x20 and character not in {"\t", "\r", "\n"}
            for character in text
        )
    ):
        _fail(PackageConfigurationErrorCode.CONFIGURATION_INVALID)

    normalized_text = text.replace("\r\n", "\n")
    if "\r" in normalized_text:
        _fail(PackageConfigurationErrorCode.CONFIGURATION_INVALID)
    matches: list[str] = []
    for raw_line in normalized_text.split("\n"):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, separator, value = raw_line.partition("=")
        normalized_name = name.strip()
        if normalized_name.casefold() != _MACHINE_SETTING.casefold():
            continue
        if separator != "=" or normalized_name != _MACHINE_SETTING:
            _fail(PackageConfigurationErrorCode.CONFIGURATION_INVALID)
        candidate = value.strip()
        if not _MACHINE_NAME.fullmatch(candidate):
            _fail(PackageConfigurationErrorCode.CONFIGURATION_INVALID)
        matches.append(candidate)
    if len(matches) != 1:
        _fail(PackageConfigurationErrorCode.CONFIGURATION_INVALID)
    return matches[0]


def _binding_sha256(
    machine: str,
    source: FileIdentity,
    package_root: StableFileIdentity,
) -> str:
    return _digest(
        _BINDING_DOMAIN,
        (
            machine.encode("utf-8", errors="strict"),
            source.volume_serial.to_bytes(8, "big"),
            source.file_id,
            source.sha256.encode("ascii"),
            source.size_bytes.to_bytes(8, "big"),
            _path_key(source.final_path).encode("utf-16-le", errors="strict"),
            package_root.volume_serial.to_bytes(8, "big"),
            package_root.file_id,
        ),
    )


@dataclass(frozen=True, slots=True, repr=False)
class PodmanMachineConfigurationEvidence:
    """Opaque proof that one machine name came from the held package ``.env``."""

    environment_source: FileIdentity = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    configured_machine_sha256: str = field(repr=False)
    binding_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.environment_source) is not FileIdentity
            or self.environment_source.logical_name != ".env"
            or self.environment_source.is_directory
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.configured_machine_sha256) is not str
            or not _SHA256.fullmatch(self.configured_machine_sha256)
            or type(self.binding_sha256) is not str
            or not _SHA256.fullmatch(self.binding_sha256)
        ):
            raise ValueError("Podman machine configuration evidence is invalid.")

    def __repr__(self) -> str:
        return "PodmanMachineConfigurationEvidence(state='verified', <redacted>)"


class BoundPodmanMachineConfiguration:
    """Own the package root and ``.env`` handles behind one machine selector."""

    __slots__ = (
        "_active_owner",
        "_environment",
        "_evidence",
        "_lifetime_lock",
        "_machine",
        "_package_root",
    )

    def __init__(
        self,
        *,
        machine: str,
        package_root: PathHierarchyTrust,
        environment: HandleBoundFile,
        evidence: PodmanMachineConfigurationEvidence,
    ) -> None:
        if (
            type(machine) is not str
            or not _MACHINE_NAME.fullmatch(machine)
            or type(package_root) is not PathHierarchyTrust
            or package_root.closed
            or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
            or type(environment) is not HandleBoundFile
            or environment.closed
            or type(evidence) is not PodmanMachineConfigurationEvidence
            or package_root.evidence.root_identity != evidence.package_root_identity
            or not _snapshot_matches(environment.snapshot, evidence.environment_source)
            or hashlib.sha256(machine.encode("utf-8", errors="strict")).hexdigest()
            != evidence.configured_machine_sha256
            or _binding_sha256(
                machine,
                evidence.environment_source,
                evidence.package_root_identity,
            )
            != evidence.binding_sha256
        ):
            raise ValueError("Bound Podman machine configuration is invalid.")
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None
        self._machine = machine
        self._package_root: PathHierarchyTrust | None = package_root
        self._environment: HandleBoundFile | None = environment
        self._evidence = evidence

    @property
    def evidence(self) -> PodmanMachineConfigurationEvidence:
        return self._evidence

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            return self._package_root is None or self._environment is None

    @property
    def _fully_closed(self) -> bool:
        with self._lifetime_lock:
            package_root = self._package_root
            environment = self._environment
            return bool(
                (package_root is None or package_root.closed)
                and (environment is None or environment.closed)
            )

    def _begin_use(self) -> tuple[PathHierarchyTrust, HandleBoundFile]:
        self._lifetime_lock.acquire()
        if self._active_owner is not None:
            self._lifetime_lock.release()
            _fail(PackageConfigurationErrorCode.CONFIGURATION_CHANGED)
        package_root = self._package_root
        environment = self._environment
        if (
            package_root is None
            or environment is None
            or package_root.closed
            or environment.closed
        ):
            self._lifetime_lock.release()
            _fail(PackageConfigurationErrorCode.CONFIGURATION_CHANGED)
        self._active_owner = threading.get_ident()
        return package_root, environment

    def _end_use(self) -> None:
        self._active_owner = None
        self._lifetime_lock.release()

    def _run_while_held(
        self,
        operation: Callable[[str, PodmanMachineConfigurationEvidence], _Result],
    ) -> _Result:
        """Run an internal resolver step without exposing the held file handles."""

        if not callable(operation):
            raise ValueError("Package configuration operation is invalid.")
        package_root, environment = self._begin_use()

        def invoke() -> _Result:
            try:
                return operation(self._machine, self._evidence)
            except BaseException as error:
                raise _ConfigurationOperationFailure(error) from None

        try:
            return package_root.run_while_held(
                lambda: environment.run_while_held(invoke)
            )
        except _ConfigurationOperationFailure as failure:
            raise failure.error
        except PackageConfigurationError:
            raise
        except WindowsSecurityError:
            _fail(PackageConfigurationErrorCode.CONFIGURATION_CHANGED)
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise
        finally:
            self._end_use()

    def assert_unchanged(self) -> PodmanMachineConfigurationEvidence:
        return self._run_while_held(lambda _machine, evidence: evidence)

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(PackageConfigurationErrorCode.CONFIGURATION_CHANGED)
            environment = self._environment
            package_root = self._package_root
            failed = False
            interruption: BaseException | None = None
            if environment is not None:
                try:
                    environment.close()
                except BaseException as error:
                    if isinstance(error, Exception):
                        failed = True
                    else:
                        interruption = error
                if environment.closed:
                    self._environment = None
                else:
                    failed = True
            if package_root is not None:
                try:
                    package_root.close()
                except BaseException as error:
                    if isinstance(error, Exception):
                        failed = True
                    elif interruption is None:
                        interruption = error
                if package_root.closed:
                    self._package_root = None
                else:
                    failed = True
            if interruption is not None:
                raise interruption
            if failed:
                _fail(PackageConfigurationErrorCode.CONFIGURATION_CHANGED)

    def __enter__(self) -> BoundPodmanMachineConfiguration:
        if self.closed:
            _fail(PackageConfigurationErrorCode.CONFIGURATION_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"BoundPodmanMachineConfiguration(state={state!r}, <redacted>)"


def capture_bound_podman_machine_configuration(
    package_root: PureWindowsPath,
    *,
    path_api: WindowsPathTrustApi | None = None,
    file_api: WindowsFileApi | None = None,
) -> BoundPodmanMachineConfiguration:
    """Capture an existing package ``.env`` and its exact machine selector."""

    if (
        type(package_root) is not PureWindowsPath
        or not package_root.is_absolute()
        or not package_root.name
        or "\x00" in str(package_root)
        or len(str(package_root)) > 32_767
    ):
        _fail(PackageConfigurationErrorCode.CONFIGURATION_INVALID)

    root_owner: PathHierarchyTrust | None = None
    environment: HandleBoundFile | None = None
    owner: BoundPodmanMachineConfiguration | None = None
    try:
        root_owner = capture_path_hierarchy(
            str(package_root),
            purpose=PathTrustPurpose.PACKAGE_ROOT,
            api=path_api,
        )
        environment = capture_handle_bound_file(
            Path(str(package_root / ".env")),
            api=file_api,
            policy=FileCapturePolicy(
                max_bytes=_MAX_ENV_BYTES,
                require_single_link=True,
                allow_hydrated_cloud_placeholder=True,
            ),
        )
        resolved_root = PureWindowsPath(root_owner.root_snapshot.final_path)
        resolved_environment = PureWindowsPath(environment.snapshot.final_path)
        if resolved_environment.name != ".env" or _path_key(
            resolved_environment.parent
        ) != _path_key(resolved_root):
            _fail(PackageConfigurationErrorCode.CONFIGURATION_INVALID)
        contents = environment.inspect_same_handle_random_access(_read_all)
        machine = _parse_machine(contents)
        source = _snapshot_identity(environment.snapshot)
        root_identity = root_owner.evidence.root_identity
        evidence = PodmanMachineConfigurationEvidence(
            environment_source=source,
            package_root_identity=root_identity,
            configured_machine_sha256=hashlib.sha256(
                machine.encode("utf-8", errors="strict")
            ).hexdigest(),
            binding_sha256=_binding_sha256(machine, source, root_identity),
        )
        owner = BoundPodmanMachineConfiguration(
            machine=machine,
            package_root=root_owner,
            environment=environment,
            evidence=evidence,
        )
        root_owner = None
        environment = None
        return owner
    except PackageConfigurationError:
        raise
    except WindowsSecurityError:
        _fail(PackageConfigurationErrorCode.CONFIGURATION_INVALID)
    except (OSError, RuntimeError, TypeError, ValueError, UnicodeError):
        _fail(PackageConfigurationErrorCode.VERIFICATION_UNAVAILABLE)
    finally:
        failed = sys.exc_info()[0] is not None
        if failed and owner is not None:
            try:
                owner.close()
            except BaseException:
                pass
        else:
            if environment is not None:
                try:
                    environment.close()
                except BaseException:
                    pass
            if root_owner is not None:
                try:
                    root_owner.close()
                except BaseException:
                    pass


__all__ = [
    "BoundPodmanMachineConfiguration",
    "PackageConfigurationError",
    "PackageConfigurationErrorCode",
    "PodmanMachineConfigurationEvidence",
    "capture_bound_podman_machine_configuration",
]
