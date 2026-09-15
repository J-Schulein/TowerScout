"""Handle-bound proof that a package ``.env`` leaf is securely absent.

This Gate-A source layer retains the trusted package-root hierarchy and
rechecks absence through a no-follow native open. It performs no file creation,
replacement, cleanup, recovery, or runtime mutation.
"""

from __future__ import annotations

import hashlib
import ntpath
import re
import struct
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import NoReturn, Protocol

from .target_contracts import ABSENT_FILE_SHA256
from .windows_path_trust import (
    NativeWindowsPathTrustApi,
    PathHierarchyTrust,
    PathTrustPurpose,
    WindowsPathTrustApi,
    capture_path_hierarchy,
)
from .windows_security import (
    NativeWindowsFileApi,
    StableFileIdentity,
    WindowsSecurityError,
)

_SCHEMA_VERSION = 1
_ENVIRONMENT_NAME = ".env"
_BINDING_DOMAIN = b"TowerScout.EnvironmentAbsence.v1"
_MAX_PATH_CHARACTERS = 32_768
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EnvironmentPresenceApi(Protocol):
    """Injectable boundary for an exact no-follow leaf presence probe."""

    @property
    def supported(self) -> bool: ...

    def open_file_if_exists(self, path: str) -> object | None: ...

    def close_handle(self, handle: object) -> None: ...


class EnvironmentAbsenceErrorCode(str, Enum):
    INPUT_INVALID = "environment_absence_input_invalid"
    VERIFICATION_UNAVAILABLE = "environment_absence_verification_unavailable"
    ENVIRONMENT_PRESENT = "environment_present"
    ENVIRONMENT_CHANGED = "environment_absence_changed"


class EnvironmentAbsenceError(RuntimeError):
    """Sanitized failure at the package-environment absence boundary."""

    _MESSAGES = {
        EnvironmentAbsenceErrorCode.INPUT_INVALID: (
            "The package environment absence request is invalid."
        ),
        EnvironmentAbsenceErrorCode.VERIFICATION_UNAVAILABLE: (
            "The package environment absence could not be verified safely."
        ),
        EnvironmentAbsenceErrorCode.ENVIRONMENT_PRESENT: (
            "The package environment file is present."
        ),
        EnvironmentAbsenceErrorCode.ENVIRONMENT_CHANGED: (
            "The package environment absence changed during verification."
        ),
    }

    def __init__(self, code: EnvironmentAbsenceErrorCode) -> None:
        if type(code) is not EnvironmentAbsenceErrorCode:
            raise ValueError("Unknown environment absence error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"EnvironmentAbsenceError(code={self.code.value!r})"


def _fail(code: EnvironmentAbsenceErrorCode) -> NoReturn:
    raise EnvironmentAbsenceError(code)


def _binding_sha256(identity: StableFileIdentity) -> str:
    digest = hashlib.sha256()
    for value in (
        _BINDING_DOMAIN,
        identity.volume_serial.to_bytes(8, "big"),
        identity.file_id,
        _ENVIRONMENT_NAME.encode("ascii"),
        ABSENT_FILE_SHA256.encode("ascii"),
    ):
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _path_key(path: PureWindowsPath) -> str:
    value = str(path)
    if value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentAbsenceEvidence:
    """Opaque binding of one absent ``.env`` to one held package root."""

    schema_version: int
    package_root_identity: StableFileIdentity = field(repr=False)
    environment_sha256: str = field(repr=False)
    binding_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or type(self.package_root_identity) is not StableFileIdentity
            or self.environment_sha256 != ABSENT_FILE_SHA256
            or type(self.binding_sha256) is not str
            or not _SHA256.fullmatch(self.binding_sha256)
            or self.binding_sha256 != _binding_sha256(self.package_root_identity)
        ):
            raise ValueError("Environment absence evidence is invalid.")

    def __repr__(self) -> str:
        return (
            "EnvironmentAbsenceEvidence("
            f"schema_version={self.schema_version}, <redacted>)"
        )


def _assert_api_supported(api: EnvironmentPresenceApi) -> None:
    try:
        supported = api.supported is True
    except (OSError, RuntimeError, TypeError, ValueError):
        supported = False
    if not supported:
        _fail(EnvironmentAbsenceErrorCode.VERIFICATION_UNAVAILABLE)


def _assert_environment_absent(api: EnvironmentPresenceApi, path: str) -> None:
    _assert_api_supported(api)
    handle: object | None = None
    try:
        handle = api.open_file_if_exists(path)
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail(EnvironmentAbsenceErrorCode.VERIFICATION_UNAVAILABLE)
    if handle is None:
        return
    try:
        api.close_handle(handle)
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail(EnvironmentAbsenceErrorCode.VERIFICATION_UNAVAILABLE)
    _fail(EnvironmentAbsenceErrorCode.ENVIRONMENT_PRESENT)


class BoundEnvironmentAbsence:
    """Own the package-root handles behind one recheckable absence proof."""

    __slots__ = (
        "_active_owner",
        "_api",
        "_environment_path",
        "_evidence",
        "_lifetime_lock",
        "_package_root",
    )

    def __init__(
        self,
        *,
        api: EnvironmentPresenceApi,
        environment_path: str,
        package_root: PathHierarchyTrust,
        evidence: EnvironmentAbsenceEvidence,
    ) -> None:
        if (
            type(package_root) is not PathHierarchyTrust
            or package_root.closed
            or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
            or type(environment_path) is not str
            or not environment_path
            or "\x00" in environment_path
            or len(environment_path) > _MAX_PATH_CHARACTERS
            or type(evidence) is not EnvironmentAbsenceEvidence
            or package_root.evidence.root_identity != evidence.package_root_identity
        ):
            raise ValueError("Bound environment absence is invalid.")
        candidate_path = PureWindowsPath(environment_path)
        resolved_root = PureWindowsPath(package_root.root_snapshot.final_path)
        if candidate_path.name != _ENVIRONMENT_NAME or _path_key(
            candidate_path.parent
        ) != _path_key(resolved_root):
            raise ValueError("Bound environment absence is invalid.")
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None
        self._api = api
        self._environment_path = environment_path
        self._package_root: PathHierarchyTrust | None = package_root
        self._evidence = evidence

    @property
    def evidence(self) -> EnvironmentAbsenceEvidence:
        return self._evidence

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            return self._package_root is None

    def assert_unchanged(self) -> EnvironmentAbsenceEvidence:
        self._lifetime_lock.acquire()
        if self._active_owner is not None:
            self._lifetime_lock.release()
            _fail(EnvironmentAbsenceErrorCode.ENVIRONMENT_CHANGED)
        package_root = self._package_root
        if package_root is None or package_root.closed:
            self._lifetime_lock.release()
            _fail(EnvironmentAbsenceErrorCode.ENVIRONMENT_CHANGED)
        self._active_owner = threading.get_ident()
        try:
            try:
                package_root.run_while_held(
                    lambda: _assert_environment_absent(
                        self._api, self._environment_path
                    )
                )
            except EnvironmentAbsenceError:
                raise
            except WindowsSecurityError:
                _fail(EnvironmentAbsenceErrorCode.ENVIRONMENT_CHANGED)
            return self._evidence
        finally:
            self._active_owner = None
            self._lifetime_lock.release()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(EnvironmentAbsenceErrorCode.ENVIRONMENT_CHANGED)
            package_root = self._package_root
            self._package_root = None
            if package_root is None:
                return
            try:
                package_root.close()
            except WindowsSecurityError:
                _fail(EnvironmentAbsenceErrorCode.ENVIRONMENT_CHANGED)

    def __enter__(self) -> "BoundEnvironmentAbsence":
        if self.closed:
            _fail(EnvironmentAbsenceErrorCode.ENVIRONMENT_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"BoundEnvironmentAbsence(state={state!r}, <redacted>)"


def capture_bound_environment_absence(
    package_root: PureWindowsPath,
    *,
    path_api: WindowsPathTrustApi | None = None,
    presence_api: EnvironmentPresenceApi | None = None,
) -> BoundEnvironmentAbsence:
    """Capture and retain proof that one package-root ``.env`` is absent."""

    if (
        type(package_root) is not PureWindowsPath
        or not package_root.is_absolute()
        or not package_root.name
        or "\x00" in str(package_root)
        or len(str(package_root)) > _MAX_PATH_CHARACTERS
    ):
        _fail(EnvironmentAbsenceErrorCode.INPUT_INVALID)

    selected_path_api = (
        path_api if path_api is not None else NativeWindowsPathTrustApi()
    )
    selected_presence_api = (
        presence_api if presence_api is not None else NativeWindowsFileApi()
    )
    root_owner: PathHierarchyTrust | None = None
    owner: BoundEnvironmentAbsence | None = None
    try:
        root_owner = capture_path_hierarchy(
            str(package_root),
            purpose=PathTrustPurpose.PACKAGE_ROOT,
            api=selected_path_api,
        )
        resolved_root = PureWindowsPath(root_owner.root_snapshot.final_path)
        environment_path = str(resolved_root / _ENVIRONMENT_NAME)
        if (
            not resolved_root.is_absolute()
            or not resolved_root.name
            or len(environment_path) > _MAX_PATH_CHARACTERS
        ):
            _fail(EnvironmentAbsenceErrorCode.VERIFICATION_UNAVAILABLE)
        root_owner.run_while_held(
            lambda: _assert_environment_absent(selected_presence_api, environment_path)
        )
        root_identity = root_owner.evidence.root_identity
        evidence = EnvironmentAbsenceEvidence(
            schema_version=_SCHEMA_VERSION,
            package_root_identity=root_identity,
            environment_sha256=ABSENT_FILE_SHA256,
            binding_sha256=_binding_sha256(root_identity),
        )
        owner = BoundEnvironmentAbsence(
            api=selected_presence_api,
            environment_path=environment_path,
            package_root=root_owner,
            evidence=evidence,
        )
        root_owner = None
        return owner
    except EnvironmentAbsenceError:
        raise
    except WindowsSecurityError:
        _fail(EnvironmentAbsenceErrorCode.VERIFICATION_UNAVAILABLE)
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail(EnvironmentAbsenceErrorCode.VERIFICATION_UNAVAILABLE)
    finally:
        if owner is None and root_owner is not None:
            try:
                root_owner.close()
            except BaseException:
                pass


__all__ = [
    "BoundEnvironmentAbsence",
    "EnvironmentAbsenceError",
    "EnvironmentAbsenceErrorCode",
    "EnvironmentAbsenceEvidence",
    "EnvironmentPresenceApi",
    "capture_bound_environment_absence",
]
