from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_recovery_environment_storage_native as native  # noqa: E402
from towerscout_launcher.windows_environment_replacement_native import (  # noqa: E402
    NativeEnvironmentTempNameSource,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
    NativeDirectoryFacts,
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
    PathTrustPurpose,
    capture_path_hierarchy,
)
from towerscout_launcher.windows_recovery_environment_storage import (  # noqa: E402
    RecoveryEnvironmentStorageError,
    RecoveryEnvironmentStorageErrorCode,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    EnvironmentRestoreTempCreatedRecord,
    EnvironmentRestoreTempPlanRecord,
    EnvironmentRestoreTempVerifiedRecord,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    StableFileIdentity,
)

_PACKAGE_ROOT = r"C:\Users\reviewed-user\TowerScout"
_TEMP_NAME = ".towerscout-env-0123456789abcdef0123456789abcdef.tmp"
_TEMP_PATH = rf"{_PACKAGE_ROOT}\{_TEMP_NAME}"
_USER_SID = "S-1-5-21-1000"
_SYSTEM_SID = "S-1-5-18"


def _path_identity(path: str) -> bytes:
    return hashlib.sha256(path.casefold().encode("utf-16-le")).digest()[:16]


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


def _protected_security() -> NativeSecurityFacts:
    return NativeSecurityFacts(
        owner_sid=_USER_SID,
        dacl_present=True,
        allowed_aces=(
            AccessAllowedAce(_USER_SID, 0x001F01FF, 0),
            AccessAllowedAce(_SYSTEM_SID, 0x001F01FF, 0),
        ),
        dacl_protected=True,
    )


@dataclass(frozen=True, slots=True)
class _PathHandle:
    path: str
    sequence: int


class _PathApi:
    supported = True

    def __init__(self) -> None:
        self.opened: list[_PathHandle] = []
        self.closed: list[_PathHandle] = []

    def current_user_sid(self) -> str:
        return _USER_SID

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        del follow_reparse
        handle = _PathHandle(path, len(self.opened))
        self.opened.append(handle)
        return handle

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        assert isinstance(handle, _PathHandle)
        return NativeDirectoryFacts(
            final_path=handle.path,
            volume_serial=7,
            file_id=_path_identity(handle.path),
            attributes=0x10,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, _PathHandle)
        return NativeSecurityFacts(
            owner_sid=_USER_SID,
            dacl_present=True,
            allowed_aces=(),
        )

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _PathHandle)
        self.closed.append(handle)


@dataclass(slots=True)
class _File:
    identity: StableFileIdentity
    contents: bytes
    security: NativeSecurityFacts
    final_path: str


@dataclass(slots=True)
class _Handle:
    path: str
    identity: StableFileIdentity
    delete_on_close: bool = False
    offset: int = 0


class _Api:
    def __init__(self) -> None:
        self._supported = True
        self.files: dict[str, _File] = {}
        self.create_identity = _identity(31)
        self.update_identity: StableFileIdentity | None = None
        self.reopen_identity: StableFileIdentity | None = None
        self.create_error: BaseException | None = None
        self.flush_error: BaseException | None = None
        self.write_results: list[int | BaseException] = []
        self.delete_error: BaseException | None = None
        self.close_error: BaseException | None = None
        self.events: list[str] = []

    @property
    def supported(self) -> bool:
        return self._supported

    def current_user_sid(self) -> str:
        self.events.append("sid")
        return _USER_SID

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object:
        assert path == _TEMP_PATH
        assert owner_sid == _USER_SID
        self.events.append("create")
        if self.create_error is not None:
            error = self.create_error
            self.create_error = None
            raise error
        if path in self.files:
            raise FileExistsError("private collision path")
        self.files[path] = _File(
            self.create_identity,
            b"",
            _protected_security(),
            path,
        )
        return _Handle(path, self.create_identity)

    def reopen_file_for_verification(self, path: str) -> object:
        assert path == _TEMP_PATH
        self.events.append("reopen")
        item = self.files[path]
        identity = self.reopen_identity or item.identity
        return _Handle(path, identity)

    def open_existing_file_for_update(self, path: str) -> object:
        assert path == _TEMP_PATH
        self.events.append("open-update")
        item = self.files[path]
        identity = self.update_identity or item.identity
        return _Handle(path, identity)

    def open_file_for_delete_if_exists(self, path: str) -> object | None:
        assert path == _TEMP_PATH
        self.events.append("open-delete")
        item = self.files.get(path)
        return None if item is None else _Handle(path, item.identity)

    def reopen_file_if_exists(self, path: str) -> object | None:
        assert path == _TEMP_PATH
        self.events.append("optional")
        item = self.files.get(path)
        return None if item is None else _Handle(path, item.identity)

    def query_file(self, handle: object) -> NativeFileFacts:
        assert isinstance(handle, _Handle)
        self.events.append("query")
        item = self.files[handle.path]
        return NativeFileFacts(
            final_path=item.final_path,
            volume_serial=handle.identity.volume_serial,
            file_id=handle.identity.file_id,
            attributes=0x80,
            link_count=1,
            size=len(item.contents),
            creation_time=100,
            last_write_time=200,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, _Handle)
        self.events.append("security")
        return self.files[handle.path].security

    def flush_file(self, handle: object) -> None:
        assert isinstance(handle, _Handle)
        self.events.append("flush")
        if self.flush_error is not None:
            raise self.flush_error

    def write_file(self, handle: object, contents: bytes) -> int:
        assert isinstance(handle, _Handle)
        self.events.append("write")
        result: int | BaseException = len(contents)
        if self.write_results:
            result = self.write_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        amount = min(result, len(contents))
        item = self.files[handle.path]
        item.contents = (
            item.contents[: handle.offset]
            + contents[:amount]
            + item.contents[handle.offset + amount :]
        )
        handle.offset += amount
        return amount

    def seek_file(self, handle: object, offset: int) -> None:
        assert isinstance(handle, _Handle)
        self.events.append("seek")
        handle.offset = offset

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert isinstance(handle, _Handle)
        self.events.append("read")
        item = self.files[handle.path]
        chunk = item.contents[handle.offset : handle.offset + maximum]
        handle.offset += len(chunk)
        return chunk

    def mark_file_for_deletion(self, handle: object) -> None:
        assert isinstance(handle, _Handle)
        self.events.append("delete")
        if self.delete_error is not None:
            raise self.delete_error
        handle.delete_on_close = True

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _Handle)
        self.events.append("close")
        if self.close_error is not None:
            raise self.close_error
        if handle.delete_on_close:
            self.files.pop(handle.path, None)


def _root() -> tuple[object, _PathApi]:
    api = _PathApi()
    root = capture_path_hierarchy(
        _PACKAGE_ROOT,
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=api,
    )
    return root, api


def _plan(
    package_root_identity: StableFileIdentity,
) -> EnvironmentRestoreTempPlanRecord:
    return EnvironmentRestoreTempPlanRecord(
        1,
        "1" * 64,
        package_root_identity,
        _identity(21),
        "2" * 64,
        101,
        True,
        "3" * 64,
        17,
        0x20,
        "4" * 64,
        _TEMP_NAME,
    )


def _created(
    plan: EnvironmentRestoreTempPlanRecord,
    identity: StableFileIdentity,
) -> EnvironmentRestoreTempCreatedRecord:
    return EnvironmentRestoreTempCreatedRecord(
        1,
        "5" * 64,
        plan.package_root_identity,
        plan.environment_backup_identity,
        plan.environment_ciphertext_sha256,
        plan.environment_ciphertext_size,
        plan.environment_present,
        plan.environment_sha256,
        plan.environment_size,
        plan.environment_file_attributes,
        plan.environment_security_descriptor_sha256,
        plan.temp_name,
        identity,
    )


def _created_for_contents(
    plan: EnvironmentRestoreTempPlanRecord,
    identity: StableFileIdentity,
    contents: bytes,
) -> EnvironmentRestoreTempCreatedRecord:
    return EnvironmentRestoreTempCreatedRecord(
        1,
        "5" * 64,
        plan.package_root_identity,
        plan.environment_backup_identity,
        plan.environment_ciphertext_sha256,
        plan.environment_ciphertext_size,
        True,
        hashlib.sha256(contents).hexdigest(),
        len(contents),
        plan.environment_file_attributes,
        plan.environment_security_descriptor_sha256,
        plan.temp_name,
        identity,
    )


def _verified(
    created: EnvironmentRestoreTempCreatedRecord,
) -> EnvironmentRestoreTempVerifiedRecord:
    return EnvironmentRestoreTempVerifiedRecord(
        1,
        "6" * 64,
        created.package_root_identity,
        created.environment_backup_identity,
        created.environment_ciphertext_sha256,
        created.environment_ciphertext_size,
        created.environment_present,
        created.environment_sha256,
        created.environment_size,
        created.environment_file_attributes,
        created.environment_security_descriptor_sha256,
        created.temp_name,
        created.temp_identity,
    )


def test_create_restore_temp_requires_held_package_root() -> None:
    root, _path_api = _root()
    api = _Api()
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    try:
        with pytest.raises(RecoveryEnvironmentStorageError) as failure:
            storage.create_environment_restore_temp_from_held_package_root(
                root,  # type: ignore[arg-type]
                _plan(root.evidence.root_identity),  # type: ignore[attr-defined]
            )
        assert failure.value.code is RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED
        assert api.events == []
    finally:
        root.close()  # type: ignore[attr-defined]


def test_create_restore_temp_is_zero_byte_reopened_and_identity_bound() -> None:
    root, _path_api = _root()
    api = _Api()
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    plan = _plan(root.evidence.root_identity)  # type: ignore[attr-defined]
    try:
        result = root.run_while_held(  # type: ignore[attr-defined]
            lambda: storage.create_environment_restore_temp_from_held_package_root(
                root,  # type: ignore[arg-type]
                plan,
            )
        )
        assert result == api.create_identity
        assert api.files[_TEMP_PATH].contents == b""
        assert api.events.count("create") == 1
        assert api.events.count("flush") == 1
        assert api.events.count("reopen") == 1
        assert "delete" not in api.events
    finally:
        root.close()  # type: ignore[attr-defined]


def test_create_restore_temp_reconciles_only_exact_empty_planned_orphan() -> None:
    root, _path_api = _root()
    api = _Api()
    old_identity = _identity(30)
    api.files[_TEMP_PATH] = _File(
        old_identity,
        b"",
        _protected_security(),
        _TEMP_PATH,
    )
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    plan = _plan(root.evidence.root_identity)  # type: ignore[attr-defined]
    try:
        result = root.run_while_held(  # type: ignore[attr-defined]
            lambda: storage.create_environment_restore_temp_from_held_package_root(
                root,  # type: ignore[arg-type]
                plan,
            )
        )
        assert result == api.create_identity
        assert result != old_identity
        assert api.events.count("create") == 2
        assert api.events.count("delete") == 1
        assert api.files[_TEMP_PATH].identity == api.create_identity
    finally:
        root.close()  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("contents", "security"),
    [
        (b"not-empty", _protected_security()),
        (
            b"",
            NativeSecurityFacts(
                owner_sid=_USER_SID,
                dacl_present=True,
                allowed_aces=(AccessAllowedAce("S-1-5-32-545", 0x001F01FF, 0),),
                dacl_protected=False,
            ),
        ),
    ],
)
def test_create_restore_temp_preserves_ambiguous_collision(
    contents: bytes,
    security: NativeSecurityFacts,
) -> None:
    root, _path_api = _root()
    api = _Api()
    api.files[_TEMP_PATH] = _File(_identity(30), contents, security, _TEMP_PATH)
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    plan = _plan(root.evidence.root_identity)  # type: ignore[attr-defined]
    try:
        with pytest.raises(RecoveryEnvironmentStorageError) as failure:
            root.run_while_held(  # type: ignore[attr-defined]
                lambda: storage.create_environment_restore_temp_from_held_package_root(
                    root,  # type: ignore[arg-type]
                    plan,
                )
            )
        assert failure.value.code is RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED
        assert api.files[_TEMP_PATH].contents == contents
        assert "delete" not in api.events
        assert _TEMP_PATH not in str(failure.value)
    finally:
        root.close()  # type: ignore[attr-defined]


def test_create_restore_temp_rejects_reopen_identity_drift() -> None:
    root, _path_api = _root()
    api = _Api()
    api.reopen_identity = _identity(32)
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    plan = _plan(root.evidence.root_identity)  # type: ignore[attr-defined]
    try:
        with pytest.raises(RecoveryEnvironmentStorageError) as failure:
            root.run_while_held(  # type: ignore[attr-defined]
                lambda: storage.create_environment_restore_temp_from_held_package_root(
                    root,  # type: ignore[arg-type]
                    plan,
                )
            )
        assert failure.value.code is RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED
        assert _TEMP_PATH in api.files
    finally:
        root.close()  # type: ignore[attr-defined]


def test_verify_restore_temp_requires_exact_recorded_identity() -> None:
    root, _path_api = _root()
    api = _Api()
    plan = _plan(root.evidence.root_identity)  # type: ignore[attr-defined]
    api.files[_TEMP_PATH] = _File(
        api.create_identity,
        b"",
        _protected_security(),
        _TEMP_PATH,
    )
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    try:
        verified = root.run_while_held(  # type: ignore[attr-defined]
            lambda: storage.verify_environment_restore_temp_from_held_package_root(
                root,  # type: ignore[arg-type]
                _created(plan, api.create_identity),
            )
        )
        assert verified == api.create_identity

        with pytest.raises(RecoveryEnvironmentStorageError) as failure:
            root.run_while_held(  # type: ignore[attr-defined]
                lambda: storage.verify_environment_restore_temp_from_held_package_root(
                    root,  # type: ignore[arg-type]
                    _created(plan, _identity(32)),
                )
            )
        assert failure.value.code is RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED
    finally:
        root.close()  # type: ignore[attr-defined]


def test_write_restore_temp_flushes_reads_and_reopens_exact_contents() -> None:
    root, _path_api = _root()
    api = _Api()
    contents = b"GOOGLE_API_KEY=restored\n"
    plan = _plan(root.evidence.root_identity)  # type: ignore[attr-defined]
    created = _created_for_contents(plan, api.create_identity, contents)
    api.files[_TEMP_PATH] = _File(
        api.create_identity,
        b"",
        _protected_security(),
        _TEMP_PATH,
    )
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    try:
        identity = root.run_while_held(  # type: ignore[attr-defined]
            lambda: storage.write_and_verify_environment_restore_temp_from_held_package_root(
                root,  # type: ignore[arg-type]
                created,
                contents,
            )
        )
        assert identity == api.create_identity
        assert api.files[_TEMP_PATH].contents == contents
        assert api.events.count("open-update") == 1
        assert api.events.count("write") == 1
        assert api.events.count("flush") == 1
        assert api.events.count("reopen") == 1
        assert api.events.count("read") == 2
        assert "delete" not in api.events

        assert (
            root.run_while_held(  # type: ignore[attr-defined]
                lambda: storage.verify_written_environment_restore_temp_from_held_package_root(
                    root,  # type: ignore[arg-type]
                    _verified(created),
                )
            )
            == api.create_identity
        )
        assert api.events.count("write") == 1
    finally:
        root.close()  # type: ignore[attr-defined]


def test_write_restore_temp_reverifies_exact_crash_residue_without_rewrite() -> None:
    root, _path_api = _root()
    api = _Api()
    contents = b"DEFAULT_MAP_PROVIDER=azure\n"
    plan = _plan(root.evidence.root_identity)  # type: ignore[attr-defined]
    created = _created_for_contents(plan, api.create_identity, contents)
    api.files[_TEMP_PATH] = _File(
        api.create_identity,
        contents,
        _protected_security(),
        _TEMP_PATH,
    )
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    try:
        assert (
            root.run_while_held(  # type: ignore[attr-defined]
                lambda: storage.write_and_verify_environment_restore_temp_from_held_package_root(
                    root,  # type: ignore[arg-type]
                    created,
                    contents,
                )
            )
            == api.create_identity
        )
        assert "write" not in api.events
        assert api.events.count("read") == 3
    finally:
        root.close()  # type: ignore[attr-defined]


@pytest.mark.parametrize("existing", [b"partial", b"X" * 24])
def test_write_restore_temp_preserves_partial_or_wrong_complete_content(
    existing: bytes,
) -> None:
    root, _path_api = _root()
    api = _Api()
    contents = b"GOOGLE_API_KEY=restored\n"
    assert len(existing) != 0
    plan = _plan(root.evidence.root_identity)  # type: ignore[attr-defined]
    created = _created_for_contents(plan, api.create_identity, contents)
    api.files[_TEMP_PATH] = _File(
        api.create_identity,
        existing,
        _protected_security(),
        _TEMP_PATH,
    )
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    try:
        with pytest.raises(RecoveryEnvironmentStorageError) as failure:
            root.run_while_held(  # type: ignore[attr-defined]
                lambda: storage.write_and_verify_environment_restore_temp_from_held_package_root(
                    root,  # type: ignore[arg-type]
                    created,
                    contents,
                )
            )
        assert failure.value.code is RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED
        assert api.files[_TEMP_PATH].contents == existing
        assert "write" not in api.events
        assert "delete" not in api.events
    finally:
        root.close()  # type: ignore[attr-defined]


def test_write_restore_temp_preserves_partial_file_after_write_failure() -> None:
    root, _path_api = _root()
    api = _Api()
    contents = b"AZURE_MAPS_SUBSCRIPTION_KEY=restored\n"
    plan = _plan(root.evidence.root_identity)  # type: ignore[attr-defined]
    created = _created_for_contents(plan, api.create_identity, contents)
    api.files[_TEMP_PATH] = _File(
        api.create_identity,
        b"",
        _protected_security(),
        _TEMP_PATH,
    )
    api.write_results = [7, OSError("private write failure")]
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    try:
        with pytest.raises(RecoveryEnvironmentStorageError) as failure:
            root.run_while_held(  # type: ignore[attr-defined]
                lambda: storage.write_and_verify_environment_restore_temp_from_held_package_root(
                    root,  # type: ignore[arg-type]
                    created,
                    contents,
                )
            )
        assert failure.value.code is RecoveryEnvironmentStorageErrorCode.WRITE_FAILED
        assert api.files[_TEMP_PATH].contents == contents[:7]
        assert "delete" not in api.events
        assert _TEMP_PATH not in str(failure.value)
    finally:
        root.close()  # type: ignore[attr-defined]


def test_write_restore_temp_preserves_complete_file_after_flush_failure() -> None:
    root, _path_api = _root()
    api = _Api()
    contents = b"FLASK_SECRET_KEY=restored\n"
    plan = _plan(root.evidence.root_identity)  # type: ignore[attr-defined]
    created = _created_for_contents(plan, api.create_identity, contents)
    api.files[_TEMP_PATH] = _File(
        api.create_identity,
        b"",
        _protected_security(),
        _TEMP_PATH,
    )
    api.flush_error = OSError("private flush failure")
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    try:
        with pytest.raises(RecoveryEnvironmentStorageError) as failure:
            root.run_while_held(  # type: ignore[attr-defined]
                lambda: storage.write_and_verify_environment_restore_temp_from_held_package_root(
                    root,  # type: ignore[arg-type]
                    created,
                    contents,
                )
            )
        assert failure.value.code is RecoveryEnvironmentStorageErrorCode.WRITE_FAILED
        assert api.files[_TEMP_PATH].contents == contents
        assert "delete" not in api.events
    finally:
        root.close()  # type: ignore[attr-defined]


def test_write_restore_temp_rejects_update_and_reopen_identity_drift() -> None:
    root, _path_api = _root()
    api = _Api()
    contents = b"GOOGLE_API_KEY=restored\n"
    plan = _plan(root.evidence.root_identity)  # type: ignore[attr-defined]
    created = _created_for_contents(plan, api.create_identity, contents)
    api.files[_TEMP_PATH] = _File(
        api.create_identity,
        b"",
        _protected_security(),
        _TEMP_PATH,
    )
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    try:
        api.update_identity = _identity(32)
        with pytest.raises(RecoveryEnvironmentStorageError) as update_failure:
            root.run_while_held(  # type: ignore[attr-defined]
                lambda: storage.write_and_verify_environment_restore_temp_from_held_package_root(
                    root,  # type: ignore[arg-type]
                    created,
                    contents,
                )
            )
        assert (
            update_failure.value.code
            is RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED
        )
        assert api.files[_TEMP_PATH].contents == b""

        api.update_identity = None
        api.reopen_identity = _identity(33)
        with pytest.raises(RecoveryEnvironmentStorageError) as reopen_failure:
            root.run_while_held(  # type: ignore[attr-defined]
                lambda: storage.write_and_verify_environment_restore_temp_from_held_package_root(
                    root,  # type: ignore[arg-type]
                    created,
                    contents,
                )
            )
        assert (
            reopen_failure.value.code
            is RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED
        )
        assert api.files[_TEMP_PATH].contents == contents
        assert "delete" not in api.events
    finally:
        root.close()  # type: ignore[attr-defined]


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file APIs")
def test_native_restore_temp_round_trip_under_held_package_root(tmp_path: Path) -> None:
    api = native.NativeWindowsRecoveryEnvironmentTempApi()
    native_path_api = NativeWindowsPathTrustApi()

    class _NativeHandlePathApi:
        supported = True

        def current_user_sid(self) -> str:
            return native_path_api.current_user_sid()

        def open_directory(self, path: str, *, follow_reparse: bool) -> object:
            return native_path_api.open_directory(path, follow_reparse=follow_reparse)

        def query_directory(self, handle: object) -> NativeDirectoryFacts:
            return native_path_api.query_directory(handle)

        def query_security(self, handle: object) -> NativeSecurityFacts:
            del handle
            return NativeSecurityFacts(
                owner_sid=self.current_user_sid(),
                dacl_present=True,
                allowed_aces=(),
            )

        def close_handle(self, handle: object) -> None:
            native_path_api.close_handle(handle)

    root = capture_path_hierarchy(
        str(tmp_path),
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=_NativeHandlePathApi(),
    )
    temp_name = NativeEnvironmentTempNameSource().new_environment_temp_name()
    plan = EnvironmentRestoreTempPlanRecord(
        1,
        "1" * 64,
        root.evidence.root_identity,
        _identity(21),
        "2" * 64,
        101,
        True,
        "3" * 64,
        17,
        0x20,
        "4" * 64,
        temp_name,
    )
    storage = native.NativeWindowsEnvironmentRestoreTempStorage(api=api)
    path = tmp_path / temp_name
    try:
        identity = root.run_while_held(
            lambda: storage.create_environment_restore_temp_from_held_package_root(
                root,
                plan,
            )
        )
        assert path.read_bytes() == b""
        assert (
            root.run_while_held(
                lambda: storage.verify_environment_restore_temp_from_held_package_root(
                    root,
                    _created(plan, identity),
                )
            )
            == identity
        )
        contents = b"GOOGLE_API_KEY=restored\n"
        created = _created_for_contents(plan, identity, contents)
        assert (
            root.run_while_held(
                lambda: storage.write_and_verify_environment_restore_temp_from_held_package_root(
                    root,
                    created,
                    contents,
                )
            )
            == identity
        )
        assert path.read_bytes() == contents
        assert (
            root.run_while_held(
                lambda: storage.verify_written_environment_restore_temp_from_held_package_root(
                    root,
                    _verified(created),
                )
            )
            == identity
        )
    finally:
        root.close()
        path.unlink(missing_ok=True)
