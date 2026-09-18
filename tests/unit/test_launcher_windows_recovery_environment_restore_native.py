from __future__ import annotations

import hashlib
import ntpath
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_recovery_environment_restore_native as native  # noqa: E402
from towerscout_launcher.windows_environment_replacement_native import (  # noqa: E402
    NativeWindowsEnvironmentReplacementApi,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
    NativeDirectoryFacts,
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
    PathTrustPurpose,
    capture_path_hierarchy,
)
from towerscout_launcher.windows_recovery_environment_restore import (  # noqa: E402
    EnvironmentDestinationObservation,
    EnvironmentRestoreAuthority,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    StableFileIdentity,
)

_ROOT = r"C:\Users\reviewed-user\TowerScout"
_DESTINATION = rf"{_ROOT}\.env"
_TEMP_NAME = ".towerscout-env-0123456789abcdef0123456789abcdef.tmp"
_TEMP = rf"{_ROOT}\{_TEMP_NAME}"
_USER_SID = "S-1-5-21-1000"


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


class _PathApi:
    supported = True

    def __init__(self) -> None:
        self.changed = False

    def current_user_sid(self) -> str:
        return _USER_SID

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        del follow_reparse
        return path

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        assert isinstance(handle, str)
        identity = _identity(99 if self.changed else 7)
        return NativeDirectoryFacts(
            handle,
            identity.volume_serial,
            identity.file_id,
            0x10,
            3,
            1,
            0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, str)
        return NativeSecurityFacts(_USER_SID, True, ())

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, str)


@dataclass(slots=True)
class _File:
    identity: StableFileIdentity
    contents: bytes
    attributes: int
    descriptor: str
    restricted: bool = False


@dataclass(slots=True)
class _Handle:
    path: str
    identity: StableFileIdentity
    offset: int = 0


class _Api:
    supported = True

    def __init__(self) -> None:
        self.files: dict[str, _File] = {}
        self.events: list[str] = []
        self.replace_error: Exception | None = None
        self.replace_error_after_apply = False
        self.delete_error: Exception | None = None
        self.delete_error_after_apply = False
        self.corrupt_after_replace = False
        self.substitute_on_delete_open = False

    def current_user_sid(self) -> str:
        return _USER_SID

    def open_file_if_exists(self, path: str) -> object | None:
        self.events.append(f"open:{ntpath.basename(path)}")
        item = self.files.get(path)
        return None if item is None else _Handle(path, item.identity)

    def open_file_for_delete_if_exists(self, path: str) -> object | None:
        self.events.append(f"delete-open:{ntpath.basename(path)}")
        if self.substitute_on_delete_open and path in self.files:
            self.files[path].identity = _identity(99)
            self.files[path].contents = b"substituted"
        item = self.files.get(path)
        return None if item is None else _Handle(path, item.identity)

    def _item(self, handle: object) -> _File:
        assert isinstance(handle, _Handle)
        item = self.files[handle.path]
        if item.identity != handle.identity:
            raise OSError("private identity")
        return item

    def query_file(self, handle: object) -> NativeFileFacts:
        assert isinstance(handle, _Handle)
        item = self._item(handle)
        return NativeFileFacts(
            handle.path,
            item.identity.volume_serial,
            item.identity.file_id,
            item.attributes,
            1,
            len(item.contents),
            100,
            200,
            3,
            1,
            0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        item = self._item(handle)
        aces = (
            (
                AccessAllowedAce(_USER_SID, 0x001F01FF, 0),
                AccessAllowedAce("S-1-5-18", 0x001F01FF, 0),
            )
            if item.restricted
            else ()
        )
        return NativeSecurityFacts(
            _USER_SID,
            True,
            aces,
            item.restricted,
            item.descriptor,
        )

    def seek_file(self, handle: object, offset: int) -> None:
        assert isinstance(handle, _Handle)
        handle.offset = offset

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert isinstance(handle, _Handle)
        item = self._item(handle)
        chunk = item.contents[handle.offset : handle.offset + maximum]
        handle.offset += len(chunk)
        return chunk

    def mark_file_for_deletion(self, handle: object) -> None:
        assert isinstance(handle, _Handle)
        self._item(handle)
        self.events.append("delete")
        if self.delete_error is not None and not self.delete_error_after_apply:
            raise self.delete_error
        self.files.pop(handle.path)
        if self.delete_error is not None:
            raise self.delete_error

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _Handle)

    def replace_existing_file(self, destination: str, source: str) -> None:
        self.events.append("replace")
        if self.replace_error is not None and not self.replace_error_after_apply:
            raise self.replace_error
        prior = self.files[destination]
        replacement = self.files.pop(source)
        self.files[destination] = _File(
            replacement.identity,
            b"corrupt" if self.corrupt_after_replace else replacement.contents,
            prior.attributes,
            prior.descriptor,
        )
        if self.replace_error is not None:
            raise self.replace_error


def _root() -> tuple[object, _PathApi]:
    api = _PathApi()
    root = capture_path_hierarchy(
        _ROOT,
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=api,
    )
    return root, api


def _authority(
    *,
    original_present: bool = True,
) -> native.EnvironmentRestoreStorageAuthority:
    original = b"original environment"
    candidate = b"candidate environment"
    restore = EnvironmentRestoreAuthority(
        1,
        _identity(7),
        original_present,
        _identity(8) if original_present else None,
        hashlib.sha256(original).hexdigest() if original_present else None,
        len(original) if original_present else None,
        0x20 if original_present else None,
        "b" * 64 if original_present else None,
        hashlib.sha256(candidate).hexdigest(),
        len(candidate),
        _identity(9),
        0x20 if original_present else 0x80,
        "b" * 64 if original_present else "d" * 64,
        _identity(10) if original_present else None,
    )
    return native.EnvironmentRestoreStorageAuthority(
        1,
        restore,
        _TEMP_NAME if original_present else None,
    )


def _arrange(
    api: _Api,
    authority: native.EnvironmentRestoreStorageAuthority,
) -> None:
    restore = authority.restore
    assert restore.candidate_identity is not None
    assert restore.candidate_file_attributes is not None
    assert restore.candidate_security_descriptor_sha256 is not None
    api.files[_DESTINATION] = _File(
        restore.candidate_identity,
        b"candidate environment",
        restore.candidate_file_attributes,
        restore.candidate_security_descriptor_sha256,
    )
    if restore.original_present:
        assert restore.restore_temp_identity is not None
        api.files[_TEMP] = _File(
            restore.restore_temp_identity,
            b"original environment",
            0x80,
            "f" * 64,
            True,
        )


def _restore(
    root: object,
    authority: native.EnvironmentRestoreStorageAuthority,
    api: _Api,
) -> EnvironmentDestinationObservation:
    storage = native.NativeWindowsEnvironmentRestoreStorage(api=api)
    return storage.restore_environment_from_held_package_root(  # type: ignore[arg-type]
        root,
        authority,
    )


def test_present_original_replaces_only_candidate_with_verified_restore_temp() -> None:
    root, _path_api = _root()
    authority = _authority()
    api = _Api()
    _arrange(api, authority)
    try:
        result = _restore(root, authority, api)
    finally:
        root.close()  # type: ignore[attr-defined]

    assert result.identity == authority.restore.restore_temp_identity
    assert result.sha256 == authority.restore.original_sha256
    assert result.file_attributes == authority.restore.original_file_attributes
    assert result.security_descriptor_sha256 == (
        authority.restore.original_security_descriptor_sha256
    )
    assert _TEMP not in api.files
    assert api.events.count("replace") == 1


@pytest.mark.parametrize("present", [True, False])
def test_environment_observation_is_read_only_under_held_package_root(
    present: bool,
) -> None:
    root, _path_api = _root()
    api = _Api()
    authority = _authority()
    if present:
        restore = authority.restore
        assert restore.original_identity is not None
        assert restore.original_sha256 is not None
        assert restore.original_file_attributes is not None
        assert restore.original_security_descriptor_sha256 is not None
        api.files[_DESTINATION] = _File(
            restore.original_identity,
            b"original environment",
            restore.original_file_attributes,
            restore.original_security_descriptor_sha256,
        )
    storage = native.NativeWindowsEnvironmentRestoreStorage(api=api)
    try:
        observed = root.run_while_held(
            lambda: storage.observe_environment_while_package_root_held(
                root,
                _identity(7),
            )
        )
    finally:
        root.close()

    assert observed.present is present
    assert "replace" not in api.events
    assert not any(item.startswith("delete-open:") for item in api.events)
    if present:
        assert observed.identity == authority.restore.original_identity
        assert observed.sha256 == authority.restore.original_sha256


def test_absent_original_deletes_only_exact_candidate_by_held_handle() -> None:
    root, _path_api = _root()
    authority = _authority(original_present=False)
    api = _Api()
    _arrange(api, authority)
    try:
        result = _restore(root, authority, api)
    finally:
        root.close()  # type: ignore[attr-defined]

    assert result == EnvironmentDestinationObservation(False)
    assert _DESTINATION not in api.files
    assert api.events.count("delete") == 1
    assert "replace" not in api.events


@pytest.mark.parametrize("original_present", (True, False))
def test_completed_restore_is_idempotent(original_present: bool) -> None:
    root, _path_api = _root()
    authority = _authority(original_present=original_present)
    api = _Api()
    restore = authority.restore
    if original_present:
        assert restore.restore_temp_identity is not None
        assert restore.original_file_attributes is not None
        assert restore.original_security_descriptor_sha256 is not None
        api.files[_DESTINATION] = _File(
            restore.restore_temp_identity,
            b"original environment",
            restore.original_file_attributes,
            restore.original_security_descriptor_sha256,
        )
    try:
        result = _restore(root, authority, api)
    finally:
        root.close()  # type: ignore[attr-defined]

    assert result.present is original_present
    assert "replace" not in api.events
    assert "delete" not in api.events


@pytest.mark.parametrize("original_present", (True, False))
def test_api_error_after_apply_reconciles_as_success(original_present: bool) -> None:
    root, _path_api = _root()
    authority = _authority(original_present=original_present)
    api = _Api()
    _arrange(api, authority)
    if original_present:
        api.replace_error = OSError("private")
        api.replace_error_after_apply = True
    else:
        api.delete_error = OSError("private")
        api.delete_error_after_apply = True
    try:
        result = _restore(root, authority, api)
    finally:
        root.close()  # type: ignore[attr-defined]

    assert result.present is original_present


@pytest.mark.parametrize("original_present", (True, False))
def test_api_error_with_unchanged_state_is_retryable_failure(
    original_present: bool,
) -> None:
    root, _path_api = _root()
    authority = _authority(original_present=original_present)
    api = _Api()
    _arrange(api, authority)
    if original_present:
        api.replace_error = OSError("private")
    else:
        api.delete_error = OSError("private")
    try:
        with pytest.raises(native.EnvironmentRestoreStorageError) as failure:
            _restore(root, authority, api)
    finally:
        root.close()  # type: ignore[attr-defined]

    assert failure.value.code is native.EnvironmentRestoreStorageErrorCode.APPLY_FAILED
    assert "private" not in str(failure.value)


def test_candidate_or_restore_temp_drift_is_preserved_without_mutation() -> None:
    for drift_path in (_DESTINATION, _TEMP):
        root, _path_api = _root()
        authority = _authority()
        api = _Api()
        _arrange(api, authority)
        api.files[drift_path].contents = b"third state"
        try:
            with pytest.raises(native.EnvironmentRestoreStorageError) as failure:
                _restore(root, authority, api)
        finally:
            root.close()  # type: ignore[attr-defined]

        assert failure.value.code is (
            native.EnvironmentRestoreStorageErrorCode.STATE_AMBIGUOUS
        )
        assert "replace" not in api.events
        assert "delete" not in api.events
        assert drift_path in api.files


def test_unsafe_restore_temp_security_is_preserved_without_replace() -> None:
    root, _path_api = _root()
    authority = _authority()
    api = _Api()
    _arrange(api, authority)
    api.files[_TEMP].restricted = False
    try:
        with pytest.raises(native.EnvironmentRestoreStorageError) as failure:
            _restore(root, authority, api)
    finally:
        root.close()  # type: ignore[attr-defined]

    assert failure.value.code is native.EnvironmentRestoreStorageErrorCode.VERIFY_FAILED
    assert "replace" not in api.events
    assert _TEMP in api.files


def test_corrupt_post_replace_state_is_preserved_as_ambiguous() -> None:
    root, _path_api = _root()
    authority = _authority()
    api = _Api()
    _arrange(api, authority)
    api.corrupt_after_replace = True
    try:
        with pytest.raises(native.EnvironmentRestoreStorageError) as failure:
            _restore(root, authority, api)
    finally:
        root.close()  # type: ignore[attr-defined]

    assert failure.value.code is (
        native.EnvironmentRestoreStorageErrorCode.STATE_AMBIGUOUS
    )
    assert _TEMP not in api.files
    assert _DESTINATION in api.files


def test_substituted_delete_identity_is_preserved_without_deletion() -> None:
    root, _path_api = _root()
    authority = _authority(original_present=False)
    api = _Api()
    _arrange(api, authority)
    api.substitute_on_delete_open = True
    try:
        with pytest.raises(native.EnvironmentRestoreStorageError) as failure:
            _restore(root, authority, api)
    finally:
        root.close()  # type: ignore[attr-defined]

    assert failure.value.code is (
        native.EnvironmentRestoreStorageErrorCode.STATE_AMBIGUOUS
    )
    assert _DESTINATION in api.files
    assert api.files[_DESTINATION].contents == b"substituted"
    assert "delete" not in api.events


def test_package_root_change_and_unsupported_platform_fail_closed() -> None:
    root, path_api = _root()
    authority = _authority()
    api = _Api()
    _arrange(api, authority)
    try:
        path_api.changed = True
        with pytest.raises(native.EnvironmentRestoreStorageError) as changed:
            _restore(root, authority, api)
        assert changed.value.code is (
            native.EnvironmentRestoreStorageErrorCode.VERIFY_FAILED
        )
        path_api.changed = False
        api.supported = False
        with pytest.raises(native.EnvironmentRestoreStorageError) as unsupported:
            _restore(root, authority, api)
        assert unsupported.value.code is (
            native.EnvironmentRestoreStorageErrorCode.PLATFORM_UNAVAILABLE
        )
    finally:
        root.close()  # type: ignore[attr-defined]


def test_authority_rejects_missing_or_unexpected_restore_temp_name() -> None:
    present = _authority().restore
    absent = _authority(original_present=False).restore

    with pytest.raises(ValueError):
        native.EnvironmentRestoreStorageAuthority(1, present, None)
    with pytest.raises(ValueError):
        native.EnvironmentRestoreStorageAuthority(1, absent, _TEMP_NAME)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file APIs")
def test_native_replace_and_delete_follow_exact_restore_identity_contract(
    tmp_path: Path,
) -> None:
    path_api = NativeWindowsPathTrustApi()

    class _NativePackagePathApi:
        supported = True

        def current_user_sid(self) -> str:
            return path_api.current_user_sid()

        def open_directory(self, path: str, *, follow_reparse: bool) -> object:
            return path_api.open_directory(path, follow_reparse=follow_reparse)

        def query_directory(self, handle: object) -> NativeDirectoryFacts:
            return path_api.query_directory(handle)

        def query_security(self, handle: object) -> NativeSecurityFacts:
            del handle
            return NativeSecurityFacts(self.current_user_sid(), True, ())

        def close_handle(self, handle: object) -> None:
            path_api.close_handle(handle)

    root = capture_path_hierarchy(
        str(tmp_path),
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=_NativePackagePathApi(),
    )
    creation = NativeWindowsEnvironmentReplacementApi()
    api = native.NativeWindowsEnvironmentRestoreApi()
    destination = tmp_path / ".env"
    restore_temp = tmp_path / _TEMP_NAME
    original = b"original environment"
    candidate = b"candidate environment"

    def create(path: Path, contents: bytes) -> None:
        handle = creation.create_new_restricted_file(
            str(path),
            owner_sid=creation.current_user_sid(),
        )
        try:
            assert creation.write_file(handle, contents) == len(contents)
            creation.flush_file(handle)
        finally:
            creation.close_handle(handle)

    def observe(path: Path) -> EnvironmentDestinationObservation:
        handle = api.open_file_if_exists(str(path))
        assert handle is not None
        try:
            facts = api.query_file(handle)
            security = api.query_security(handle)
            api.seek_file(handle, 0)
            contents = api.read_file(handle, facts.size)
            assert security.security_descriptor_sha256 is not None
            return EnvironmentDestinationObservation(
                True,
                StableFileIdentity(facts.volume_serial, facts.file_id),
                hashlib.sha256(contents).hexdigest(),
                len(contents),
                facts.attributes,
                security.security_descriptor_sha256,
            )
        finally:
            api.close_handle(handle)

    try:
        create(destination, candidate)
        create(restore_temp, original)
        candidate_observed = observe(destination)
        temp_observed = observe(restore_temp)
        assert candidate_observed.identity is not None
        assert candidate_observed.file_attributes is not None
        assert candidate_observed.security_descriptor_sha256 is not None
        assert temp_observed.identity is not None
        authority = native.EnvironmentRestoreStorageAuthority(
            1,
            EnvironmentRestoreAuthority(
                1,
                root.evidence.root_identity,
                True,
                _identity(200),
                hashlib.sha256(original).hexdigest(),
                len(original),
                candidate_observed.file_attributes,
                candidate_observed.security_descriptor_sha256,
                candidate_observed.sha256 or "",
                candidate_observed.size or 0,
                candidate_observed.identity,
                candidate_observed.file_attributes,
                candidate_observed.security_descriptor_sha256,
                temp_observed.identity,
            ),
            _TEMP_NAME,
        )
        restored = native.NativeWindowsEnvironmentRestoreStorage(
            api=api
        ).restore_environment_from_held_package_root(root, authority)
        assert restored.identity == temp_observed.identity
        assert restored.sha256 == hashlib.sha256(original).hexdigest()
        assert not restore_temp.exists()

        destination.unlink()
        create(destination, candidate)
        candidate_observed = observe(destination)
        assert candidate_observed.identity is not None
        assert candidate_observed.file_attributes is not None
        assert candidate_observed.security_descriptor_sha256 is not None
        absent_authority = native.EnvironmentRestoreStorageAuthority(
            1,
            EnvironmentRestoreAuthority(
                1,
                root.evidence.root_identity,
                False,
                candidate_sha256=candidate_observed.sha256 or "",
                candidate_size=candidate_observed.size or 0,
                candidate_identity=candidate_observed.identity,
                candidate_file_attributes=candidate_observed.file_attributes,
                candidate_security_descriptor_sha256=(
                    candidate_observed.security_descriptor_sha256
                ),
            ),
        )
        absent = native.NativeWindowsEnvironmentRestoreStorage(
            api=api
        ).restore_environment_from_held_package_root(root, absent_authority)
        assert absent == EnvironmentDestinationObservation(False)
        assert not destination.exists()
    finally:
        root.close()
        destination.unlink(missing_ok=True)
        restore_temp.unlink(missing_ok=True)
