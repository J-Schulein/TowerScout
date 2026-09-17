from __future__ import annotations

import hashlib
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_environment_promotion as promotion  # noqa: E402
import towerscout_launcher.windows_environment_promotion_native as native  # noqa: E402
from towerscout_launcher.windows_environment_replacement_native import (  # noqa: E402
    EnvironmentTempVerifiedRecord,
    NativeWindowsEnvironmentReplacementApi,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    NativeDirectoryFacts,
    NativeSecurityFacts,
    PathTrustPurpose,
    capture_path_hierarchy,
)
from towerscout_launcher.windows_recovery_environment_restore import (  # noqa: E402
    EnvironmentDestinationObservation,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    StableFileIdentity,
)

_ROOT = r"C:\Users\reviewed-user\TowerScout"
_DESTINATION = rf"{_ROOT}\.env"
_TEMP_NAME = ".towerscout-env-0123456789abcdef0123456789abcdef.tmp"
_TEMP = rf"{_ROOT}\{_TEMP_NAME}"


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


def _path_identity(path: str) -> bytes:
    return hashlib.sha256(path.casefold().encode("utf-16-le")).digest()[:16]


@dataclass(frozen=True, slots=True)
class _PathHandle:
    path: str


class _PathApi:
    supported = True

    def __init__(self) -> None:
        self.changed = False

    def current_user_sid(self) -> str:
        return "S-1-5-21-1000"

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        del follow_reparse
        return _PathHandle(path)

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        assert isinstance(handle, _PathHandle)
        identity = (
            _identity(7).file_id
            if handle.path == _ROOT
            else _path_identity(handle.path)
        )
        if self.changed and handle.path == _ROOT:
            identity = _identity(99).file_id
        return NativeDirectoryFacts(
            handle.path,
            7,
            identity,
            0x10,
            3,
            1,
            0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, _PathHandle)
        return NativeSecurityFacts("S-1-5-21-1000", True, ())

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _PathHandle)


@dataclass(slots=True)
class _File:
    identity: StableFileIdentity
    contents: bytes
    attributes: int
    descriptor: str


@dataclass(slots=True)
class _Handle:
    path: str
    identity: StableFileIdentity
    offset: int = 0


class _Api:
    def __init__(self) -> None:
        self._supported = True
        self.files: dict[str, _File] = {}
        self.events: list[str] = []
        self.replace_error: BaseException | None = None
        self.move_error: BaseException | None = None
        self.replace_error_after_apply = False
        self.move_error_after_apply = False
        self.corrupt_after_apply = False

    @property
    def supported(self) -> bool:
        return self._supported

    def open_file_if_exists(self, path: str) -> object | None:
        self.events.append(f"open:{path.rsplit('\\', 1)[-1]}")
        item = self.files.get(path)
        return None if item is None else _Handle(path, item.identity)

    def query_file(self, handle: object) -> NativeFileFacts:
        assert isinstance(handle, _Handle)
        item = self.files[handle.path]
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
        assert isinstance(handle, _Handle)
        return NativeSecurityFacts(
            "S-1-5-21-1000",
            True,
            (),
            security_descriptor_sha256=self.files[handle.path].descriptor,
        )

    def seek_file(self, handle: object, offset: int) -> None:
        assert isinstance(handle, _Handle)
        handle.offset = offset

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert isinstance(handle, _Handle)
        contents = self.files[handle.path].contents
        result = contents[handle.offset : handle.offset + maximum]
        handle.offset += len(result)
        return result

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _Handle)

    def _apply_replace(self, destination: str, source: str) -> None:
        prior = self.files[destination]
        candidate = self.files.pop(source)
        self.files[destination] = _File(
            candidate.identity,
            b"corrupt" if self.corrupt_after_apply else candidate.contents,
            prior.attributes,
            prior.descriptor,
        )

    def replace_existing_file(self, destination: str, source: str) -> None:
        self.events.append("replace")
        if self.replace_error is not None and not self.replace_error_after_apply:
            raise self.replace_error
        self._apply_replace(destination, source)
        if self.replace_error is not None:
            raise self.replace_error

    def _apply_move(self, source: str, destination: str) -> None:
        if destination in self.files:
            raise FileExistsError("private destination")
        candidate = self.files.pop(source)
        if self.corrupt_after_apply:
            candidate.contents = b"corrupt"
        self.files[destination] = candidate

    def move_new_file(self, source: str, destination: str) -> None:
        self.events.append("move")
        if self.move_error is not None and not self.move_error_after_apply:
            raise self.move_error
        self._apply_move(source, destination)
        if self.move_error is not None:
            raise self.move_error


def _root() -> tuple[object, _PathApi]:
    api = _PathApi()
    root = capture_path_hierarchy(
        _ROOT,
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=api,
    )
    return root, api


def _verified() -> EnvironmentTempVerifiedRecord:
    contents = b"candidate environment"
    return EnvironmentTempVerifiedRecord(
        1,
        "1" * 64,
        _identity(7),
        _identity(9),
        hashlib.sha256(contents).hexdigest(),
        len(contents),
        0x80,
        "d" * 64,
        _TEMP_NAME,
    )


def _original() -> EnvironmentDestinationObservation:
    contents = b"original env"
    return EnvironmentDestinationObservation(
        True,
        _identity(8),
        hashlib.sha256(contents).hexdigest(),
        len(contents),
        0x20,
        "b" * 64,
    )


def _authority(
    *, original_present: bool = True
) -> promotion.EnvironmentPromotionAuthority:
    return promotion.EnvironmentPromotionAuthority(
        1,
        _identity(7),
        _original() if original_present else EnvironmentDestinationObservation(False),
        _verified(),
    )


def _arrange(api: _Api, authority: promotion.EnvironmentPromotionAuthority) -> None:
    if authority.original.present:
        assert authority.original.identity is not None
        assert authority.original.file_attributes is not None
        assert authority.original.security_descriptor_sha256 is not None
        api.files[_DESTINATION] = _File(
            authority.original.identity,
            b"original env",
            authority.original.file_attributes,
            authority.original.security_descriptor_sha256,
        )
    api.files[_TEMP] = _File(
        authority.verified.temp_identity,
        b"candidate environment",
        authority.verified.candidate_file_attributes,
        authority.verified.candidate_security_descriptor_sha256,
    )


def _promote(
    root: object,
    authority: promotion.EnvironmentPromotionAuthority,
    api: _Api,
) -> EnvironmentDestinationObservation:
    storage = native.NativeWindowsEnvironmentPromotionStorage(api=api)
    return storage.promote_environment_from_held_package_root(  # type: ignore[arg-type]
        root,
        authority,
    )


def test_existing_destination_is_replaced_and_preserves_destination_metadata() -> None:
    root, _path_api = _root()
    api = _Api()
    authority = _authority()
    _arrange(api, authority)
    try:
        result = _promote(root, authority, api)
        assert result == authority.expected_applied
        assert api.files[_DESTINATION].identity == authority.verified.temp_identity
        assert api.files[_DESTINATION].attributes == authority.original.file_attributes
        assert api.files[_DESTINATION].descriptor == (
            authority.original.security_descriptor_sha256
        )
        assert _TEMP not in api.files
        assert api.events.count("replace") == 1
        assert "move" not in api.events
    finally:
        root.close()  # type: ignore[attr-defined]


def test_absent_destination_uses_non_overwriting_move_and_staged_metadata() -> None:
    root, _path_api = _root()
    api = _Api()
    authority = _authority(original_present=False)
    _arrange(api, authority)
    try:
        result = _promote(root, authority, api)
        assert result == authority.expected_applied
        assert api.files[_DESTINATION].attributes == (
            authority.verified.candidate_file_attributes
        )
        assert api.events.count("move") == 1
        assert "replace" not in api.events
    finally:
        root.close()  # type: ignore[attr-defined]


@pytest.mark.parametrize("original_present", (True, False))
def test_restart_after_completed_call_is_idempotent(original_present: bool) -> None:
    root, _path_api = _root()
    api = _Api()
    authority = _authority(original_present=original_present)
    expected = authority.expected_applied
    assert expected.identity is not None
    assert expected.file_attributes is not None
    assert expected.security_descriptor_sha256 is not None
    api.files[_DESTINATION] = _File(
        expected.identity,
        b"candidate environment",
        expected.file_attributes,
        expected.security_descriptor_sha256,
    )
    try:
        assert _promote(root, authority, api) == expected
        assert "replace" not in api.events
        assert "move" not in api.events
    finally:
        root.close()  # type: ignore[attr-defined]


@pytest.mark.parametrize("original_present", (True, False))
def test_api_error_after_completed_call_reconciles_as_success(
    original_present: bool,
) -> None:
    root, _path_api = _root()
    api = _Api()
    authority = _authority(original_present=original_present)
    _arrange(api, authority)
    if original_present:
        api.replace_error = OSError("private")
        api.replace_error_after_apply = True
    else:
        api.move_error = OSError("private")
        api.move_error_after_apply = True
    try:
        assert _promote(root, authority, api) == authority.expected_applied
    finally:
        root.close()  # type: ignore[attr-defined]


@pytest.mark.parametrize("original_present", (True, False))
def test_api_error_with_exact_unchanged_state_is_retryable_failure(
    original_present: bool,
) -> None:
    root, _path_api = _root()
    api = _Api()
    authority = _authority(original_present=original_present)
    _arrange(api, authority)
    if original_present:
        api.replace_error = OSError("private")
    else:
        api.move_error = OSError("private")
    try:
        with pytest.raises(native.EnvironmentPromotionStorageError) as failure:
            _promote(root, authority, api)
        assert (
            failure.value.code
            is native.EnvironmentPromotionStorageErrorCode.APPLY_FAILED
        )
        assert "private" not in str(failure.value)
    finally:
        root.close()  # type: ignore[attr-defined]


def test_destination_or_temp_drift_is_preserved_without_mutation() -> None:
    root, _path_api = _root()
    api = _Api()
    authority = _authority()
    _arrange(api, authority)
    api.files[_TEMP].contents = b"third state"
    try:
        with pytest.raises(native.EnvironmentPromotionStorageError) as failure:
            _promote(root, authority, api)
        assert failure.value.code is (
            native.EnvironmentPromotionStorageErrorCode.STATE_AMBIGUOUS
        )
        assert "replace" not in api.events
        assert "move" not in api.events
        assert _DESTINATION in api.files and _TEMP in api.files
    finally:
        root.close()  # type: ignore[attr-defined]


def test_corrupt_post_call_state_is_preserved_as_ambiguous() -> None:
    root, _path_api = _root()
    api = _Api()
    authority = _authority()
    _arrange(api, authority)
    api.corrupt_after_apply = True
    try:
        with pytest.raises(native.EnvironmentPromotionStorageError) as failure:
            _promote(root, authority, api)
        assert failure.value.code is (
            native.EnvironmentPromotionStorageErrorCode.STATE_AMBIGUOUS
        )
        assert _DESTINATION in api.files
        assert _TEMP not in api.files
    finally:
        root.close()  # type: ignore[attr-defined]


def test_package_root_change_and_unsupported_platform_fail_closed() -> None:
    root, path_api = _root()
    api = _Api()
    authority = _authority()
    _arrange(api, authority)
    try:
        path_api.changed = True
        with pytest.raises(native.EnvironmentPromotionStorageError) as changed:
            _promote(root, authority, api)
        assert (
            changed.value.code
            is native.EnvironmentPromotionStorageErrorCode.VERIFY_FAILED
        )
        path_api.changed = False
        api._supported = False
        with pytest.raises(native.EnvironmentPromotionStorageError) as unsupported:
            _promote(root, authority, api)
        assert unsupported.value.code is (
            native.EnvironmentPromotionStorageErrorCode.PLATFORM_UNAVAILABLE
        )
    finally:
        root.close()  # type: ignore[attr-defined]


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file APIs")
def test_native_api_replace_and_move_preserve_documented_identity_contract() -> None:
    directory = (
        ROOT / ".agent_work" / ("task087-environment-promotion-" + secrets.token_hex(8))
    )
    directory.mkdir()
    try:
        _run_native_promotion_smoke(directory)
    finally:
        for name in (
            ".env",
            _TEMP_NAME,
            ".env-new",
            ".towerscout-env-fedcba9876543210fedcba9876543210.tmp",
        ):
            (directory / name).unlink(missing_ok=True)
        directory.rmdir()


def _run_native_promotion_smoke(directory: Path) -> None:
    api = native.NativeWindowsEnvironmentPromotionApi()
    creation = NativeWindowsEnvironmentReplacementApi()
    destination = directory / ".env"
    replacement = directory / _TEMP_NAME
    moved_destination = directory / ".env-new"
    moved_source = directory / ".towerscout-env-fedcba9876543210fedcba9876543210.tmp"

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

    create(destination, b"original")
    create(replacement, b"replacement")
    create(moved_source, b"moved")

    def inspect(
        path: Path,
    ) -> tuple[StableFileIdentity, int, str, NativeSecurityFacts]:
        handle = api.open_file_if_exists(str(path))
        assert handle is not None
        try:
            facts = api.query_file(handle)
            security = api.query_security(handle)
            assert security.security_descriptor_sha256 is not None
            return (
                StableFileIdentity(facts.volume_serial, facts.file_id),
                facts.attributes,
                security.security_descriptor_sha256,
                security,
            )
        finally:
            api.close_handle(handle)

    (
        original_identity,
        original_attributes,
        original_descriptor,
        original_security,
    ) = inspect(destination)
    (
        replacement_identity,
        _replacement_attributes,
        _replacement_descriptor,
        _replacement_security,
    ) = inspect(replacement)

    try:
        api.replace_existing_file(str(destination), str(replacement))
    except OSError as error:
        if error.errno == 5:
            pytest.skip("host policy denies ReplaceFileW WRITE_DAC/delete access")
        raise
    (
        applied_identity,
        applied_attributes,
        applied_descriptor,
        applied_security,
    ) = inspect(destination)
    assert original_identity != replacement_identity
    assert applied_identity == replacement_identity
    assert applied_attributes == original_attributes
    assert applied_security.owner_sid == original_security.owner_sid
    assert applied_security.dacl_present is original_security.dacl_present
    assert applied_security.dacl_protected is original_security.dacl_protected
    assert applied_security.allowed_aces == original_security.allowed_aces
    assert applied_descriptor == original_descriptor
    assert not replacement.exists()

    moved_identity, moved_attributes, moved_descriptor, moved_security = inspect(
        moved_source
    )
    api.move_new_file(str(moved_source), str(moved_destination))
    assert inspect(moved_destination) == (
        moved_identity,
        moved_attributes,
        moved_descriptor,
        moved_security,
    )
    assert not moved_source.exists()
