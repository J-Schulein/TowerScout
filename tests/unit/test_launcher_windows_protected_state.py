from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_protected_state as protected_state  # noqa: E402
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
    NativeDirectoryFacts,
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
    validate_security_facts,
)
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    NativeWindowsProtectedStateApi,
    ProtectedDataPurpose,
    ProtectedStateError,
    protect_current_user_data,
    unprotect_current_user_data,
)

_CURRENT_USER = "S-1-5-21-100-200-300-1001"
_SYSTEM = "S-1-5-18"
_LOCAL_APP_DATA = r"C:\Users\private-user\AppData\Local"


def _identity(path: str) -> bytes:
    return hashlib.sha256(path.casefold().encode("utf-8")).digest()[:16]


def _final_path(path: str) -> str:
    return path if path.startswith("\\\\?\\") else rf"\\?\{path}"


def _protected_security() -> NativeSecurityFacts:
    return NativeSecurityFacts(
        owner_sid=_CURRENT_USER,
        dacl_present=True,
        allowed_aces=(
            AccessAllowedAce(_CURRENT_USER, 0x001F01FF, 0x03),
            AccessAllowedAce(_SYSTEM, 0x001F01FF, 0x03),
        ),
        dacl_protected=True,
    )


class _FakePathApi:
    supported = True

    def __init__(self, *, protected: bool = True) -> None:
        self.protected = protected
        self.opened: list[tuple[str, bool, int]] = []
        self.closed: list[int] = []
        self.paths: dict[int, str] = {}

    def current_user_sid(self) -> str:
        return _CURRENT_USER

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        handle = len(self.opened) + 1
        self.opened.append((path, follow_reparse, handle))
        self.paths[handle] = path
        return handle

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        assert type(handle) is int
        path = self.paths[handle]
        final = _final_path(path)
        return NativeDirectoryFacts(
            final_path=final,
            volume_serial=7,
            file_id=_identity(final),
            attributes=0x10,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        del handle
        security = _protected_security()
        if self.protected:
            return security
        return NativeSecurityFacts(
            security.owner_sid,
            security.dacl_present,
            security.allowed_aces,
            dacl_protected=False,
        )

    def close_handle(self, handle: object) -> None:
        assert type(handle) is int
        self.closed.append(handle)


class _FakeProtectedStateApi:
    supported = True

    def __init__(self) -> None:
        self.created: list[tuple[str, str]] = []
        self.protect_calls: list[tuple[bytes, int]] = []
        self.unprotect_calls: list[tuple[bytes, int]] = []
        self.fail_create_at: int | None = None

    def current_user_sid(self) -> str:
        return _CURRENT_USER

    def local_app_data_path(self) -> str:
        return _LOCAL_APP_DATA

    def ensure_directory(self, path: str, *, owner_sid: str) -> None:
        if self.fail_create_at == len(self.created):
            raise OSError("sensitive native detail")
        self.created.append((path, owner_sid))

    def protect_current_user(
        self, plaintext: bytes, *, entropy: bytes, flags: int
    ) -> bytes:
        self.protect_calls.append((entropy, flags))
        key = hashlib.sha256(entropy).digest()
        return key + bytes(
            value ^ key[index % len(key)] for index, value in enumerate(plaintext)
        )

    def unprotect_current_user(
        self, ciphertext: bytes, *, entropy: bytes, flags: int
    ) -> bytes:
        self.unprotect_calls.append((entropy, flags))
        key = hashlib.sha256(entropy).digest()
        if not ciphertext.startswith(key):
            raise ValueError("sensitive authentication detail")
        encrypted = ciphertext[len(key) :]
        return bytes(
            value ^ key[index % len(key)] for index, value in enumerate(encrypted)
        )


def test_protected_root_uses_fixed_known_folder_hierarchy_and_redacts() -> None:
    api = _FakeProtectedStateApi()
    path_api = _FakePathApi()

    with protected_state._capture_protected_state_root_with_apis(
        api=api,
        path_api=path_api,
    ) as root:
        assert api.created == [
            (rf"{_LOCAL_APP_DATA}\TowerScout", _CURRENT_USER),
            (rf"{_LOCAL_APP_DATA}\TowerScout\Recovery", _CURRENT_USER),
            (rf"{_LOCAL_APP_DATA}\TowerScout\Recovery\v1", _CURRENT_USER),
        ]
        assert root.assert_unchanged() == root.evidence
        protected = root.protect(
            b"provider-key-material",
            ProtectedDataPurpose.ENVIRONMENT_BACKUP,
        )
        assert (
            root.unprotect(
                protected,
                ProtectedDataPurpose.ENVIRONMENT_BACKUP,
            )
            == b"provider-key-material"
        )
        rendered = repr(root) + repr(root.evidence) + repr(protected)
        assert "private-user" not in rendered
        assert "provider-key-material" not in rendered

    assert root.closed
    assert len(path_api.closed) == len(path_api.opened)
    assert api.protect_calls[0][1] == 1
    assert api.unprotect_calls[0][1] == 1
    assert api.protect_calls[0][0] == api.unprotect_calls[0][0]


def test_protected_root_scopes_journal_storage_to_retained_hierarchy() -> None:
    api = _FakeProtectedStateApi()
    path_api = _FakePathApi()
    root = protected_state._capture_protected_state_root_with_apis(
        api=api,
        path_api=path_api,
    )
    observed: list[str] = []

    result = root.run_journal_storage(
        lambda root_path: observed.append(root_path) or "completed"
    )

    assert result == "completed"
    assert observed == [rf"{_LOCAL_APP_DATA}\TowerScout\Recovery\v1"]
    root.close()
    with pytest.raises(ProtectedStateError) as closed:
        root.run_journal_storage(lambda root_path: root_path)
    assert closed.value.category == "protected_state_unsafe"


def test_protected_root_preserves_journal_callback_failure_after_revalidation() -> None:
    api = _FakeProtectedStateApi()
    path_api = _FakePathApi()
    root = protected_state._capture_protected_state_root_with_apis(
        api=api,
        path_api=path_api,
    )
    failure = RuntimeError("caller-owned sanitized failure")

    with pytest.raises(RuntimeError) as raised:
        root.run_journal_storage(lambda root_path: (_ for _ in ()).throw(failure))

    assert raised.value is failure
    assert root.assert_unchanged() == root.evidence
    root.close()


def test_protected_root_preserves_process_control_exception() -> None:
    root = protected_state._capture_protected_state_root_with_apis(
        api=_FakeProtectedStateApi(),
        path_api=_FakePathApi(),
    )
    interruption = KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt) as raised:
        root.run_journal_storage(lambda root_path: (_ for _ in ()).throw(interruption))

    assert raised.value is interruption
    assert root.assert_unchanged() == root.evidence
    root.close()


def test_protected_root_rejects_unprotected_state_and_closes_handles() -> None:
    api = _FakeProtectedStateApi()
    path_api = _FakePathApi(protected=False)

    with pytest.raises(ProtectedStateError) as exc_info:
        protected_state._capture_protected_state_root_with_apis(
            api=api,
            path_api=path_api,
        )

    assert exc_info.value.category == "protected_state_unsafe"
    assert _LOCAL_APP_DATA not in str(exc_info.value)
    assert len(path_api.closed) == len(path_api.opened)


def test_protected_root_creation_failure_is_sanitized_and_closes_handles() -> None:
    api = _FakeProtectedStateApi()
    api.fail_create_at = 1
    path_api = _FakePathApi()

    with pytest.raises(ProtectedStateError) as exc_info:
        protected_state._capture_protected_state_root_with_apis(
            api=api,
            path_api=path_api,
        )

    assert exc_info.value.category == "protected_state_unavailable"
    assert "sensitive" not in str(exc_info.value)
    assert len(path_api.closed) == len(path_api.opened)


def test_dpapi_purpose_mismatch_and_tampering_fail_without_detail() -> None:
    api = _FakeProtectedStateApi()
    blob = protected_state._protect_current_user_data_with_api(
        b"secret",
        ProtectedDataPurpose.JOURNAL_GENERATION,
        api=api,
    )

    with pytest.raises(ProtectedStateError) as mismatch:
        protected_state._unprotect_current_user_data_with_api(
            blob,
            ProtectedDataPurpose.ENVIRONMENT_BACKUP,
            api=api,
        )
    assert mismatch.value.category == "protected_data_invalid"

    tampered = protected_state.CurrentUserProtectedBlob(
        ProtectedDataPurpose.JOURNAL_GENERATION,
        b"tampered",
    )
    with pytest.raises(ProtectedStateError) as invalid:
        protected_state._unprotect_current_user_data_with_api(
            tampered,
            ProtectedDataPurpose.JOURNAL_GENERATION,
            api=api,
        )
    assert invalid.value.category == "protected_data_invalid"
    assert "sensitive" not in str(invalid.value)


def test_native_adapter_degrades_closed_when_windows_apis_are_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as scoped:
        scoped.setattr(os, "name", "posix")
        api = NativeWindowsProtectedStateApi()
    assert not api.supported


def test_native_adapter_rejects_unscoped_entropy_before_os_use() -> None:
    api = NativeWindowsProtectedStateApi()

    with pytest.raises(ValueError):
        api.protect_current_user(b"secret", entropy=b"ambient", flags=1)
    with pytest.raises(ValueError):
        api.unprotect_current_user(b"ciphertext", entropy=b"ambient", flags=1)


@pytest.mark.skipif(os.name != "nt", reason="native Windows current-user DPAPI proof")
def test_native_current_user_dpapi_round_trip_is_purpose_bound() -> None:
    plaintext = b"TowerScout Gate-A DPAPI proof"
    protected = protect_current_user_data(
        plaintext,
        ProtectedDataPurpose.JOURNAL_GENERATION,
    )

    assert plaintext not in protected.ciphertext
    assert (
        unprotect_current_user_data(
            protected,
            ProtectedDataPurpose.JOURNAL_GENERATION,
        )
        == plaintext
    )
    with pytest.raises(ProtectedStateError) as mismatch:
        unprotect_current_user_data(
            protected,
            ProtectedDataPurpose.CERTIFICATE_BACKUP,
        )
    assert mismatch.value.category == "protected_data_invalid"


@pytest.mark.skipif(os.name != "nt", reason="native Windows protected DACL proof")
def test_native_known_folder_and_protected_directory_policy(tmp_path: Path) -> None:
    api = NativeWindowsProtectedStateApi()
    path_api = NativeWindowsPathTrustApi()
    assert api.supported
    assert path_api.supported
    assert Path(api.local_app_data_path()).is_absolute()

    candidate = tmp_path / "protected-state"
    current_user_sid = api.current_user_sid()
    api.ensure_directory(str(candidate), owner_sid=current_user_sid)
    handle = path_api.open_directory(str(candidate), follow_reparse=True)
    try:
        facts = path_api.query_directory(handle)
        assert facts.reparse_tag == 0
        validate_security_facts(
            path_api.query_security(handle),
            current_user_sid=current_user_sid,
            trusted_root=True,
            protected_state_root=True,
        )
    finally:
        path_api.close_handle(handle)
