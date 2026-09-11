from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_path_trust as windows_path_trust  # noqa: E402
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    BROAD_WRITE_PRINCIPAL_SIDS,
    AccessAllowedAce,
    NativeDirectoryFacts,
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
    PathTrustPurpose,
    capture_path_hierarchy,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    KNOWN_CLOUD_REPARSE_TAGS,
    NativeFileFacts,
    WindowsSecurityError,
    capture_handle_bound_file,
)

_CURRENT_USER = "S-1-5-21-100-200-300-1001"
_SYSTEM = "S-1-5-18"
_ADMINISTRATORS = "S-1-5-32-544"
_SECRET = r"C:\Users\private-user\OneDrive\TowerScout"
_RESOLVED = r"\\?\C:\Users\private-user\OneDrive\TowerScout"


def _identity(path: str) -> bytes:
    value = sum(ord(character) for character in path.casefold()) % 256
    return bytes([value]) * 16


def _directory_facts(
    path: str,
    *,
    attributes: int = 0x10,
    reparse_tag: int = 0,
    drive_type: int = 3,
) -> NativeDirectoryFacts:
    final_path = path if path.startswith("\\\\?\\") else rf"\\?\{path}"
    return NativeDirectoryFacts(
        final_path=final_path,
        volume_serial=7,
        file_id=_identity(final_path),
        attributes=attributes,
        drive_type=drive_type,
        file_type=1,
        reparse_tag=reparse_tag,
    )


def _safe_security(owner: str = _CURRENT_USER) -> NativeSecurityFacts:
    return NativeSecurityFacts(
        owner_sid=owner,
        dacl_present=True,
        allowed_aces=(AccessAllowedAce(_CURRENT_USER, 0x001F01FF, 0),),
    )


class _FakePathTrustApi:
    supported = True

    def __init__(self) -> None:
        self.opened: list[tuple[str, bool, object]] = []
        self.closed: list[object] = []
        self.facts_by_handle: dict[object, NativeDirectoryFacts] = {}
        self.security_by_handle: dict[object, NativeSecurityFacts] = {}
        self.next_facts: list[NativeDirectoryFacts] = []
        self.next_security: list[NativeSecurityFacts] = []
        self.followed_root = _RESOLVED
        self.current_sid = _CURRENT_USER
        self.query_hook = None

    def current_user_sid(self) -> str:
        return self.current_sid

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        handle = object()
        self.opened.append((path, follow_reparse, handle))
        if self.next_facts:
            facts = self.next_facts.pop(0)
        elif follow_reparse and path.casefold() == _SECRET.casefold():
            facts = _directory_facts(self.followed_root)
        else:
            facts = _directory_facts(path)
        self.facts_by_handle[handle] = facts
        self.security_by_handle[handle] = (
            self.next_security.pop(0) if self.next_security else _safe_security()
        )
        return handle

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        if self.query_hook is not None:
            hook = self.query_hook
            self.query_hook = None
            hook()
        return self.facts_by_handle[handle]

    def query_security(self, handle: object) -> NativeSecurityFacts:
        return self.security_by_handle.get(handle, _safe_security())

    def close_handle(self, handle: object) -> None:
        self.closed.append(handle)


class _FakeCloudFileApi:
    supported = True

    def __init__(self) -> None:
        self.probe_handle = object()
        self.hydrated_handle = object()
        self.closed: list[object] = []
        self.cursor = 0
        self.content = b"cloud-content"
        self.hydrated_query_error: BaseException | None = None
        self.probe = NativeFileFacts(
            final_path=_RESOLVED + r"\.env",
            volume_serial=7,
            file_id=bytes.fromhex("11" * 16),
            attributes=0x480,
            link_count=1,
            size=len(self.content),
            creation_time=1,
            last_write_time=2,
            drive_type=3,
            file_type=1,
            reparse_tag=min(KNOWN_CLOUD_REPARSE_TAGS),
        )
        self.hydrated = self.probe

    def open_file_for_identity(self, path: str) -> object:
        del path
        return self.probe_handle

    def open_file_for_hydrated_identity(self, path: str) -> object:
        del path
        return self.hydrated_handle

    def query_file(self, handle: object) -> NativeFileFacts:
        if handle is self.hydrated_handle and self.hydrated_query_error is not None:
            error = self.hydrated_query_error
            self.hydrated_query_error = None
            raise error
        return self.probe if handle is self.probe_handle else self.hydrated

    def rewind_file(self, handle: object) -> None:
        del handle
        self.cursor = 0

    def read_file(self, handle: object, maximum: int) -> bytes:
        del handle
        chunk = self.content[self.cursor : self.cursor + maximum]
        self.cursor += len(chunk)
        return chunk

    def close_handle(self, handle: object) -> None:
        self.closed.append(handle)


class _NativeCleanupKernelShim:
    def __init__(self) -> None:
        self.closed: list[int] = []
        self.freed: list[int] = []

    @staticmethod
    def GetCurrentProcess() -> int:
        return 77

    def CloseHandle(self, handle: object) -> bool:
        self.closed.append(int(getattr(handle, "value", handle)))
        return True

    def LocalFree(self, value: object) -> None:
        self.freed.append(int(getattr(value, "value", value)))


class _NativeCleanupAdvapiShim:
    def __init__(self, operation: str) -> None:
        self.operation = operation

    @staticmethod
    def IsValidSid(_sid: object) -> bool:
        return True

    def ConvertSidToStringSidW(self, _sid: object, output: object) -> bool:
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p)).contents.value = 801
        if self.operation == "sid":
            raise KeyboardInterrupt
        return True

    def GetSecurityInfo(self, *arguments: object) -> int:
        descriptor = arguments[-1]
        ctypes.cast(descriptor, ctypes.POINTER(ctypes.c_void_p)).contents.value = 802
        if self.operation == "security":
            raise KeyboardInterrupt
        return 0

    def OpenProcessToken(self, _process: object, _access: int, token: object) -> bool:
        ctypes.cast(token, ctypes.POINTER(ctypes.c_void_p)).contents.value = 803
        if self.operation == "token":
            raise KeyboardInterrupt
        return True


def test_package_route_binds_lexical_and_resolved_ancestors() -> None:
    api = _FakePathTrustApi()

    with capture_path_hierarchy(
        _SECRET, purpose=PathTrustPurpose.PACKAGE_ROOT, api=api
    ) as trust:
        assert trust.evidence.lexical_depth == 5
        assert trust.evidence.resolved_depth == 5
        assert trust.root_snapshot.final_path == _RESOLVED
        assert trust.assert_unchanged() == trust.evidence
        assert not trust.closed

    assert trust.closed
    assert len(api.closed) == len(api.opened)
    assert all(handle in api.closed for _path, _follow, handle in api.opened)


def test_active_path_lease_allows_only_its_owner_to_revalidate() -> None:
    api = _FakePathTrustApi()

    with capture_path_hierarchy(
        _SECRET, purpose=PathTrustPurpose.PROCESS_ENVIRONMENT, api=api
    ) as trust:
        with pytest.raises(WindowsSecurityError) as outside:
            trust.assert_unchanged_while_held()
        assert outside.value.category == "path_handle_not_held"

        evidence = trust.run_while_held(trust.assert_unchanged_while_held)
        assert evidence == trust.evidence
        assert evidence.purpose is PathTrustPurpose.PROCESS_ENVIRONMENT


@pytest.mark.parametrize(
    "path",
    (
        r"C:\Users\private-user\..\TowerScout",
        "C:/Users/private-user/TowerScout",
        "C:\\Users\\private-user\\TowerScout\\.",
        "C:\\Users\\private-user\\TowerScout ",
    ),
)
def test_noncanonical_directory_names_fail_before_open(path: str) -> None:
    api = _FakePathTrustApi()

    with pytest.raises(WindowsSecurityError) as exc_info:
        capture_path_hierarchy(
            path,
            purpose=PathTrustPurpose.PACKAGE_ROOT,
            api=api,
        )

    assert exc_info.value.category == "path_invalid"
    assert api.opened == []


def test_junction_route_is_followed_but_held_and_resolved_target_is_rechecked() -> None:
    api = _FakePathTrustApi()
    junction = _directory_facts(
        _SECRET,
        attributes=0x410,
        reparse_tag=0xA0000003,
    )
    # The lexical chain's final component is the junction; the explicit followed
    # root and resolved chain then bind the target rather than trusting the name.
    api.next_facts = [
        _directory_facts("C:\\"),
        _directory_facts(r"C:\Users"),
        _directory_facts(r"C:\Users\private-user"),
        _directory_facts(r"C:\Users\private-user\OneDrive"),
        junction,
    ]

    with capture_path_hierarchy(
        _SECRET, purpose=PathTrustPurpose.PACKAGE_ROOT, api=api
    ) as trust:
        assert trust.root_snapshot.final_path == _RESOLVED
        assert any(follow for _path, follow, _handle in api.opened)
        assert trust.assert_unchanged() == trust.evidence


def test_hydrated_cloud_ancestor_is_allowed_but_unknown_or_offline_tag_fails() -> None:
    cloud = min(KNOWN_CLOUD_REPARSE_TAGS)
    api = _FakePathTrustApi()
    api.next_facts = [
        _directory_facts("C:\\"),
        _directory_facts(r"C:\Users"),
        _directory_facts(r"C:\Users\private-user"),
        _directory_facts(
            r"C:\Users\private-user\OneDrive",
            attributes=0x410,
            reparse_tag=cloud,
        ),
        _directory_facts(_SECRET),
    ]
    with capture_path_hierarchy(
        _SECRET, purpose=PathTrustPurpose.PACKAGE_ROOT, api=api
    ) as trust:
        assert trust.assert_unchanged() == trust.evidence

    for attributes, tag in ((0x1410, cloud), (0x410, 0x80000017)):
        failed = _FakePathTrustApi()
        failed.next_facts = [
            _directory_facts("C:\\", attributes=attributes, reparse_tag=tag)
        ]
        with pytest.raises(WindowsSecurityError) as exc_info:
            capture_path_hierarchy(
                _SECRET, purpose=PathTrustPurpose.PACKAGE_ROOT, api=failed
            )
        assert exc_info.value.category == "path_reparse_unsafe"
        assert len(failed.closed) == len(failed.opened)


@pytest.mark.parametrize(
    ("security", "category"),
    (
        (_safe_security("S-1-5-21-999-888-777-1009"), "path_owner_unsafe"),
        (
            NativeSecurityFacts(
                owner_sid=_CURRENT_USER,
                dacl_present=False,
                allowed_aces=(),
            ),
            "path_acl_unsafe",
        ),
        (
            NativeSecurityFacts(
                owner_sid=_CURRENT_USER,
                dacl_present=True,
                allowed_aces=(AccessAllowedAce("S-1-5-4", 0x2, 0),),
            ),
            "path_acl_unsafe",
        ),
        (
            NativeSecurityFacts(
                owner_sid=_CURRENT_USER,
                dacl_present=True,
                allowed_aces=(
                    AccessAllowedAce("S-1-5-21-444-555-666-1008", 0x40000, 0),
                ),
            ),
            "path_acl_unsafe",
        ),
        (
            NativeSecurityFacts(
                owner_sid=_CURRENT_USER,
                dacl_present=True,
                allowed_aces=(
                    AccessAllowedAce(min(BROAD_WRITE_PRINCIPAL_SIDS), 0x2, 0),
                ),
            ),
            "path_acl_unsafe",
        ),
    ),
)
def test_package_root_rejects_unapproved_owner_or_broad_writer(
    security: NativeSecurityFacts, category: str
) -> None:
    api = _FakePathTrustApi()
    api.next_security = [_safe_security()] * 4 + [security]

    with pytest.raises(WindowsSecurityError) as exc_info:
        capture_path_hierarchy(_SECRET, purpose=PathTrustPurpose.PACKAGE_ROOT, api=api)

    assert exc_info.value.category == category
    assert _SECRET not in str(exc_info.value)
    assert len(api.closed) == len(api.opened)


def test_inherited_read_and_inherit_only_write_do_not_reject_current_object() -> None:
    broad = min(BROAD_WRITE_PRINCIPAL_SIDS)
    api = _FakePathTrustApi()
    accepted = NativeSecurityFacts(
        owner_sid=_SYSTEM,
        dacl_present=True,
        allowed_aces=(
            AccessAllowedAce(broad, 0x001200A9, 0x10),
            AccessAllowedAce(broad, 0x001F01FF, 0x08),
            AccessAllowedAce(_ADMINISTRATORS, 0x001F01FF, 0),
        ),
    )
    api.next_security = [accepted] * 11

    with capture_path_hierarchy(
        _SECRET, purpose=PathTrustPurpose.PACKAGE_ROOT, api=api
    ) as trust:
        assert trust.assert_unchanged() == trust.evidence


def test_security_or_identity_drift_fails_closed_and_repr_is_redacted() -> None:
    api = _FakePathTrustApi()
    trust = capture_path_hierarchy(
        _SECRET, purpose=PathTrustPurpose.PACKAGE_ROOT, api=api
    )
    rendered = repr(trust) + repr(trust.evidence) + repr(trust.root_snapshot)
    assert "private-user" not in rendered
    assert _CURRENT_USER not in rendered

    root_handle = api.opened[-1][2]
    api.security_by_handle[root_handle] = replace(
        _safe_security(),
        allowed_aces=(AccessAllowedAce(min(BROAD_WRITE_PRINCIPAL_SIDS), 0x2, 0),),
    )
    with pytest.raises(WindowsSecurityError) as exc_info:
        trust.assert_unchanged()
    assert exc_info.value.category == "path_changed"
    trust.close()


def test_same_thread_close_during_path_revalidation_fails_without_closing() -> None:
    api = _FakePathTrustApi()
    trust = capture_path_hierarchy(
        _SECRET, purpose=PathTrustPurpose.PACKAGE_ROOT, api=api
    )
    api.query_hook = trust.close

    with pytest.raises(WindowsSecurityError) as exc_info:
        trust.assert_unchanged()

    assert exc_info.value.category == "path_changed"
    assert not trust.closed
    trust.close()


def test_capture_interruption_closes_every_opened_directory_handle() -> None:
    api = _FakePathTrustApi()

    def interrupt() -> None:
        raise KeyboardInterrupt

    api.query_hook = interrupt
    with pytest.raises(KeyboardInterrupt):
        capture_path_hierarchy(
            _SECRET,
            purpose=PathTrustPurpose.PACKAGE_ROOT,
            api=api,
        )

    assert len(api.closed) == len(api.opened) == 1


def test_native_dacl_parser_rejects_unsupported_access_granting_ace_type() -> None:
    assert windows_path_trust._ace_type_grants_access(0)
    assert not windows_path_trust._ace_type_grants_access(1)
    with pytest.raises(OSError):
        windows_path_trust._ace_type_grants_access(4)


@pytest.mark.parametrize(
    ("operation", "released"),
    (("sid", 801), ("security", 802), ("token", 803)),
)
def test_native_out_parameter_acquisition_interruption_releases_resource(
    operation: str,
    released: int,
) -> None:
    kernel = _NativeCleanupKernelShim()
    api = object.__new__(NativeWindowsPathTrustApi)
    api._kernel32 = kernel
    api._advapi32 = _NativeCleanupAdvapiShim(operation)

    with pytest.raises(KeyboardInterrupt):
        if operation == "sid":
            api._sid_text(ctypes.c_void_p(700))
        elif operation == "security":
            api.query_security(700)
        else:
            api.current_user_sid()

    released_values = kernel.closed + kernel.freed
    assert released_values == [released]


def test_cloud_file_is_hydrated_through_a_second_handle_and_bound_to_identity() -> None:
    from towerscout_launcher.windows_security import FileCapturePolicy

    api = _FakeCloudFileApi()
    policy = FileCapturePolicy(allow_hydrated_cloud_placeholder=True)

    with capture_handle_bound_file(
        Path(_SECRET + r"\.env"), api=api, policy=policy
    ) as bound:
        assert bound.snapshot.classification.hydrated
        assert bound.snapshot.identity.file_id == bytes.fromhex("11" * 16)
        assert bound.assert_unchanged() == bound.snapshot

    assert api.closed == [api.probe_handle, api.hydrated_handle]


def test_cloud_file_identity_change_during_hydration_fails_closed() -> None:
    from towerscout_launcher.windows_security import FileCapturePolicy

    api = _FakeCloudFileApi()
    api.hydrated = replace(api.probe, file_id=bytes.fromhex("22" * 16))

    with pytest.raises(WindowsSecurityError) as exc_info:
        capture_handle_bound_file(
            Path(_SECRET + r"\.env"),
            api=api,
            policy=FileCapturePolicy(allow_hydrated_cloud_placeholder=True),
        )

    assert exc_info.value.category == "file_identity_changed"
    assert api.closed == [api.probe_handle, api.hydrated_handle]


def test_cloud_hydration_interruption_closes_both_native_handles() -> None:
    from towerscout_launcher.windows_security import FileCapturePolicy

    api = _FakeCloudFileApi()
    api.hydrated_query_error = KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        capture_handle_bound_file(
            Path(_SECRET + r"\.env"),
            api=api,
            policy=FileCapturePolicy(allow_hydrated_cloud_placeholder=True),
        )

    assert api.closed == [api.probe_handle, api.hydrated_handle]


def test_cloud_file_read_hydrates_an_offline_known_placeholder() -> None:
    from towerscout_launcher.windows_security import FileCapturePolicy

    api = _FakeCloudFileApi()
    api.probe = replace(api.probe, attributes=0x1480)

    with capture_handle_bound_file(
        Path(_SECRET + r"\.env"),
        api=api,
        policy=FileCapturePolicy(allow_hydrated_cloud_placeholder=True),
    ) as bound:
        assert bound.snapshot.classification.hydrated
        assert bound.assert_unchanged() == bound.snapshot


def test_cloud_file_that_remains_offline_after_read_fails_closed() -> None:
    from towerscout_launcher.windows_security import FileCapturePolicy

    api = _FakeCloudFileApi()
    api.probe = replace(api.probe, attributes=0x1480)
    api.hydrated = api.probe

    with pytest.raises(WindowsSecurityError) as exc_info:
        capture_handle_bound_file(
            Path(_SECRET + r"\.env"),
            api=api,
            policy=FileCapturePolicy(allow_hydrated_cloud_placeholder=True),
        )

    assert exc_info.value.category == "file_reparse_unsafe"
    assert api.closed == [api.probe_handle, api.hydrated_handle]


def test_native_path_api_degrades_closed_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as scoped:
        scoped.setattr(os, "name", "posix")
        api = NativeWindowsPathTrustApi()
    assert not api.supported

    with pytest.raises(WindowsSecurityError) as exc_info:
        capture_path_hierarchy(_SECRET, purpose=PathTrustPurpose.PACKAGE_ROOT, api=api)
    assert exc_info.value.category == "windows_security_unavailable"


@pytest.mark.skipif(os.name != "nt", reason="native Windows path trust proof")
def test_native_path_api_binds_protected_system_hierarchy() -> None:
    candidate = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32")

    with capture_path_hierarchy(
        candidate,
        purpose=PathTrustPurpose.PACKAGE_ROOT,
    ) as trust:
        assert trust.evidence.lexical_depth >= 2
        assert trust.evidence.resolved_depth >= 2
        assert trust.assert_unchanged() == trust.evidence
        assert candidate not in repr(trust)
