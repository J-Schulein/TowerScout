from __future__ import annotations

import hashlib
import os
import re
import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher import windows_security  # noqa: E402
from towerscout_launcher.windows_security import (  # noqa: E402
    CanonicalIdentityDigest,
    FileCapturePolicy,
    KNOWN_CLOUD_REPARSE_TAGS,
    NativeFileFacts,
    NativeWindowsFileApi,
    PathLocality,
    ReparseKind,
    StableFileIdentity,
    WindowsSecurityError,
    canonical_identity_digest,
    capture_handle_bound_file,
    classify_path,
    derive_environment_mutex_name,
    derive_repair_mutex_name,
)

_SECRET_PATH = r"\\?\C:\Users\private-user\secret-package\.env"


def _facts(**changes: object) -> NativeFileFacts:
    base = NativeFileFacts(
        final_path=_SECRET_PATH,
        volume_serial=0x0102030405060708,
        file_id=bytes.fromhex("00112233445566778899aabbccddeeff"),
        attributes=0x80,
        link_count=1,
        size=7,
        creation_time=100,
        last_write_time=200,
        drive_type=3,
        file_type=1,
        reparse_tag=0,
    )
    return replace(base, **changes)


class _FakeWindowsFileApi:
    def __init__(
        self,
        *,
        facts: NativeFileFacts | None = None,
        content: bytes = b"content",
        supported: bool = True,
    ) -> None:
        self.supported = supported
        self.facts = facts or _facts(size=len(content))
        self.content = content
        self.handle = object()
        self.opened_path = ""
        self.closed = False
        self.cursor = 0
        self.query_results: list[NativeFileFacts] = []
        self.open_error: Exception | None = None
        self.query_error: Exception | None = None
        self.read_result_override: object | None = None
        self.close_error: Exception | None = None

    def open_file_for_identity(self, path: str) -> object:
        self.opened_path = path
        if self.open_error is not None:
            raise self.open_error
        return self.handle

    def query_file(self, handle: object) -> NativeFileFacts:
        del handle
        if self.query_error is not None:
            raise self.query_error
        if self.query_results:
            return self.query_results.pop(0)
        return self.facts

    def rewind_file(self, handle: object) -> None:
        del handle
        self.cursor = 0

    def read_file(self, handle: object, maximum: int) -> bytes:
        del handle
        if self.read_result_override is not None:
            return self.read_result_override  # type: ignore[return-value]
        chunk = self.content[self.cursor : self.cursor + maximum]
        self.cursor += len(chunk)
        return chunk

    def close_handle(self, handle: object) -> None:
        del handle
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


def test_handle_capture_hashes_and_revalidates_through_same_open_handle() -> None:
    api = _FakeWindowsFileApi()
    requested = Path(r"C:\Users\private-user\secret-package\.env")

    with capture_handle_bound_file(requested, api=api) as bound:
        assert bound.snapshot.sha256 == hashlib.sha256(b"content").hexdigest()
        assert bound.snapshot.identity == StableFileIdentity(
            0x0102030405060708,
            bytes.fromhex("00112233445566778899aabbccddeeff"),
        )
        assert bound.snapshot.classification.locality is PathLocality.FIXED_LOCAL
        assert bound.assert_unchanged() == bound.snapshot
        assert api.opened_path == os.fspath(requested)
        assert not bound.closed

    assert bound.closed
    assert api.closed


def test_scoped_inspector_receives_and_revalidates_the_same_held_handle() -> None:
    api = _FakeWindowsFileApi()

    with capture_handle_bound_file(Path("private.exe"), api=api) as bound:
        observed: list[tuple[object, object]] = []

        def inspect(handle: object, snapshot: object) -> str:
            observed.append((handle, snapshot))
            return "verified"

        assert bound.inspect_same_handle(inspect) == "verified"

    assert observed == [(api.handle, bound.snapshot)]


def test_scoped_inspector_sanitizes_native_failure() -> None:
    api = _FakeWindowsFileApi()

    with capture_handle_bound_file(Path("private.exe"), api=api) as bound:
        with pytest.raises(WindowsSecurityError) as exc_info:
            bound.inspect_same_handle(
                lambda _handle, _snapshot: (_ for _ in ()).throw(OSError(_SECRET_PATH))
            )

    assert exc_info.value.category == "file_inspection_failed"
    assert _SECRET_PATH not in str(exc_info.value)
    assert _SECRET_PATH not in repr(exc_info.value)


def test_scoped_inspector_revalidates_after_failure_and_prioritizes_drift() -> None:
    api = _FakeWindowsFileApi()

    with capture_handle_bound_file(Path("private.exe"), api=api) as bound:

        def replace_then_fail(_handle: object, _snapshot: object) -> None:
            api.content = b"CONTENT"
            raise OSError(_SECRET_PATH)

        with pytest.raises(WindowsSecurityError) as exc_info:
            bound.inspect_same_handle(replace_then_fail)

    assert exc_info.value.category == "file_identity_changed"
    assert _SECRET_PATH not in str(exc_info.value)


def test_capture_detects_metadata_change_during_hash_and_closes_handle() -> None:
    api = _FakeWindowsFileApi()
    api.query_results = [_facts(), _facts(last_write_time=201)]

    with pytest.raises(WindowsSecurityError) as exc_info:
        capture_handle_bound_file(Path("private.env"), api=api)

    assert exc_info.value.category == "file_identity_changed"
    assert api.closed


def test_revalidation_detects_same_size_content_change() -> None:
    api = _FakeWindowsFileApi()

    with capture_handle_bound_file(Path("private.env"), api=api) as bound:
        api.content = b"CONTENT"
        with pytest.raises(WindowsSecurityError) as exc_info:
            bound.assert_unchanged()

    assert exc_info.value.category == "file_identity_changed"


@pytest.mark.parametrize(
    ("facts", "category"),
    (
        (_facts(drive_type=4), "file_location_unsafe"),
        (_facts(drive_type=0), "file_location_unsafe"),
        (_facts(link_count=2), "file_link_count_unsafe"),
        (_facts(attributes=0x90), "file_identity_unsafe"),
        (
            _facts(
                attributes=0x480,
                reparse_tag=0xA000000C,
            ),
            "file_reparse_unsafe",
        ),
        (
            _facts(
                attributes=0x480,
                reparse_tag=0x80000017,
            ),
            "file_reparse_unsafe",
        ),
    ),
)
def test_capture_rejects_nonlocal_nonregular_or_unsafe_reparse_leaf(
    facts: NativeFileFacts, category: str
) -> None:
    api = _FakeWindowsFileApi(facts=facts)

    with pytest.raises(WindowsSecurityError) as exc_info:
        capture_handle_bound_file(Path("private.env"), api=api)

    assert exc_info.value.category == category
    assert api.closed


def test_capture_rejects_oversized_file_before_reading() -> None:
    api = _FakeWindowsFileApi(facts=_facts(size=9), content=b"123456789")

    with pytest.raises(WindowsSecurityError) as exc_info:
        capture_handle_bound_file(
            Path("private.env"), api=api, policy=FileCapturePolicy(max_bytes=8)
        )

    assert exc_info.value.category == "file_size_invalid"
    assert api.cursor == 0
    assert api.closed


def test_capture_can_explicitly_allow_hardlinked_held_executable_identity() -> None:
    api = _FakeWindowsFileApi(facts=_facts(link_count=2))

    with capture_handle_bound_file(
        Path("runtime.exe"),
        api=api,
        policy=FileCapturePolicy(require_single_link=False),
    ) as bound:
        assert not bound.snapshot.classification.single_link
        assert bound.assert_unchanged() == bound.snapshot


def test_known_cloud_tag_is_classified_but_remains_ineligible_for_capture() -> None:
    cloud_tag = min(KNOWN_CLOUD_REPARSE_TAGS)
    api = _FakeWindowsFileApi(facts=_facts(attributes=0x480, reparse_tag=cloud_tag))

    classification = classify_path(api.facts)
    assert classification.reparse_kind is ReparseKind.KNOWN_CLOUD_PLACEHOLDER
    assert classification.hydrated
    with pytest.raises(WindowsSecurityError, match="reparse state"):
        capture_handle_bound_file(Path("private.env"), api=api)

    offline = _FakeWindowsFileApi(
        facts=_facts(attributes=0x1480, reparse_tag=cloud_tag)
    )
    assert not classify_path(offline.facts).hydrated
    with pytest.raises(WindowsSecurityError, match="reparse state"):
        capture_handle_bound_file(Path("private.env"), api=offline)


def test_unsupported_platform_and_native_failures_are_sanitized() -> None:
    secret = Path(r"C:\Users\private-user\secret-package\.env")
    unsupported = _FakeWindowsFileApi(supported=False)

    with pytest.raises(WindowsSecurityError) as unsupported_error:
        capture_handle_bound_file(secret, api=unsupported)
    assert unsupported_error.value.category == "windows_security_unavailable"

    failed = _FakeWindowsFileApi()
    failed.open_error = OSError(f"native failure for {secret}")
    with pytest.raises(WindowsSecurityError) as open_error:
        capture_handle_bound_file(secret, api=failed)

    rendered = f"{open_error.value!s} {open_error.value!r}"
    assert open_error.value.category == "file_open_failed"
    assert str(secret) not in rendered
    assert "private-user" not in rendered


def test_native_api_degrades_closed_when_windows_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = Path("private.env")
    with monkeypatch.context() as scoped_patch:
        scoped_patch.setattr(windows_security.os, "name", "posix")
        api = NativeWindowsFileApi()

    assert not api.supported
    with pytest.raises(WindowsSecurityError) as exc_info:
        capture_handle_bound_file(candidate, api=api)
    assert exc_info.value.category == "windows_security_unavailable"


def test_query_and_read_failures_do_not_disclose_private_native_details() -> None:
    secret_message = f"failed at {_SECRET_PATH} with raw identity 00112233"
    for failure_mode in ("query", "read"):
        api = _FakeWindowsFileApi()
        if failure_mode == "query":
            api.query_error = OSError(secret_message)
        else:
            api.read_result_override = "not bytes"

        with pytest.raises(WindowsSecurityError) as exc_info:
            capture_handle_bound_file(Path("private.env"), api=api)

        rendered = f"{exc_info.value!s} {exc_info.value!r}"
        assert _SECRET_PATH not in rendered
        assert "00112233" not in rendered
        assert api.closed


def test_close_failure_does_not_mask_primary_sanitized_capture_error() -> None:
    api = _FakeWindowsFileApi(facts=_facts(drive_type=4))
    api.close_error = OSError(f"close failed at {_SECRET_PATH}")

    with pytest.raises(WindowsSecurityError) as exc_info:
        capture_handle_bound_file(Path("private.env"), api=api)

    rendered = f"{exc_info.value!s} {exc_info.value!r}"
    assert exc_info.value.category == "file_location_unsafe"
    assert _SECRET_PATH not in rendered
    assert api.closed


def test_redacted_representations_hide_paths_hashes_and_file_ids() -> None:
    api = _FakeWindowsFileApi()
    with capture_handle_bound_file(Path("private.env"), api=api) as bound:
        rendered = " ".join(
            (
                repr(api.facts),
                repr(bound.snapshot.identity),
                repr(bound.snapshot),
                repr(bound),
            )
        )

    assert _SECRET_PATH not in rendered
    assert "00112233445566778899aabbccddeeff" not in rendered
    assert hashlib.sha256(b"content").hexdigest() not in rendered


def test_closed_handle_cannot_authorize_revalidation() -> None:
    bound = capture_handle_bound_file(Path("private.env"), api=_FakeWindowsFileApi())
    bound.close()

    with pytest.raises(WindowsSecurityError) as exc_info:
        bound.assert_unchanged()

    assert exc_info.value.category == "file_handle_closed"


def test_reparse_classification_uses_explicit_cloud_allowlist() -> None:
    cloud = classify_path(
        _facts(
            attributes=0x480,
            reparse_tag=min(KNOWN_CLOUD_REPARSE_TAGS),
        )
    )
    name_surrogate = classify_path(_facts(attributes=0x480, reparse_tag=0xA0000003))
    unsupported = classify_path(_facts(attributes=0x480, reparse_tag=0x80000017))

    assert cloud.reparse_kind is ReparseKind.KNOWN_CLOUD_PLACEHOLDER
    assert name_surrogate.reparse_kind is ReparseKind.NAME_SURROGATE
    assert unsupported.reparse_kind is ReparseKind.UNSUPPORTED


def test_canonical_identity_digest_is_length_prefixed_and_domain_separated() -> None:
    split_one = canonical_identity_digest("Endpoint", (b"a", b"bc"))
    split_two = canonical_identity_digest("Endpoint", (b"ab", b"c"))
    other_domain = canonical_identity_digest("ConfigVolume", (b"a", b"bc"))

    assert split_one != split_two
    assert split_one != other_domain
    assert "61" not in repr(split_one)
    assert "6263" not in repr(split_one)


def test_environment_mutex_name_binds_full_parent_identity() -> None:
    parent = StableFileIdentity(7, bytes.fromhex("10" * 16))
    same = derive_environment_mutex_name(parent)
    other_volume = derive_environment_mutex_name(
        StableFileIdentity(8, bytes.fromhex("10" * 16))
    )
    other_file = derive_environment_mutex_name(
        StableFileIdentity(7, bytes.fromhex("11" * 16))
    )

    assert same == derive_environment_mutex_name(parent)
    assert re.fullmatch(r"Global\\TowerScoutEnv-v1-[0-9a-f]{64}", same)
    assert same != other_volume
    assert same != other_file
    assert "10101010" not in same


def test_repair_mutex_name_binds_endpoint_project_and_config_volume() -> None:
    endpoint = canonical_identity_digest("Endpoint", (b"private-endpoint",))
    other_endpoint = canonical_identity_digest("Endpoint", (b"other-endpoint",))
    volume = canonical_identity_digest("ConfigVolume", (b"private-volume",))
    other_volume = canonical_identity_digest("ConfigVolume", (b"other-volume",))

    baseline = derive_repair_mutex_name(
        endpoint=endpoint,
        compose_project="towerscout",
        config_volume=volume,
    )

    assert re.fullmatch(r"Global\\TowerScoutRepair-v1-[0-9a-f]{64}", baseline)
    assert baseline != derive_repair_mutex_name(
        endpoint=other_endpoint,
        compose_project="towerscout",
        config_volume=volume,
    )
    assert baseline != derive_repair_mutex_name(
        endpoint=endpoint,
        compose_project="towerscout-other",
        config_volume=volume,
    )
    assert baseline != derive_repair_mutex_name(
        endpoint=endpoint,
        compose_project="towerscout",
        config_volume=other_volume,
    )
    assert "private-endpoint" not in baseline
    assert "private-volume" not in baseline


@pytest.mark.parametrize("project", ("", "TowerScout", "../escape", "a" * 64))
def test_repair_mutex_rejects_noncanonical_project(project: str) -> None:
    identity = CanonicalIdentityDigest("Endpoint", "0" * 64)

    with pytest.raises(ValueError, match="Compose project identity is invalid"):
        derive_repair_mutex_name(
            endpoint=identity,
            compose_project=project,
            config_volume=CanonicalIdentityDigest("ConfigVolume", "1" * 64),
        )


@pytest.mark.parametrize(
    ("endpoint_domain", "volume_domain"),
    (("ConfigVolume", "ConfigVolume"), ("Endpoint", "Endpoint")),
)
def test_repair_mutex_rejects_semantically_miswired_identity_domains(
    endpoint_domain: str, volume_domain: str
) -> None:
    with pytest.raises(ValueError, match="identity domains"):
        derive_repair_mutex_name(
            endpoint=CanonicalIdentityDigest(endpoint_domain, "0" * 64),
            compose_project="towerscout",
            config_volume=CanonicalIdentityDigest(volume_domain, "1" * 64),
        )


def test_mutex_name_derivation_rejects_wrong_internal_identity_types() -> None:
    with pytest.raises(ValueError, match="Environment mutex identity is invalid"):
        derive_environment_mutex_name(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="identity domains"):
        derive_repair_mutex_name(
            endpoint=object(),  # type: ignore[arg-type]
            compose_project="towerscout",
            config_volume=CanonicalIdentityDigest("ConfigVolume", "1" * 64),
        )


@pytest.mark.skipif(os.name != "nt", reason="native Windows handle proof")
def test_native_windows_handle_capture_smoke() -> None:
    candidate = Path(windows_security.__file__).resolve()
    expected = hashlib.sha256(candidate.read_bytes()).hexdigest()

    with capture_handle_bound_file(candidate) as bound:
        assert bound.snapshot.sha256 == expected
        assert bound.snapshot.classification.locality is PathLocality.FIXED_LOCAL
        assert bound.assert_unchanged() == bound.snapshot
        assert str(candidate) not in repr(bound)
        assert str(candidate) not in repr(bound.snapshot)


@pytest.mark.skipif(os.name != "nt", reason="native Windows hard-link proof")
def test_native_held_executable_hardlink_denies_concurrent_write(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "vendor.exe"
    alias = tmp_path / "vendor-hardlink.exe"
    executable.write_bytes(b"verified-vendor-bytes")
    os.link(executable, alias)

    policy = FileCapturePolicy(require_single_link=False)
    with capture_handle_bound_file(executable, policy=policy) as bound:
        assert not bound.snapshot.classification.single_link
        with pytest.raises(OSError):
            alias.open("r+b")
        assert bound.assert_unchanged() == bound.snapshot
