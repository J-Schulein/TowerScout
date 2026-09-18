from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
    NativeSecurityFacts,
)
from towerscout_launcher.target_contracts import MapProvider  # noqa: E402
from towerscout_launcher.windows_certificate_replacement import (  # noqa: E402
    CertificateReplacementPlan,
    certificate_replacement_evidence_sha256,
)
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from towerscout_launcher.windows_recovery_certificate_storage import (  # noqa: E402
    RecoveryCertificateStorageError,
    RecoveryCertificateStorageErrorCode,
)
from towerscout_launcher.windows_recovery_certificate_storage_native import (  # noqa: E402
    HeldCertificateRestoreTempPaths,
    NativeCertificateRestoreTempNameSource,
    NativeWindowsCertificateRestoreTempStorage,
    NativeWindowsRepairCertificateTempStorage,
    capture_held_certificate_restore_temps,
)
from towerscout_launcher.windows_recovery_certificate_restore import (  # noqa: E402
    CertificateDestinationRestoreAuthority,
    CertificateRestorationAuthority,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    CertificateRestoreTempCreatedRecord,
    CertificateRestoreTempPlanRecord,
    CertificateRestoreTempVerifiedRecord,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    StableFileIdentity,
)
import towerscout_launcher.windows_repair_transaction_journal as forward_journal  # noqa: E402

_ROOT = r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1"
_LOCAL_NAME = "recovery-certificate-" + "1" * 32 + ".tmp"
_BUNDLE_NAME = "recovery-certificate-" + "2" * 32 + ".tmp"
_LOCAL_PATH = rf"{_ROOT}\{_LOCAL_NAME}"
_BUNDLE_PATH = rf"{_ROOT}\{_BUNDLE_NAME}"
_USER_SID = "S-1-5-21-1000"
_SYSTEM_SID = "S-1-5-18"
_LOCAL = b"private-local-ca"
_BUNDLE = b"private-ca-bundle"
_REPAIR_LOCAL_NAME = "repair-certificate-" + "3" * 32 + ".tmp"
_REPAIR_BUNDLE_NAME = "repair-certificate-" + "4" * 32 + ".tmp"
_REPAIR_LOCAL_PATH = rf"{_ROOT}\{_REPAIR_LOCAL_NAME}"
_REPAIR_BUNDLE_PATH = rf"{_ROOT}\{_REPAIR_BUNDLE_NAME}"
_CANDIDATE_LOCAL = (
    b"-----BEGIN CERTIFICATE-----\nprivate-root\n-----END CERTIFICATE-----\n"
)
_CANDIDATE_BUNDLE = b"private-system-bundle\n" + _CANDIDATE_LOCAL


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


def test_native_certificate_restore_temp_names_are_bounded_and_unique() -> None:
    source = NativeCertificateRestoreTempNameSource()

    first = source.new_certificate_temp_name()
    second = source.new_certificate_temp_name()

    assert first != second
    assert len(first) == len("recovery-certificate-") + 32 + len(".tmp")
    assert first.startswith("recovery-certificate-")
    assert first.endswith(".tmp")
    assert all(character in "0123456789abcdef" for character in first[21:-4])


def _security() -> NativeSecurityFacts:
    return NativeSecurityFacts(
        _USER_SID,
        True,
        (
            AccessAllowedAce(_USER_SID, 0x001F01FF, 0),
            AccessAllowedAce(_SYSTEM_SID, 0x001F01FF, 0),
        ),
        True,
    )


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
    offset: int = 0
    delete_on_close: bool = False


class _Api:
    def __init__(self) -> None:
        self.supported = True
        self.files: dict[str, _File] = {}
        self.next_identity = 40
        self.query_identity_override: StableFileIdentity | None = None
        self.events: list[str] = []

    def current_user_sid(self) -> str:
        return _USER_SID

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object:
        assert owner_sid == _USER_SID
        self.events.append(f"create:{path}")
        if path in self.files:
            raise FileExistsError("private collision")
        identity = _identity(self.next_identity)
        self.next_identity += 1
        self.files[path] = _File(identity, b"", _security(), path)
        return _Handle(path, identity)

    def open_existing_file_for_update(self, path: str) -> object:
        self.events.append(f"update:{path}")
        return _Handle(path, self.files[path].identity)

    def reopen_file_for_verification(self, path: str) -> object:
        self.events.append(f"reopen:{path}")
        return _Handle(path, self.files[path].identity)

    def open_file_for_delete_if_exists(self, path: str) -> object | None:
        self.events.append(f"delete-open:{path}")
        item = self.files.get(path)
        return None if item is None else _Handle(path, item.identity)

    def reopen_file_if_exists(self, path: str) -> object | None:
        item = self.files.get(path)
        return None if item is None else _Handle(path, item.identity)

    def query_file(self, handle: object) -> NativeFileFacts:
        assert isinstance(handle, _Handle)
        item = self.files[handle.path]
        identity = self.query_identity_override or handle.identity
        return NativeFileFacts(
            item.final_path,
            identity.volume_serial,
            identity.file_id,
            0x80,
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
        return self.files[handle.path].security

    def flush_file(self, handle: object) -> None:
        assert isinstance(handle, _Handle)
        self.events.append(f"flush:{handle.path}")

    def write_file(self, handle: object, contents: bytes) -> int:
        assert isinstance(handle, _Handle)
        item = self.files[handle.path]
        before = item.contents[: handle.offset]
        after_offset = handle.offset + len(contents)
        after = item.contents[after_offset:]
        item.contents = before + contents + after
        handle.offset += len(contents)
        return len(contents)

    def seek_file(self, handle: object, offset: int) -> None:
        assert isinstance(handle, _Handle)
        handle.offset = offset

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert isinstance(handle, _Handle)
        item = self.files[handle.path]
        chunk = item.contents[handle.offset : handle.offset + maximum]
        handle.offset += len(chunk)
        return chunk

    def mark_file_for_deletion(self, handle: object) -> None:
        assert isinstance(handle, _Handle)
        handle.delete_on_close = True

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _Handle)
        if handle.delete_on_close:
            del self.files[handle.path]
            self.events.append(f"deleted:{handle.path}")


class _ForwardProtection:
    def __init__(self) -> None:
        self.nonce = 0

    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        self.nonce += 1
        return CurrentUserProtectedBlob(
            purpose,
            b"TSF1" + self.nonce.to_bytes(4, "big") + plaintext,
        )

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        assert blob.purpose is purpose
        return blob.ciphertext[8:]


def _replacement_plan() -> CertificateReplacementPlan:
    return CertificateReplacementPlan(
        MapProvider.GOOGLE,
        "a" * 64,
        _CANDIDATE_LOCAL,
        _CANDIDATE_BUNDLE,
    )


def _forward_selection(
    count: int,
    plan: CertificateReplacementPlan,
    identities: tuple[StableFileIdentity, StableFileIdentity] | None = None,
) -> forward_journal.RepairTransactionChainSelection:
    protection = _ForwardProtection()
    stream = forward_journal.RepairTransactionStreamIdentity(
        1,
        "a" * 32,
        "b" * 32,
        "c" * 64,
        "d" * 64,
        _identity(9),
    )
    states = (
        forward_journal.RepairTransactionState.CERTIFICATE_TEMP_PLANNED,
        forward_journal.RepairTransactionState.CERTIFICATE_TEMP_CREATED,
        forward_journal.RepairTransactionState.CERTIFICATE_TEMP_VERIFIED,
    )
    previous = stream.rollback_armed_generation_sha256
    sealed = []
    for sequence, state in enumerate(states[:count], start=1):
        record = forward_journal.RepairTransitionRecord(
            1,
            previous,
            stream.package_root_identity,
            (
                certificate_replacement_evidence_sha256(plan)
                if sequence == 1
                else f"{sequence:064x}"
            ),
            certificate_temp_names=(
                (_REPAIR_LOCAL_NAME, _REPAIR_BUNDLE_NAME) if sequence == 1 else None
            ),
            certificate_temp_identities=(identities if sequence in {2, 3} else None),
        )
        generation = forward_journal.RepairTransactionGeneration(
            1,
            stream,
            sequence,
            previous,
            state,
            record,
        )
        protected = forward_journal.protect_repair_transaction_generation(
            generation,
            protection=protection,
        )
        sealed.append(protected)
        previous = protected.generation_sha256
    return forward_journal.select_repair_transaction_chain(
        tuple(sealed),
        None,
        expected_stream=stream,
        protection=protection,
    )


def _plan(
    *, local: bool = True, bundle: bool = True
) -> CertificateRestoreTempPlanRecord:
    return CertificateRestoreTempPlanRecord(
        1,
        "a" * 64,
        _identity(1),
        _identity(2),
        "b" * 64,
        100,
        local,
        hashlib.sha256(_LOCAL).hexdigest() if local else None,
        len(_LOCAL) if local else None,
        0o644 if local else None,
        _LOCAL_NAME if local else None,
        bundle,
        hashlib.sha256(_BUNDLE).hexdigest() if bundle else None,
        len(_BUNDLE) if bundle else None,
        0o600 if bundle else None,
        _BUNDLE_NAME if bundle else None,
    )


def _created(
    local: StableFileIdentity | None,
    bundle: StableFileIdentity | None,
) -> CertificateRestoreTempCreatedRecord:
    return CertificateRestoreTempCreatedRecord(1, "c" * 64, local, bundle)


def _restore_authority(
    local: StableFileIdentity | None,
    bundle: StableFileIdentity | None,
) -> CertificateRestorationAuthority:
    return CertificateRestorationAuthority(
        "a" * 64,
        _identity(1),
        "b" * 64,
        "c" * 64,
        tuple(f"{value:064x}" for value in range(1, 9)),
        CertificateDestinationRestoreAuthority(
            local is not None,
            hashlib.sha256(_LOCAL).hexdigest() if local is not None else None,
            len(_LOCAL) if local is not None else None,
            0o644 if local is not None else None,
            "d" * 64,
            len(_LOCAL) + 1,
            0o644,
            _LOCAL_NAME if local is not None else None,
            local,
        ),
        CertificateDestinationRestoreAuthority(
            bundle is not None,
            hashlib.sha256(_BUNDLE).hexdigest() if bundle is not None else None,
            len(_BUNDLE) if bundle is not None else None,
            0o600 if bundle is not None else None,
            "e" * 64,
            len(_BUNDLE) + 1,
            0o644,
            _BUNDLE_NAME if bundle is not None else None,
            bundle,
        ),
    )


def test_native_certificate_temps_create_write_and_reverify_both_files() -> None:
    api = _Api()
    adapter = NativeWindowsCertificateRestoreTempStorage(api=api)
    plan = _plan()

    identities = adapter.create_certificate_restore_temps(_ROOT, plan)
    created = _created(identities.local_ca, identities.ca_bundle)
    assert adapter.verify_certificate_restore_temps(_ROOT, plan, created) == identities

    written = adapter.write_and_verify_certificate_restore_temps(
        _ROOT,
        plan,
        created,
        local_ca_contents=_LOCAL,
        ca_bundle_contents=_BUNDLE,
    )
    verified = CertificateRestoreTempVerifiedRecord(
        1,
        "d" * 64,
        written.local_ca,
        written.ca_bundle,
    )

    assert (
        adapter.verify_written_certificate_restore_temps(_ROOT, plan, verified)
        == written
    )
    assert api.files[_LOCAL_PATH].contents == _LOCAL
    assert api.files[_BUNDLE_PATH].contents == _BUNDLE


def test_native_forward_certificate_temps_follow_authenticated_write_ahead() -> None:
    api = _Api()
    adapter = NativeWindowsRepairCertificateTempStorage(api=api)
    plan = _replacement_plan()

    planned = _forward_selection(1, plan)
    identities = adapter.create_repair_certificate_temps(_ROOT, planned)
    assert identities.local_ca is not None
    assert identities.ca_bundle is not None
    exact_identities = (identities.local_ca, identities.ca_bundle)

    created = _forward_selection(2, plan, exact_identities)
    assert adapter.verify_created_repair_certificate_temps(_ROOT, created) == identities
    assert (
        adapter.write_and_verify_repair_certificate_temps(_ROOT, created, plan)
        == identities
    )

    verified = _forward_selection(3, plan, exact_identities)
    assert (
        adapter.verify_written_repair_certificate_temps(_ROOT, verified, plan)
        == identities
    )
    assert api.files[_REPAIR_LOCAL_PATH].contents == _CANDIDATE_LOCAL
    assert api.files[_REPAIR_BUNDLE_PATH].contents == _CANDIDATE_BUNDLE


def test_native_forward_certificate_write_rejects_substituted_plan() -> None:
    api = _Api()
    adapter = NativeWindowsRepairCertificateTempStorage(api=api)
    plan = _replacement_plan()
    identities = adapter.create_repair_certificate_temps(
        _ROOT,
        _forward_selection(1, plan),
    )
    assert identities.local_ca is not None
    assert identities.ca_bundle is not None
    created = _forward_selection(
        2,
        plan,
        (identities.local_ca, identities.ca_bundle),
    )
    substituted = CertificateReplacementPlan(
        MapProvider.GOOGLE,
        "b" * 64,
        _CANDIDATE_LOCAL,
        _CANDIDATE_BUNDLE,
    )

    with pytest.raises(RecoveryCertificateStorageError) as failure:
        adapter.write_and_verify_repair_certificate_temps(
            _ROOT,
            created,
            substituted,
        )

    assert failure.value.code is RecoveryCertificateStorageErrorCode.INPUT_INVALID
    assert api.files[_REPAIR_LOCAL_PATH].contents == b""
    assert api.files[_REPAIR_BUNDLE_PATH].contents == b""


def test_held_certificate_restore_temps_revalidate_both_exact_sources() -> None:
    api = _Api()
    local = _identity(40)
    bundle = _identity(41)
    api.files[_LOCAL_PATH] = _File(local, _LOCAL, _security(), _LOCAL_PATH)
    api.files[_BUNDLE_PATH] = _File(bundle, _BUNDLE, _security(), _BUNDLE_PATH)

    owner = capture_held_certificate_restore_temps(
        _ROOT,
        _restore_authority(local, bundle),
        api=api,
    )
    paths = owner.run_while_held(lambda value: value)

    assert paths == HeldCertificateRestoreTempPaths(
        local_ca=PureWindowsPath(_LOCAL_PATH),
        ca_bundle=PureWindowsPath(_BUNDLE_PATH),
    )
    owner.close()
    assert owner.closed


def test_held_certificate_restore_temps_detect_source_drift_after_operation() -> None:
    api = _Api()
    local = _identity(40)
    api.files[_LOCAL_PATH] = _File(local, _LOCAL, _security(), _LOCAL_PATH)
    owner = capture_held_certificate_restore_temps(
        _ROOT,
        _restore_authority(local, None),
        api=api,
    )

    with pytest.raises(RecoveryCertificateStorageError) as failure:
        owner.run_while_held(
            lambda _paths: setattr(api.files[_LOCAL_PATH], "contents", b"drift")
        )

    assert failure.value.code is RecoveryCertificateStorageErrorCode.VERIFY_FAILED
    owner.close()


def test_native_certificate_temp_reconciles_only_zero_byte_protected_orphan() -> None:
    api = _Api()
    original = _identity(20)
    api.files[_LOCAL_PATH] = _File(original, b"", _security(), _LOCAL_PATH)
    adapter = NativeWindowsCertificateRestoreTempStorage(api=api)

    identities = adapter.create_certificate_restore_temps(
        _ROOT,
        _plan(bundle=False),
    )

    assert identities.local_ca is not None
    assert identities.local_ca != original
    assert f"deleted:{_LOCAL_PATH}" in api.events


def test_native_certificate_temp_preserves_nonempty_planned_name_collision() -> None:
    api = _Api()
    original = _identity(20)
    api.files[_LOCAL_PATH] = _File(
        original,
        b"unrelated",
        _security(),
        _LOCAL_PATH,
    )
    adapter = NativeWindowsCertificateRestoreTempStorage(api=api)

    with pytest.raises(RecoveryCertificateStorageError) as failure:
        adapter.create_certificate_restore_temps(_ROOT, _plan(bundle=False))

    assert failure.value.code is RecoveryCertificateStorageErrorCode.VERIFY_FAILED
    assert api.files[_LOCAL_PATH].identity == original
    assert api.files[_LOCAL_PATH].contents == b"unrelated"


def test_native_certificate_temp_rejects_identity_drift_before_write() -> None:
    api = _Api()
    adapter = NativeWindowsCertificateRestoreTempStorage(api=api)
    plan = _plan(bundle=False)
    identities = adapter.create_certificate_restore_temps(_ROOT, plan)
    created = _created(identities.local_ca, None)
    api.query_identity_override = _identity(99)

    with pytest.raises(RecoveryCertificateStorageError) as failure:
        adapter.write_and_verify_certificate_restore_temps(
            _ROOT,
            plan,
            created,
            local_ca_contents=_LOCAL,
            ca_bundle_contents=None,
        )

    assert failure.value.code is RecoveryCertificateStorageErrorCode.VERIFY_FAILED
    assert api.files[_LOCAL_PATH].contents == b""


def test_native_certificate_temp_write_retry_accepts_only_exact_existing_bytes() -> (
    None
):
    api = _Api()
    adapter = NativeWindowsCertificateRestoreTempStorage(api=api)
    plan = _plan()
    identities = adapter.create_certificate_restore_temps(_ROOT, plan)
    created = _created(identities.local_ca, identities.ca_bundle)
    api.files[_LOCAL_PATH].contents = _LOCAL

    assert (
        adapter.write_and_verify_certificate_restore_temps(
            _ROOT,
            plan,
            created,
            local_ca_contents=_LOCAL,
            ca_bundle_contents=_BUNDLE,
        )
        == identities
    )
    assert api.files[_BUNDLE_PATH].contents == _BUNDLE


def test_native_certificate_temp_absence_never_creates_a_file() -> None:
    api = _Api()
    adapter = NativeWindowsCertificateRestoreTempStorage(api=api)

    identities = adapter.create_certificate_restore_temps(
        _ROOT,
        _plan(local=False, bundle=False),
    )

    assert identities.local_ca is None
    assert identities.ca_bundle is None
    assert api.files == {}
