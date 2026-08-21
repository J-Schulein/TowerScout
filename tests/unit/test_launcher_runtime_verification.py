from __future__ import annotations

import ast
import dataclasses
import hashlib
import inspect
import sys
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_identity as identity_module  # noqa: E402
import towerscout_launcher.runtime_verification as verification_module  # noqa: E402
from towerscout_launcher.authenticode import (  # noqa: E402
    NativeAuthenticodeFacts,
    NativeTrustStatus,
    SignerCertificateFacts,
    TimestampFacts,
    TimestampForm,
)
from towerscout_launcher.pe_version import PeVersionResource  # noqa: E402
from towerscout_launcher.runtime_policy import (  # noqa: E402
    RuntimeProductId,
    SignatureForm,
    load_package_bound_runtime_policy,
)
from towerscout_launcher.runtime_verification import (  # noqa: E402
    BoundRuntimeEvidence,
    CombinedRuntimeEvidence,
    RuntimeVerificationError,
    RuntimeVerificationErrorCode,
    combine_runtime_evidence,
    open_package_bound_runtime_evidence,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    StableFileIdentity,
)

_NOW = datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc)
_POLICY = load_package_bound_runtime_policy()
_SECRET = r"C:\Users\private-user\secret-runtime.exe"
_DOCKER_SYSTEM = (
    "HKEY_LOCAL_MACHINE",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop",
)
_DOCKER_USER = (
    "HKEY_CURRENT_USER",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop",
)
_DOCKER_PATH = r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"
_DOCKER_FINAL = r"\\?\C:\Program Files\Docker\Docker\resources\bin\docker.exe"
_PYTHON_SYSTEM = (
    "HKEY_LOCAL_MACHINE",
    r"SOFTWARE\Python\PythonCore\3.12",
)
_PYTHON_PATH = r"C:\Program Files\Python312\python.exe"
_PYTHON_FINAL = r"\\?\C:\Program Files\Python312\python.exe"


def _product(product_id: RuntimeProductId):  # noqa: ANN202
    return next(item for item in _POLICY.products if item.product_id is product_id)


def _native_facts(final_path: str, content: bytes) -> NativeFileFacts:
    return NativeFileFacts(
        final_path=final_path,
        volume_serial=0x0102030405060708,
        file_id=bytes.fromhex("00112233445566778899aabbccddeeff"),
        attributes=0x80,
        link_count=2,
        size=len(content),
        creation_time=100,
        last_write_time=200,
        drive_type=3,
        file_type=1,
        reparse_tag=0,
    )


class _FileApi:
    supported = True

    def __init__(
        self,
        *,
        final_path: str = _DOCKER_FINAL,
        content: bytes = b"signed-runtime",
    ) -> None:
        self.content = content
        self.facts = _native_facts(final_path, content)
        self.handle = object()
        self.cursor = 0
        self.opened: list[str] = []
        self.close_count = 0
        self.query_count = 0

    def open_file_for_identity(self, path: str) -> object:
        self.opened.append(path)
        return self.handle

    def query_file(self, handle: object) -> NativeFileFacts:
        assert handle is self.handle
        self.query_count += 1
        return replace(self.facts, size=len(self.content))

    def rewind_file(self, handle: object) -> None:
        assert handle is self.handle
        self.cursor = 0

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert handle is self.handle
        chunk = self.content[self.cursor : self.cursor + maximum]
        self.cursor += len(chunk)
        return chunk

    def close_handle(self, handle: object) -> None:
        assert handle is self.handle
        self.close_count += 1


class _InstallBackend:
    supported = True

    def __init__(self) -> None:
        self.records: dict[
            tuple[str, str], dict[tuple[str, str], str] | object | None
        ] = {}
        self.known_folders = {
            "local_app_data": r"C:\Users\reviewed-user\AppData\Local",
            "program_files": r"C:\Program Files",
        }
        self.calls: list[tuple[str, str, str, tuple[object, ...]]] = []
        self.on_read = None

    def read_string_values(
        self,
        *,
        hive: str,
        view: str,
        key: str,
        selectors: tuple[object, ...],
    ) -> object:
        from towerscout_launcher.runtime_identity import RegistryStringValues

        self.calls.append((hive, view, key, selectors))
        if self.on_read is not None:
            self.on_read(len(self.calls))
        record = self.records.get((hive, key))
        if record is None or not isinstance(record, dict):
            return record
        return RegistryStringValues(
            tuple(record[(item.subkey, item.name)] for item in selectors)
        )

    def known_folder_path(self, known_folder: str) -> str:
        return self.known_folders[known_folder]


class _PeBackend:
    supported = True

    def __init__(self, facts: object) -> None:
        self.facts = facts
        self.handles: list[object] = []
        self.snapshots: list[object] = []

    def inspect_open_file(self, *, handle: object, snapshot: object) -> object:
        self.handles.append(handle)
        self.snapshots.append(snapshot)
        return self.facts


class _AuthenticodeBackend:
    supported = True

    def __init__(self, facts: object, *, on_inspect=None) -> None:  # noqa: ANN001
        self.facts = facts
        self.on_inspect = on_inspect
        self.handles: list[object] = []
        self.snapshots: list[object] = []

    def inspect_open_file(self, *, handle: object, snapshot: object) -> object:
        self.handles.append(handle)
        self.snapshots.append(snapshot)
        if self.on_inspect is not None:
            self.on_inspect()
        return self.facts


class _Clock:
    def now_utc(self) -> datetime:
        return _NOW


def _docker_record(path: str = r"C:\Program Files\Docker\Docker") -> dict:
    return {
        ("", "DisplayName"): "Docker Desktop",
        ("", "Publisher"): "Docker Inc.",
        ("", "InstallLocation"): path,
    }


def _docker_pe() -> PeVersionResource:
    return PeVersionResource(
        company_name="Docker Inc",
        product_name="Docker Client",
        original_filename="docker-windows-amd64.exe",
        file_version="29.7.2",
        product_version="29.7.2",
        fixed_file_version=(29, 7, 2, 17),
        fixed_product_version=(29, 7, 2, 19),
        translations=((0x0409, 0x04B0),),
        resource_sha256="7" * 64,
    )


def _python_record() -> dict:
    return {
        ("", "DisplayName"): "Python 3.12.10",
        ("", "SysArchitecture"): "64bit",
        ("", "Version"): "3.12.10",
        ("InstallPath", "ExecutablePath"): _PYTHON_PATH,
    }


def _python_pe() -> PeVersionResource:
    return PeVersionResource(
        company_name="Python Software Foundation",
        product_name="Python",
        original_filename="python.exe",
        file_version="3.12.10",
        product_version="3.12.10",
        fixed_file_version=(3, 12, 10, 0),
        fixed_product_version=(3, 12, 10, 0),
        translations=((0x0409, 0x04B0),),
        resource_sha256="8" * 64,
    )


def _signer(product_id: RuntimeProductId) -> SignerCertificateFacts:
    approved = _product(product_id).signers[0]
    return SignerCertificateFacts(
        certificate_sha256=approved.certificate_sha256,
        subject_common_name=approved.subject_common_name,
        subject_organization=approved.subject_organization,
        issuer_common_name=approved.issuer_common_name,
        serial_number=approved.serial_number,
        not_before_utc=approved.not_before_utc,
        not_after_utc=approved.not_after_utc,
        public_key_algorithm=approved.public_key_algorithm,
        public_key_bits=approved.minimum_public_key_bits,
        code_signing_eku=True,
    )


def _trusted_timestamp() -> TimestampFacts:
    return TimestampFacts(
        form=TimestampForm.RFC3161,
        token_sha256="3" * 64,
        signing_time_utc="2025-04-09T12:00:00Z",
        digest_algorithm="sha256",
        signature_algorithm="rsa_pkcs1v15",
        primary_signature_valid=True,
        chain_status=NativeTrustStatus.TRUSTED,
        chain_sha256="4" * 64,
    )


def _authenticode_facts(
    product_id: RuntimeProductId = RuntimeProductId.DOCKER_CLI,
) -> NativeAuthenticodeFacts:
    timestamps = (
        (_trusted_timestamp(),) if product_id is RuntimeProductId.CPYTHON else ()
    )
    return NativeAuthenticodeFacts(
        signature_form=SignatureForm.EMBEDDED_AUTHENTICODE,
        certificate_table_entry_count=1,
        primary_signer_count=1,
        secondary_signature_count=0,
        nested_signature_count=0,
        legacy_countersignature_count=0,
        embedded_signature_sha256="5" * 64,
        file_digest_algorithm="sha256",
        signer_signature_algorithm="rsa_pkcs1v15",
        wintrust_status=0,
        signer_chain_status=NativeTrustStatus.TRUSTED,
        signer_chain_sha256="6" * 64,
        signer=_signer(product_id),
        timestamps=timestamps,
    )


def _open_docker(
    *,
    auth_product: RuntimeProductId = RuntimeProductId.DOCKER_CLI,
    auth_on_inspect=None,  # noqa: ANN001
) -> tuple[
    BoundRuntimeEvidence,
    _InstallBackend,
    _FileApi,
    _PeBackend,
    _AuthenticodeBackend,
]:
    installation = _InstallBackend()
    installation.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()
    pe = _PeBackend(_docker_pe())
    authenticode = _AuthenticodeBackend(
        _authenticode_facts(auth_product), on_inspect=auth_on_inspect
    )
    result = open_package_bound_runtime_evidence(
        RuntimeProductId.DOCKER_CLI,
        installation_backend=installation,  # type: ignore[arg-type]
        file_api=api,
        pe_backend=pe,  # type: ignore[arg-type]
        authenticode_backend=authenticode,  # type: ignore[arg-type]
        clock=_Clock(),
    )
    return result, installation, api, pe, authenticode


def test_combines_install_pe_and_authenticode_over_one_retained_handle() -> None:
    result, installation, api, pe, authenticode = _open_docker()

    assert isinstance(result, BoundRuntimeEvidence)
    assert not result.closed
    assert api.opened == [_DOCKER_PATH]
    assert api.close_count == 0
    assert pe.handles == [api.handle]
    assert authenticode.handles == [api.handle]
    assert pe.snapshots == authenticode.snapshots
    assert len(installation.calls) == 6
    assert api.query_count == 12

    evidence = result.evidence
    assert isinstance(evidence, CombinedRuntimeEvidence)
    assert evidence.product_id is RuntimeProductId.DOCKER_CLI
    assert evidence.exact_version == "29.7.2"
    assert evidence.policy_sha256 == _POLICY.content_sha256
    assert evidence.file_sha256 == hashlib.sha256(b"signed-runtime").hexdigest()
    assert evidence.authenticode.signer_policy_product_ids == (
        RuntimeProductId.DOCKER_CLI,
        RuntimeProductId.DOCKER_COMPOSE,
    )
    assert evidence.installation.file_identity == evidence.pe_product.file_identity
    assert evidence.pe_product.file_identity == evidence.authenticode.file_identity

    assert result.assert_unchanged() is evidence
    assert len(installation.calls) == 8
    assert api.query_count == 14
    result.close()
    result.close()
    assert result.closed
    assert api.close_count == 1


def test_combines_cpython_pe_product_with_its_timestamped_signer() -> None:
    installation = _InstallBackend()
    installation.records[_PYTHON_SYSTEM] = _python_record()
    api = _FileApi(final_path=_PYTHON_FINAL)
    pe = _PeBackend(_python_pe())
    authenticode = _AuthenticodeBackend(_authenticode_facts(RuntimeProductId.CPYTHON))

    with open_package_bound_runtime_evidence(
        RuntimeProductId.CPYTHON,
        installation_backend=installation,  # type: ignore[arg-type]
        file_api=api,
        pe_backend=pe,  # type: ignore[arg-type]
        authenticode_backend=authenticode,  # type: ignore[arg-type]
        clock=_Clock(),
    ) as result:
        assert result.evidence.product_id is RuntimeProductId.CPYTHON
        assert result.evidence.exact_version == "3.12.10"
        assert result.evidence.authenticode.signer_policy_product_ids == (
            RuntimeProductId.CPYTHON,
        )
        assert result.evidence.authenticode.timestamp_time_utc == (
            "2025-04-09T12:00:00Z"
        )
        assert pe.handles == authenticode.handles == [api.handle]

    assert api.opened == [_PYTHON_PATH]
    assert api.close_count == 1


@pytest.mark.parametrize("component", ("installation", "pe_product", "authenticode"))
@pytest.mark.parametrize(
    "field",
    ("policy_sha256", "identity_volume", "identity_file", "file_sha256"),
)
def test_combiner_rejects_every_cross_evidence_binding_mismatch(
    component: str,
    field: str,
) -> None:
    result, _installation, _api, _pe, _authenticode = _open_docker()
    baseline = result.evidence
    result.close()
    values = {
        "installation": baseline.installation,
        "pe_product": baseline.pe_product,
        "authenticode": baseline.authenticode,
    }
    selected = values[component]
    if field == "identity_volume":
        replacement = replace(
            selected,
            file_identity=StableFileIdentity(
                selected.file_identity.volume_serial + 1,
                selected.file_identity.file_id,
            ),
        )
    elif field == "identity_file":
        replacement = replace(
            selected,
            file_identity=StableFileIdentity(
                selected.file_identity.volume_serial,
                bytes.fromhex("ffeeddccbbaa99887766554433221100"),
            ),
        )
    else:
        replacement = replace(selected, **{field: "a" * 64})
    values[component] = replacement

    with pytest.raises(RuntimeVerificationError) as exc_info:
        combine_runtime_evidence(
            values["installation"],
            values["pe_product"],
            values["authenticode"],
        )

    assert exc_info.value.code is RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID


def test_combiner_requires_nomination_and_pe_product_to_match() -> None:
    result, _installation, _api, _pe, _authenticode = _open_docker()
    baseline = result.evidence
    result.close()

    with pytest.raises(RuntimeVerificationError) as exc_info:
        combine_runtime_evidence(
            replace(
                baseline.installation,
                product_id=RuntimeProductId.CPYTHON,
            ),
            baseline.pe_product,
            baseline.authenticode,
        )

    assert exc_info.value.code is RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID


@pytest.mark.parametrize("component", ("installation", "pe_product", "authenticode"))
def test_combiner_rejects_component_type_confusion(component: str) -> None:
    result, _installation, _api, _pe, _authenticode = _open_docker()
    baseline = result.evidence
    result.close()
    values: dict[str, object] = {
        "installation": baseline.installation,
        "pe_product": baseline.pe_product,
        "authenticode": baseline.authenticode,
    }
    values[component] = object()

    with pytest.raises(RuntimeVerificationError) as exc_info:
        combine_runtime_evidence(
            values["installation"],  # type: ignore[arg-type]
            values["pe_product"],  # type: ignore[arg-type]
            values["authenticode"],  # type: ignore[arg-type]
        )

    assert exc_info.value.code is RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID


def test_derived_product_must_belong_to_signer_policy_overlap_and_closes() -> None:
    installation = _InstallBackend()
    installation.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()

    with pytest.raises(RuntimeVerificationError) as exc_info:
        open_package_bound_runtime_evidence(
            RuntimeProductId.DOCKER_CLI,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            pe_backend=_PeBackend(_docker_pe()),  # type: ignore[arg-type]
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts(RuntimeProductId.CPYTHON)
            ),  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert exc_info.value.code is RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID
    assert api.close_count == 1


def test_authenticode_unavailability_closes_the_retained_candidate() -> None:
    installation = _InstallBackend()
    installation.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()
    authenticode = _AuthenticodeBackend(_authenticode_facts())
    authenticode.supported = False

    with pytest.raises(RuntimeVerificationError) as exc_info:
        open_package_bound_runtime_evidence(
            RuntimeProductId.DOCKER_CLI,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            pe_backend=_PeBackend(_docker_pe()),  # type: ignore[arg-type]
            authenticode_backend=authenticode,  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert exc_info.value.code is RuntimeVerificationErrorCode.VERIFICATION_UNAVAILABLE
    assert api.close_count == 1


def test_final_installation_record_revalidation_occurs_after_authenticode() -> None:
    installation = _InstallBackend()
    installation.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()

    def add_late_record() -> None:
        installation.records[_DOCKER_USER] = _docker_record()

    with pytest.raises(RuntimeVerificationError) as exc_info:
        open_package_bound_runtime_evidence(
            RuntimeProductId.DOCKER_CLI,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            pe_backend=_PeBackend(_docker_pe()),  # type: ignore[arg-type]
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts(), on_inspect=add_late_record
            ),  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert exc_info.value.code is RuntimeVerificationErrorCode.RUNTIME_REPLACED
    assert len(installation.calls) == 6
    assert api.close_count == 1


def test_final_held_file_revalidation_occurs_after_component_verifiers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installation = _InstallBackend()
    installation.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()
    real_verifier = verification_module.verify_package_bound_authenticode_signer

    def verify_then_replace(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        evidence = real_verifier(*args, **kwargs)
        api.content = b"SIGNED-RUNTIME"
        return evidence

    monkeypatch.setattr(
        verification_module,
        "verify_package_bound_authenticode_signer",
        verify_then_replace,
    )

    with pytest.raises(RuntimeVerificationError) as exc_info:
        open_package_bound_runtime_evidence(
            RuntimeProductId.DOCKER_CLI,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            pe_backend=_PeBackend(_docker_pe()),  # type: ignore[arg-type]
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts()
            ),  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert exc_info.value.code is RuntimeVerificationErrorCode.RUNTIME_REPLACED
    assert api.close_count == 1


def test_combined_evidence_mismatch_from_verifier_closes_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installation = _InstallBackend()
    installation.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()
    real_verifier = verification_module.verify_package_bound_pe_product

    def mismatched_policy(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        return replace(real_verifier(*args, **kwargs), policy_sha256="a" * 64)

    monkeypatch.setattr(
        verification_module,
        "verify_package_bound_pe_product",
        mismatched_policy,
    )

    with pytest.raises(RuntimeVerificationError) as exc_info:
        open_package_bound_runtime_evidence(
            RuntimeProductId.DOCKER_CLI,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            pe_backend=_PeBackend(_docker_pe()),  # type: ignore[arg-type]
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts()
            ),  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert exc_info.value.code is RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID
    assert api.close_count == 1


def test_interruption_closes_candidate_before_propagating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installation = _InstallBackend()
    installation.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()

    def interrupt(*_args, **_kwargs) -> None:  # noqa: ANN002, ANN003
        raise KeyboardInterrupt

    monkeypatch.setattr(
        verification_module,
        "verify_package_bound_pe_product",
        interrupt,
    )

    with pytest.raises(KeyboardInterrupt):
        open_package_bound_runtime_evidence(
            RuntimeProductId.DOCKER_CLI,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            pe_backend=_PeBackend(_docker_pe()),  # type: ignore[arg-type]
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts()
            ),  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert api.close_count == 1


def test_interruption_during_initial_snapshot_closes_the_open_handle() -> None:
    class _InterruptedCaptureApi(_FileApi):
        def query_file(self, handle: object) -> NativeFileFacts:
            assert handle is self.handle
            raise KeyboardInterrupt

    installation = _InstallBackend()
    installation.records[_DOCKER_SYSTEM] = _docker_record()
    api = _InterruptedCaptureApi()

    with pytest.raises(KeyboardInterrupt):
        open_package_bound_runtime_evidence(
            RuntimeProductId.DOCKER_CLI,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            pe_backend=_PeBackend(_docker_pe()),  # type: ignore[arg-type]
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts()
            ),  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert api.opened == [_DOCKER_PATH]
    assert api.close_count == 1


def test_interruption_after_one_held_install_candidate_closes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installation = _InstallBackend()
    installation.records[_DOCKER_SYSTEM] = _docker_record()
    installation.records[_DOCKER_USER] = _docker_record()
    api = _FileApi()
    real_capture = identity_module.capture_handle_bound_file
    capture_count = 0

    def interrupt_second_capture(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        nonlocal capture_count
        capture_count += 1
        if capture_count == 2:
            raise KeyboardInterrupt
        return real_capture(*args, **kwargs)

    monkeypatch.setattr(
        identity_module,
        "capture_handle_bound_file",
        interrupt_second_capture,
    )

    with pytest.raises(KeyboardInterrupt):
        open_package_bound_runtime_evidence(
            RuntimeProductId.DOCKER_CLI,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            pe_backend=_PeBackend(_docker_pe()),  # type: ignore[arg-type]
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts()
            ),  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert capture_count == 2
    assert api.opened == [_DOCKER_PATH]
    assert api.close_count == 1


def test_interruption_during_installation_rescan_closes_all_held_files() -> None:
    installation = _InstallBackend()
    installation.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()

    def interrupt_final_scan(call_count: int) -> None:
        if call_count == 3:
            raise KeyboardInterrupt

    installation.on_read = interrupt_final_scan

    with pytest.raises(KeyboardInterrupt):
        open_package_bound_runtime_evidence(
            RuntimeProductId.DOCKER_CLI,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            pe_backend=_PeBackend(_docker_pe()),  # type: ignore[arg-type]
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts()
            ),  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert len(installation.calls) == 3
    assert api.close_count == 1


def test_combined_owner_serializes_final_use_against_close() -> None:
    result, installation, api, _pe, _authenticode = _open_docker()
    revalidation_inside = threading.Event()
    release_revalidation = threading.Event()
    close_started = threading.Event()
    close_returned = threading.Event()
    failures: list[BaseException] = []

    def block_first_read(_count: int) -> None:
        if revalidation_inside.is_set():
            return
        revalidation_inside.set()
        if not release_revalidation.wait(timeout=2):
            raise AssertionError("Revalidation was not released.")

    installation.on_read = block_first_read

    def revalidate() -> None:
        try:
            assert result.assert_unchanged() is result.evidence
        except BaseException as error:  # pragma: no cover - thread handoff
            failures.append(error)

    def close() -> None:
        close_started.set()
        try:
            result.close()
            close_returned.set()
        except BaseException as error:  # pragma: no cover - thread handoff
            failures.append(error)

    verifier = threading.Thread(target=revalidate)
    closer = threading.Thread(target=close)
    verifier.start()
    assert revalidation_inside.wait(timeout=2)
    closer.start()
    assert close_started.wait(timeout=2)
    assert not close_returned.wait(timeout=0.1)
    assert api.close_count == 0

    release_revalidation.set()
    verifier.join(timeout=2)
    closer.join(timeout=2)

    assert not verifier.is_alive()
    assert not closer.is_alive()
    assert failures == []
    assert close_returned.is_set()
    assert result.closed
    assert api.close_count == 1


def test_closed_combined_owner_never_reopens_or_revalidates() -> None:
    result, _installation, api, _pe, _authenticode = _open_docker()
    result.close()

    with pytest.raises(RuntimeVerificationError) as exc_info:
        result.assert_unchanged()

    assert exc_info.value.code is RuntimeVerificationErrorCode.RUNTIME_REPLACED
    assert api.opened == [_DOCKER_PATH]
    assert api.close_count == 1


def test_combined_owner_context_exit_closes_on_exception() -> None:
    result, _installation, api, _pe, _authenticode = _open_docker()

    with pytest.raises(RuntimeError):
        with result:
            raise RuntimeError("bounded-test-failure")

    assert result.closed
    assert api.close_count == 1


def test_combined_evidence_is_immutable_redacted_and_digest_bound() -> None:
    result, _installation, _api, _pe, _authenticode = _open_docker()
    baseline = result.evidence
    result.close()
    changed = combine_runtime_evidence(
        replace(
            baseline.installation,
            resolution_sha256="8" * 64,
        ),
        baseline.pe_product,
        baseline.authenticode,
    )

    assert changed.evidence_sha256 != baseline.evidence_sha256
    assert _SECRET not in repr(baseline)
    assert baseline.file_sha256 not in repr(baseline)
    assert baseline.file_identity.file_id.hex() not in repr(baseline)
    with pytest.raises(dataclasses.FrozenInstanceError):
        baseline.file_sha256 = "a" * 64  # type: ignore[misc]
    with pytest.raises((TypeError, ValueError)):
        replace(baseline, evidence_sha256="a" * 64)


def test_combined_result_has_only_non_executable_public_surface() -> None:
    result, _installation, _api, _pe, _authenticode = _open_docker()
    try:
        assert {name for name in dir(result) if not name.startswith("_")} == {
            "assert_unchanged",
            "close",
            "closed",
            "evidence",
        }
        for forbidden in (
            "argv",
            "bound_file",
            "command",
            "execute",
            "handle",
            "path",
            "run",
            "runtime_identity",
        ):
            assert not hasattr(result, forbidden)
    finally:
        result.close()


@pytest.mark.parametrize(
    "product_id",
    (RuntimeProductId.DOCKER_COMPOSE, RuntimeProductId.PODMAN_CLI),
)
def test_command_version_products_remain_deferred_without_open_or_execution(
    product_id: RuntimeProductId,
) -> None:
    installation = _InstallBackend()
    api = _FileApi()
    pe = _PeBackend(_docker_pe())
    authenticode = _AuthenticodeBackend(_authenticode_facts())

    with pytest.raises(RuntimeVerificationError) as exc_info:
        open_package_bound_runtime_evidence(
            product_id,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            pe_backend=pe,  # type: ignore[arg-type]
            authenticode_backend=authenticode,  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert exc_info.value.code is RuntimeVerificationErrorCode.VERIFICATION_UNAVAILABLE
    assert installation.calls == []
    assert api.opened == []
    assert pe.handles == []
    assert authenticode.handles == []


def test_factory_accepts_only_closed_product_id_not_path_or_command() -> None:
    parameters = inspect.signature(open_package_bound_runtime_evidence).parameters

    assert tuple(parameters) == (
        "product_id",
        "installation_backend",
        "file_api",
        "pe_backend",
        "authenticode_backend",
        "clock",
    )
    assert parameters["product_id"].annotation in {
        RuntimeProductId,
        "RuntimeProductId",
    }
    assert not any(
        name in parameters for name in ("argv", "command", "executable", "name", "path")
    )


def test_combiner_module_is_inert_and_unwired() -> None:
    source_path = Path(verification_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    imported_modules = {
        component
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
        for component in node.module.split(".")
    } | {
        component
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        for component in alias.name.split(".")
    }
    forbidden_imports = {
        "app",
        "discovery",
        "repair",
        "runtime_execution",
        "subprocess",
        "target_contracts",
    }

    assert imported_modules.isdisjoint(forbidden_imports)
    assert "subprocess" not in source
    assert "RuntimeIdentity" not in imported_names
    for relative in (
        "launcher/towerscout_launcher/app.py",
        "launcher/towerscout_launcher/discovery.py",
        "launcher/towerscout_launcher/repair.py",
        "launcher/towerscout_launcher/runtime_execution.py",
    ):
        live_source = (ROOT / relative).read_text(encoding="utf-8")
        assert "runtime_verification" not in live_source


def test_verification_errors_are_sanitized_and_redacted() -> None:
    installation = _InstallBackend()
    installation.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()
    backend = _PeBackend(OSError(_SECRET))

    with pytest.raises(RuntimeVerificationError) as exc_info:
        open_package_bound_runtime_evidence(
            RuntimeProductId.DOCKER_CLI,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            pe_backend=backend,  # type: ignore[arg-type]
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts()
            ),  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert _SECRET not in str(exc_info.value)
    assert _SECRET not in repr(exc_info.value)
    assert api.close_count == 1
