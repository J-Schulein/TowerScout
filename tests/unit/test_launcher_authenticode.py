from __future__ import annotations

import dataclasses
import os
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.authenticode import (  # noqa: E402
    AuthenticodeErrorCode,
    AuthenticodeVerificationError,
    NativeAuthenticodeFacts,
    NativeTrustStatus,
    SignerCertificateFacts,
    TimestampFacts,
    TimestampForm,
    VerifiedAuthenticodeEvidence,
    verify_package_bound_authenticode_signer,
)
from towerscout_launcher.runtime_policy import (  # noqa: E402
    RuntimeProductId,
    SignatureForm,
    load_package_bound_runtime_policy,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    StableFileIdentity,
    capture_handle_bound_file,
)

_NOW = datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc)
_SECRET = r"\\?\C:\Users\private-user\secret-runtime.exe"
_POLICY = load_package_bound_runtime_policy()


def _product(product_id: RuntimeProductId):  # noqa: ANN202
    return next(item for item in _POLICY.products if item.product_id is product_id)


def _native_file_facts(size: int) -> NativeFileFacts:
    return NativeFileFacts(
        final_path=_SECRET,
        volume_serial=0x0102030405060708,
        file_id=bytes.fromhex("00112233445566778899aabbccddeeff"),
        attributes=0x80,
        link_count=1,
        size=size,
        creation_time=100,
        last_write_time=200,
        drive_type=3,
        file_type=1,
        reparse_tag=0,
    )


class _FileApi:
    supported = True

    def __init__(self, content: bytes = b"signed-runtime") -> None:
        self.content = content
        self.handle = object()
        self.cursor = 0
        self.closed = False

    def open_file_for_identity(self, path: str) -> object:
        assert path == os.fspath(Path("runtime.exe"))
        return self.handle

    def query_file(self, handle: object) -> NativeFileFacts:
        assert handle is self.handle
        return _native_file_facts(len(self.content))

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
        self.closed = True


class _Clock:
    def __init__(self, now: object = _NOW) -> None:
        self.now = now

    def now_utc(self) -> datetime:
        return self.now  # type: ignore[return-value]


class _ExplodingTimezone(tzinfo):
    def utcoffset(self, _value: datetime | None) -> timedelta | None:
        raise OSError(_SECRET)

    def dst(self, _value: datetime | None) -> timedelta | None:
        return None

    def tzname(self, _value: datetime | None) -> str | None:
        return "invalid"


class _Backend:
    def __init__(
        self,
        facts: object,
        *,
        supported: object = True,
        failure: Exception | None = None,
        on_inspect=None,  # noqa: ANN001
    ) -> None:
        self.facts = facts
        self._supported = supported
        self.failure = failure
        self.on_inspect = on_inspect
        self.handles: list[object] = []
        self.snapshots: list[object] = []

    @property
    def supported(self) -> bool:
        return self._supported  # type: ignore[return-value]

    def inspect_open_file(self, *, handle: object, snapshot: object) -> object:
        self.handles.append(handle)
        self.snapshots.append(snapshot)
        if self.on_inspect is not None:
            self.on_inspect()
        if self.failure is not None:
            raise self.failure
        return self.facts


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


def _timestamp(
    *,
    signing_time: str = "2025-01-02T03:04:05Z",
    form: TimestampForm = TimestampForm.RFC3161,
    digest_algorithm: str = "sha256",
    signature_algorithm: str = "rsa_pkcs1v15",
    primary_signature_valid: bool = True,
    chain_status: NativeTrustStatus = NativeTrustStatus.TRUSTED,
) -> TimestampFacts:
    return TimestampFacts(
        form=form,
        token_sha256="3" * 64,
        signing_time_utc=signing_time,
        digest_algorithm=digest_algorithm,
        signature_algorithm=signature_algorithm,
        primary_signature_valid=primary_signature_valid,
        chain_status=chain_status,
        chain_sha256="4" * 64,
    )


def _facts(
    product_id: RuntimeProductId = RuntimeProductId.DOCKER_CLI,
    *,
    signer: SignerCertificateFacts | None = None,
    timestamps: tuple[TimestampFacts, ...] = (),
    **changes: object,
) -> NativeAuthenticodeFacts:
    values: dict[str, object] = {
        "signature_form": SignatureForm.EMBEDDED_AUTHENTICODE,
        "certificate_table_entry_count": 1,
        "primary_signer_count": 1,
        "secondary_signature_count": 0,
        "nested_signature_count": 0,
        "legacy_countersignature_count": 0,
        "embedded_signature_sha256": "5" * 64,
        "file_digest_algorithm": "sha256",
        "signer_signature_algorithm": "rsa_pkcs1v15",
        "wintrust_status": 0,
        "signer_chain_status": NativeTrustStatus.TRUSTED,
        "signer_chain_sha256": "6" * 64,
        "signer": signer or _signer(product_id),
        "timestamps": timestamps,
    }
    values.update(changes)
    return NativeAuthenticodeFacts(**values)  # type: ignore[arg-type]


def _verify(
    facts: object,
    *,
    api: _FileApi | None = None,
    backend: _Backend | None = None,
    clock: _Clock | None = None,
) -> tuple[VerifiedAuthenticodeEvidence, _FileApi, _Backend]:
    selected_api = api or _FileApi()
    selected_backend = backend or _Backend(facts)
    with capture_handle_bound_file(Path("runtime.exe"), api=selected_api) as bound:
        evidence = verify_package_bound_authenticode_signer(
            bound,
            backend=selected_backend,  # type: ignore[arg-type]
            clock=clock or _Clock(),
        )
        assert selected_backend.handles == [selected_api.handle]
        assert selected_backend.snapshots == [bound.snapshot]
        assert not bound.closed
    return evidence, selected_api, selected_backend


def _reject(
    facts: object,
    *,
    backend: _Backend | None = None,
    clock: _Clock | None = None,
) -> AuthenticodeVerificationError:
    api = _FileApi()
    selected_backend = backend or _Backend(facts)
    with capture_handle_bound_file(Path("runtime.exe"), api=api) as bound:
        with pytest.raises(AuthenticodeVerificationError) as exc_info:
            verify_package_bound_authenticode_signer(
                bound,
                backend=selected_backend,  # type: ignore[arg-type]
                clock=clock or _Clock(),
            )
    assert _SECRET not in str(exc_info.value)
    assert _SECRET not in repr(exc_info.value)
    return exc_info.value


def test_docker_shared_signer_returns_explicit_compatible_policy_set() -> None:
    evidence, api, _backend = _verify(_facts())

    assert evidence.signer_policy_product_ids == (
        RuntimeProductId.DOCKER_CLI,
        RuntimeProductId.DOCKER_COMPOSE,
    )
    assert not hasattr(evidence, "product_id")
    assert evidence.policy_sha256 == _POLICY.content_sha256
    assert evidence.file_identity.file_id == bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )
    assert evidence.timestamp_token_sha256 is None
    assert len(evidence.evidence_sha256) == 64
    assert api.closed
    rendered = repr(evidence)
    assert "docker-cli" not in rendered
    assert "docker-compose" not in rendered
    assert "private-user" not in rendered
    assert evidence.file_sha256 not in rendered
    assert evidence.signer_certificate_sha256 not in rendered
    with pytest.raises(dataclasses.FrozenInstanceError):
        evidence.file_sha256 = "0" * 64  # type: ignore[misc]


def test_verifier_has_no_caller_product_label_parameter() -> None:
    api = _FileApi()
    backend = _Backend(_facts())
    with capture_handle_bound_file(Path("runtime.exe"), api=api) as bound:
        with pytest.raises(TypeError):
            verify_package_bound_authenticode_signer(
                bound,
                RuntimeProductId.DOCKER_CLI,  # type: ignore[misc]
                backend=backend,
                clock=_Clock(),
            )
        with pytest.raises(TypeError):
            verify_package_bound_authenticode_signer(
                bound,
                product_id=RuntimeProductId.DOCKER_COMPOSE,  # type: ignore[call-arg]
                backend=backend,
                clock=_Clock(),
            )

    assert backend.handles == []


def test_expired_podman_requires_and_accepts_one_trusted_timestamp() -> None:
    facts = _facts(
        RuntimeProductId.PODMAN_CLI,
        timestamps=(_timestamp(signing_time="2025-01-02T03:04:05Z"),),
    )
    evidence, _api, _backend = _verify(facts)

    assert evidence.signer_policy_product_ids == (RuntimeProductId.PODMAN_CLI,)
    assert evidence.timestamp_token_sha256 == "3" * 64
    assert evidence.timestamp_chain_sha256 == "4" * 64
    assert evidence.timestamp_time_utc == "2025-01-02T03:04:05Z"


def test_cpython_signer_matches_only_cpython_policy() -> None:
    facts = _facts(
        RuntimeProductId.CPYTHON,
        timestamps=(_timestamp(signing_time="2025-04-09T12:00:00Z"),),
    )

    evidence, _api, _backend = _verify(facts)

    assert evidence.signer_policy_product_ids == (RuntimeProductId.CPYTHON,)


@pytest.mark.parametrize(
    "compatible_products",
    (
        (),
        [RuntimeProductId.DOCKER_CLI],
        (RuntimeProductId.DOCKER_CLI, RuntimeProductId.DOCKER_CLI),
        (RuntimeProductId.DOCKER_COMPOSE, RuntimeProductId.DOCKER_CLI),
    ),
)
def test_signer_policy_compatibility_set_must_be_canonical_and_unambiguous(
    compatible_products: object,
) -> None:
    evidence, _api, _backend = _verify(_facts())

    with pytest.raises(ValueError):
        replace(evidence, signer_policy_product_ids=compatible_products)


def test_expired_signer_without_timestamp_fails_closed() -> None:
    error = _reject(_facts(RuntimeProductId.PODMAN_CLI))
    assert error.code is AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID


@pytest.mark.parametrize("status", (-2146762496, -1, 1, 7, 2**31 - 1))
def test_only_exact_zero_wintrust_status_is_success(status: int) -> None:
    error = _reject(_facts(wintrust_status=status))
    assert error.code is AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("certificate_table_entry_count", 0),
        ("certificate_table_entry_count", 2),
        ("primary_signer_count", 0),
        ("primary_signer_count", 2),
        ("secondary_signature_count", 1),
        ("nested_signature_count", 1),
        ("legacy_countersignature_count", 1),
        ("file_digest_algorithm", "sha1"),
        ("signer_signature_algorithm", "rsa_pss"),
    ),
)
def test_signature_cardinality_and_algorithm_drift_fail_closed(
    field: str, value: object
) -> None:
    _reject(_facts(**{field: value}))


@pytest.mark.parametrize(
    "status",
    (
        NativeTrustStatus.REVOKED,
        NativeTrustStatus.OFFLINE,
        NativeTrustStatus.UNKNOWN,
        NativeTrustStatus.UNTRUSTED,
    ),
)
def test_every_nontrusted_signer_chain_disposition_fails_closed(
    status: NativeTrustStatus,
) -> None:
    _reject(_facts(signer_chain_status=status))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("certificate_sha256", "7" * 64),
        ("subject_common_name", "docker inc"),
        ("subject_organization", "Docker Inc "),
        ("issuer_common_name", "Unreviewed Issuer"),
        ("serial_number", "00"),
        ("not_before_utc", "2026-06-27T00:00:00Z"),
        ("not_after_utc", "2027-06-24T23:59:59Z"),
        ("public_key_algorithm", "ecdsa"),
        ("public_key_bits", 2048),
        ("code_signing_eku", False),
    ),
)
def test_reviewed_primary_signer_identity_is_exact(field: str, value: object) -> None:
    signer = replace(_signer(RuntimeProductId.DOCKER_CLI), **{field: value})
    _reject(_facts(signer=signer))


@pytest.mark.parametrize(
    "timestamp",
    (
        _timestamp(form=TimestampForm.LEGACY_COUNTERSIGNATURE),
        _timestamp(form=TimestampForm.UNKNOWN),
        _timestamp(digest_algorithm="sha1"),
        _timestamp(signature_algorithm="rsa_pss"),
        _timestamp(primary_signature_valid=False),
        _timestamp(chain_status=NativeTrustStatus.REVOKED),
        _timestamp(chain_status=NativeTrustStatus.OFFLINE),
        _timestamp(chain_status=NativeTrustStatus.UNKNOWN),
        _timestamp(chain_status=NativeTrustStatus.UNTRUSTED),
        _timestamp(signing_time="2023-01-01T00:00:00Z"),
        _timestamp(signing_time="2026-08-08T00:00:00Z"),
        _timestamp(signing_time="2026-08-22T00:00:00Z"),
    ),
)
def test_unreviewed_or_invalid_timestamp_fails_closed(
    timestamp: TimestampFacts,
) -> None:
    facts = _facts(RuntimeProductId.PODMAN_CLI, timestamps=(timestamp,))
    _reject(facts)


def test_multiple_timestamps_fail_even_when_signer_is_current() -> None:
    _reject(_facts(timestamps=(_timestamp(), _timestamp())))


def test_timestamp_validity_boundaries_are_inclusive() -> None:
    product = _product(RuntimeProductId.PODMAN_CLI)
    for timestamp_time in (
        product.signers[0].not_before_utc,
        product.signers[0].not_after_utc,
    ):
        facts = _facts(
            RuntimeProductId.PODMAN_CLI,
            timestamps=(_timestamp(signing_time=timestamp_time),),
        )
        _verify(facts)


def test_not_yet_valid_signer_fails_even_with_timestamp() -> None:
    _reject(
        _facts(timestamps=(_timestamp(signing_time="2026-06-26T00:00:00Z"),)),
        clock=_Clock(datetime(2026, 6, 25, tzinfo=timezone.utc)),
    )


@pytest.mark.parametrize("supported", (False, None, 1, "yes"))
def test_unsupported_or_non_boolean_backend_support_fails_closed(
    supported: object,
) -> None:
    backend = _Backend(_facts(), supported=supported)
    error = _reject(_facts(), backend=backend)
    assert error.code is AuthenticodeErrorCode.VERIFICATION_UNAVAILABLE
    assert backend.handles == []


def test_backend_raw_exception_is_sanitized() -> None:
    backend = _Backend(_facts(), failure=OSError(_SECRET))
    error = _reject(_facts(), backend=backend)
    assert error.code is AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID
    assert _SECRET not in str(error)
    assert _SECRET not in repr(error)


def test_backend_must_return_exact_immutable_facts_type() -> None:
    error = _reject(object())
    assert error.code is AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID


def test_post_inspection_same_handle_replacement_fails_closed() -> None:
    api = _FileApi(b"signed-runtime")
    backend = _Backend(
        _facts(),
        on_inspect=lambda: setattr(api, "content", b"SIGNED-RUNTIME"),
    )
    with capture_handle_bound_file(Path("runtime.exe"), api=api) as bound:
        with pytest.raises(AuthenticodeVerificationError) as exc_info:
            verify_package_bound_authenticode_signer(
                bound,
                backend=backend,
                clock=_Clock(),
            )
    assert exc_info.value.code is AuthenticodeErrorCode.RUNTIME_REPLACED


@pytest.mark.parametrize(
    "bad_now",
    (
        "2026-08-21T12:00:00Z",
        datetime(2026, 8, 21, 12, 0, 0),
        None,
    ),
)
def test_clock_must_return_aware_utc_datetime(bad_now: object) -> None:
    error = _reject(_facts(), clock=_Clock(bad_now))
    assert error.code is AuthenticodeErrorCode.VERIFICATION_UNAVAILABLE


def test_clock_timezone_failure_is_sanitized() -> None:
    bad_now = datetime(2026, 8, 21, 12, 0, 0, tzinfo=_ExplodingTimezone())

    error = _reject(_facts(), clock=_Clock(bad_now))

    assert error.code is AuthenticodeErrorCode.VERIFICATION_UNAVAILABLE
    assert _SECRET not in str(error)


def test_evidence_digest_binds_file_content() -> None:
    first, _api, _backend = _verify(_facts(), api=_FileApi(b"signed-runtime"))
    second, _api, _backend = _verify(_facts(), api=_FileApi(b"SIGNED-RUNTIME"))
    assert first.file_sha256 != second.file_sha256
    assert first.evidence_sha256 != second.evidence_sha256


@pytest.mark.parametrize(
    "mutation",
    (
        {"signer_policy_product_ids": (RuntimeProductId.PODMAN_CLI,)},
        {"policy_sha256": "0" * 64},
        {
            "file_identity": StableFileIdentity(
                0x1112131415161718,
                bytes.fromhex("ffeeddccbbaa99887766554433221100"),
            )
        },
        {"file_sha256": "1" * 64},
        {"signer_certificate_sha256": "2" * 64},
        {"signer_chain_sha256": "7" * 64},
        {"embedded_signature_sha256": "8" * 64},
    ),
)
def test_evidence_digest_is_derived_from_every_core_field(
    mutation: dict[str, object],
) -> None:
    evidence, _api, _backend = _verify(_facts())

    changed = replace(evidence, **mutation)

    assert changed.evidence_sha256 != evidence.evidence_sha256


@pytest.mark.parametrize(
    "mutation",
    (
        {"timestamp_token_sha256": "8" * 64},
        {"timestamp_chain_sha256": "9" * 64},
        {"timestamp_time_utc": "2025-01-02T03:04:06Z"},
    ),
)
def test_evidence_digest_is_derived_from_every_timestamp_field(
    mutation: dict[str, object],
) -> None:
    evidence, _api, _backend = _verify(
        _facts(
            RuntimeProductId.PODMAN_CLI,
            timestamps=(_timestamp(),),
        )
    )

    changed = replace(evidence, **mutation)

    assert changed.evidence_sha256 != evidence.evidence_sha256


def test_evidence_digest_cannot_be_supplied_or_replaced() -> None:
    evidence, _api, _backend = _verify(_facts())

    with pytest.raises(ValueError):
        replace(evidence, evidence_sha256="0" * 64)


def test_authenticode_policy_layer_has_no_process_or_discovery_imports() -> None:
    source = (LAUNCHER_ROOT / "towerscout_launcher" / "authenticode.py").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "subprocess",
        "shutil",
        "winreg",
        "Popen",
        "os.environ",
        "getenv",
    ):
        assert forbidden not in source
