from __future__ import annotations

import ast
import ctypes
import hashlib
import struct
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.authenticode_native as native_module  # noqa: E402
from towerscout_launcher.authenticode import (  # noqa: E402
    NativeTrustStatus,
    SignerCertificateFacts,
    TimestampForm,
)
from towerscout_launcher.authenticode_native import (  # noqa: E402
    NativeWindowsAuthenticodeBackend,
)
from towerscout_launcher.runtime_policy import SignatureForm  # noqa: E402
from towerscout_launcher.windows_security import (  # noqa: E402
    FileSnapshot,
    PathClassification,
    PathLocality,
    ReparseKind,
    StableFileIdentity,
    WindowsSecurityError,
)

_PE_OFFSET = 0x80
_OPTIONAL_HEADER_OFFSET = _PE_OFFSET + 24
_OPTIONAL_HEADER_SIZE = 0xF0
_SECTION_TABLE_OFFSET = _OPTIONAL_HEADER_OFFSET + _OPTIONAL_HEADER_SIZE
_CERTIFICATE_TABLE_OFFSET = 0x400
_SECURITY_DIRECTORY_OFFSET = _OPTIONAL_HEADER_OFFSET + 144
_PKCS7_DER = b"\x30\x03\x02\x01\x00"
_TIMESTAMP_DER = b"\x30\x0f" + b"timestamp-token"
_HASH_A = "a" * 64
_HASH_B = "b" * 64


class _Interruption(BaseException):
    pass


def _build_pe(der: bytes = _PKCS7_DER) -> bytes:
    certificate_length = 8 + len(der)
    certificate_table_size = (certificate_length + 7) & ~7
    image = bytearray(_CERTIFICATE_TABLE_OFFSET + certificate_table_size)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, _PE_OFFSET)
    image[_PE_OFFSET : _PE_OFFSET + 4] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        image,
        _PE_OFFSET + 4,
        0x8664,
        1,
        0,
        0,
        0,
        _OPTIONAL_HEADER_SIZE,
        0,
    )
    struct.pack_into("<H", image, _OPTIONAL_HEADER_OFFSET, 0x020B)
    struct.pack_into("<I", image, _OPTIONAL_HEADER_OFFSET + 60, 0x200)
    struct.pack_into("<I", image, _OPTIONAL_HEADER_OFFSET + 108, 16)
    struct.pack_into(
        "<II",
        image,
        _SECURITY_DIRECTORY_OFFSET,
        _CERTIFICATE_TABLE_OFFSET,
        certificate_table_size,
    )
    image[_SECTION_TABLE_OFFSET : _SECTION_TABLE_OFFSET + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", image, _SECTION_TABLE_OFFSET + 16, 0x200)
    struct.pack_into("<I", image, _SECTION_TABLE_OFFSET + 20, 0x200)
    struct.pack_into(
        "<IHH",
        image,
        _CERTIFICATE_TABLE_OFFSET,
        certificate_length,
        0x0200,
        0x0002,
    )
    image[_CERTIFICATE_TABLE_OFFSET + 8 : _CERTIFICATE_TABLE_OFFSET + 8 + len(der)] = (
        der
    )
    return bytes(image)


def _snapshot(value: bytes) -> FileSnapshot:
    return FileSnapshot(
        identity=StableFileIdentity(17, b"i" * 16),
        sha256="1" * 64,
        size=len(value),
        attributes=0,
        creation_time=1,
        last_write_time=2,
        reparse_tag=0,
        final_path=r"\\?\C:\Program Files\Vendor\runtime.exe",
        classification=PathClassification(
            locality=PathLocality.FIXED_LOCAL,
            reparse_kind=ReparseKind.NONE,
            hydrated=True,
            regular_file=True,
            single_link=False,
        ),
    )


def _signer() -> SignerCertificateFacts:
    return SignerCertificateFacts(
        certificate_sha256="2" * 64,
        subject_common_name="Vendor Code Signing",
        subject_organization="Vendor, Inc.",
        issuer_common_name="Reviewed Issuing CA",
        serial_number="01ab",
        not_before_utc="2026-01-01T00:00:00Z",
        not_after_utc="2027-01-01T00:00:00Z",
        public_key_algorithm="rsa",
        public_key_bits=4096,
        code_signing_eku=True,
    )


class _FakeNativeApi:
    def __init__(self, value: bytes, *, timestamp: bool = False) -> None:
        self.supported = True
        self.value = value
        tokens = (b"timestamp-token",) if timestamp else ()
        self.message: object = native_module._EmbeddedMessage(
            primary_signer_count=1,
            file_digest_algorithm="sha256",
            signer_signature_algorithm="rsa_pkcs1v15",
            primary_signature=b"primary-signature",
            nested_signature_count=0,
            legacy_countersignature_count=0,
            rfc3161_tokens=tokens,
        )
        self.file_signer: object = native_module._TrustedFileSigner(
            signer=_signer(),
            chain_sha256=_HASH_A,
            secondary_signature_count=0,
            wintrust_status=0,
            provider_timestamp_chain_sha256=(_HASH_B if timestamp else None),
        )
        self.timestamp: object = native_module._TrustedTimestamp(
            signing_time_utc="2026-02-03T04:05:06Z",
            digest_algorithm="sha256",
            signature_algorithm="rsa_pkcs1v15",
            primary_signature_valid=True,
            chain_sha256=_HASH_B,
        )
        self.read_calls: list[tuple[object, int, int]] = []
        self.query_calls: list[bytes] = []
        self.file_calls: list[
            tuple[
                object,
                str,
                native_module._TrustedTimestamp | None,
                bytes,
            ]
        ] = []
        self.timestamp_calls: list[tuple[bytes, bytes]] = []

    def read_at(self, handle: object, offset: int, length: int) -> bytes:
        self.read_calls.append((handle, offset, length))
        return self.value[offset : offset + length]

    def query_embedded_message(self, pkcs7_der: bytes) -> object:
        self.query_calls.append(pkcs7_der)
        return self.message

    def verify_file(
        self,
        handle: object,
        final_path: str,
        expected_timestamp: native_module._TrustedTimestamp | None,
        expected_primary_signature: bytes,
    ) -> object:
        self.file_calls.append(
            (
                handle,
                final_path,
                expected_timestamp,
                expected_primary_signature,
            )
        )
        return self.file_signer

    def verify_timestamp(self, token: bytes, primary_signature: bytes) -> object:
        self.timestamp_calls.append((token, primary_signature))
        return self.timestamp


def _failure(backend: NativeWindowsAuthenticodeBackend, snapshot: FileSnapshot) -> str:
    with pytest.raises(WindowsSecurityError) as failure:
        backend.inspect_open_file(handle=73, snapshot=snapshot)
    assert failure.value.category == "authenticode_verification_failed"
    assert failure.value.public_message == (
        "The Windows runtime signature could not be authenticated safely."
    )
    return str(failure.value)


def test_backend_extracts_complete_facts_through_the_same_held_handle() -> None:
    value = _build_pe()
    api = _FakeNativeApi(value)
    snapshot = _snapshot(value)

    facts = NativeWindowsAuthenticodeBackend(api=api).inspect_open_file(
        handle=73, snapshot=snapshot
    )

    assert facts.signature_form is SignatureForm.EMBEDDED_AUTHENTICODE
    assert facts.certificate_table_entry_count == 1
    assert facts.primary_signer_count == 1
    assert facts.secondary_signature_count == 0
    assert facts.nested_signature_count == 0
    assert facts.legacy_countersignature_count == 0
    assert facts.embedded_signature_sha256 == (
        "b560833d6f787af46113b96aad4dd5b5d1ae00dccc69cf30cc92bed651c56617"
    )
    assert facts.file_digest_algorithm == "sha256"
    assert facts.signer_signature_algorithm == "rsa_pkcs1v15"
    assert facts.wintrust_status == 0
    assert facts.signer_chain_status is NativeTrustStatus.TRUSTED
    assert facts.signer is _signer() or facts.signer == _signer()
    assert facts.timestamps == ()
    assert api.query_calls == [_PKCS7_DER]
    assert api.file_calls == [(73, snapshot.final_path, None, b"primary-signature")]
    assert api.timestamp_calls == []
    assert api.read_calls
    assert {call[0] for call in api.read_calls} == {73}


def test_backend_verifies_one_rfc3161_token_against_primary_signature() -> None:
    value = _build_pe()
    api = _FakeNativeApi(value, timestamp=True)

    facts = NativeWindowsAuthenticodeBackend(api=api).inspect_open_file(
        handle=73, snapshot=_snapshot(value)
    )

    assert api.timestamp_calls == [(b"timestamp-token", b"primary-signature")]
    assert api.file_calls == [
        (
            73,
            _snapshot(value).final_path,
            api.timestamp,
            b"primary-signature",
        )
    ]
    assert len(facts.timestamps) == 1
    timestamp = facts.timestamps[0]
    assert timestamp.form is TimestampForm.RFC3161
    assert timestamp.token_sha256 == (
        "a5815dc989f010ab7b50f9b9289173e7d1ee689f48c288dc77aad5825e339b20"
    )
    assert timestamp.signing_time_utc == "2026-02-03T04:05:06Z"
    assert timestamp.primary_signature_valid is True
    assert timestamp.chain_status is NativeTrustStatus.TRUSTED
    assert timestamp.chain_sha256 == _HASH_B


@pytest.mark.parametrize(
    "message",
    [
        native_module._EmbeddedMessage(2, "sha256", "rsa_pkcs1v15", b"sig", 0, 0, ()),
        native_module._EmbeddedMessage(1, "sha256", "rsa_pkcs1v15", b"sig", 1, 0, ()),
        native_module._EmbeddedMessage(1, "sha256", "rsa_pkcs1v15", b"sig", 0, 1, ()),
        native_module._EmbeddedMessage(
            1,
            "sha256",
            "rsa_pkcs1v15",
            b"sig",
            0,
            0,
            (b"timestamp-one", b"timestamp-two"),
        ),
    ],
)
def test_backend_rejects_ambiguous_or_legacy_message_before_wintrust(
    message: object,
) -> None:
    value = _build_pe()
    api = _FakeNativeApi(value)
    api.message = message

    _failure(NativeWindowsAuthenticodeBackend(api=api), _snapshot(value))

    assert api.file_calls == []
    assert api.timestamp_calls == []


@pytest.mark.parametrize(
    "file_signer",
    [
        native_module._TrustedFileSigner(_signer(), _HASH_A, 1, 0),
        native_module._TrustedFileSigner(_signer(), _HASH_A, 0, -1),
        object(),
    ],
)
def test_backend_rejects_nonzero_or_untyped_wintrust_evidence(
    file_signer: object,
) -> None:
    value = _build_pe()
    api = _FakeNativeApi(value)
    api.file_signer = file_signer

    _failure(NativeWindowsAuthenticodeBackend(api=api), _snapshot(value))

    assert api.timestamp_calls == []


def test_backend_fails_closed_when_native_api_is_unavailable() -> None:
    value = _build_pe()
    api = _FakeNativeApi(value)
    api.supported = False

    _failure(NativeWindowsAuthenticodeBackend(api=api), _snapshot(value))

    assert api.read_calls == []


@pytest.mark.parametrize(
    "native_error",
    [
        OSError(r"secret C:\Users\operator\runtime.exe status=0x800B010E"),
        ctypes.ArgumentError(r"secret C:\Users\operator\runtime.exe status=0x800B010E"),
    ],
)
def test_backend_sanitizes_native_exception_details(native_error: Exception) -> None:
    value = _build_pe()
    api = _FakeNativeApi(value)

    def fail(_value: bytes) -> object:
        raise native_error

    api.query_embedded_message = fail  # type: ignore[method-assign]

    rendered = _failure(NativeWindowsAuthenticodeBackend(api=api), _snapshot(value))

    assert "operator" not in rendered
    assert "0x800B010E" not in rendered


def test_supported_and_repr_hide_ctypes_exception_details() -> None:
    class ExplodingApi:
        @property
        def supported(self) -> bool:
            raise ctypes.ArgumentError(r"secret C:\Users\operator\runtime.exe")

    backend = NativeWindowsAuthenticodeBackend(api=ExplodingApi())  # type: ignore[arg-type]

    assert backend.supported is False
    rendered = repr(backend)
    assert rendered == "NativeWindowsAuthenticodeBackend(state='unavailable')"
    assert "operator" not in rendered


def test_backend_does_not_swallow_base_exception_interruption() -> None:
    value = _build_pe()
    api = _FakeNativeApi(value)
    primary = _Interruption("stop now")

    def interrupt(_value: bytes) -> object:
        raise primary

    api.query_embedded_message = interrupt  # type: ignore[method-assign]

    with pytest.raises(_Interruption) as caught:
        NativeWindowsAuthenticodeBackend(api=api).inspect_open_file(
            handle=73, snapshot=_snapshot(value)
        )

    assert caught.value is primary


def test_backend_rejects_malformed_pe_before_native_trust_calls() -> None:
    value = bytearray(_build_pe())
    value[0] = 0
    api = _FakeNativeApi(bytes(value))

    _failure(NativeWindowsAuthenticodeBackend(api=api), _snapshot(bytes(value)))

    assert api.query_calls == []
    assert api.file_calls == []


def test_backend_rejects_wrong_handle_and_snapshot_types() -> None:
    value = _build_pe()
    api = _FakeNativeApi(value)
    backend = NativeWindowsAuthenticodeBackend(api=api)

    with pytest.raises(WindowsSecurityError):
        backend.inspect_open_file(handle=True, snapshot=_snapshot(value))
    with pytest.raises(WindowsSecurityError):
        backend.inspect_open_file(handle=73, snapshot=object())  # type: ignore[arg-type]

    assert api.read_calls == []


def test_backend_rejects_untyped_timestamp_result() -> None:
    value = _build_pe()
    api = _FakeNativeApi(value, timestamp=True)
    api.timestamp = object()

    _failure(NativeWindowsAuthenticodeBackend(api=api), _snapshot(value))


def test_backend_rejects_provider_timestamp_chain_mismatch() -> None:
    value = _build_pe()
    api = _FakeNativeApi(value, timestamp=True)
    assert isinstance(api.file_signer, native_module._TrustedFileSigner)
    api.file_signer = native_module._TrustedFileSigner(
        signer=api.file_signer.signer,
        chain_sha256=api.file_signer.chain_sha256,
        secondary_signature_count=0,
        wintrust_status=0,
        provider_timestamp_chain_sha256="c" * 64,
    )

    _failure(NativeWindowsAuthenticodeBackend(api=api), _snapshot(value))


def test_native_evidence_helpers_are_frozen_and_redacted() -> None:
    message = native_module._EmbeddedMessage(
        1,
        "sha256",
        "rsa_pkcs1v15",
        b"private-signature",
        0,
        0,
        (b"private-token",),
    )
    timestamp = native_module._TrustedTimestamp(
        "2026-02-03T04:05:06Z",
        "sha256",
        "rsa_pkcs1v15",
        True,
        _HASH_B,
    )

    with pytest.raises(FrozenInstanceError):
        message.primary_signature = b"changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        timestamp.chain_sha256 = _HASH_A  # type: ignore[misc]
    assert repr(message) == "_EmbeddedMessage(<redacted>)"
    assert repr(timestamp) == "_TrustedTimestamp(<redacted>)"
    assert "private" not in repr(message)
    assert _HASH_B not in repr(timestamp)


def test_exact_wintrust_flags_and_x64_ctypes_layouts() -> None:
    assert native_module._WINTRUST_PROVIDER_FLAGS == 0x3040
    assert native_module._WINTRUST_SIGNATURE_FLAGS == 3
    assert native_module.WTD_UI_NONE == 2
    assert native_module.WTD_REVOKE_WHOLECHAIN == 1
    assert native_module.WTD_CHOICE_FILE == 1
    assert native_module.WTD_STATEACTION_VERIFY == 1
    assert native_module.WTD_STATEACTION_CLOSE == 2
    assert native_module._CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY == 0x80000000
    assert native_module._abi_layout_supported() is (
        ctypes.sizeof(ctypes.c_void_p) == 8
    )

    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert ctypes.sizeof(native_module._WinTrustFileInfo) == 32
        assert ctypes.sizeof(native_module._WinTrustSignatureSettings) == 32
        assert ctypes.sizeof(native_module._CertStrongSignPara) == 16
        assert ctypes.sizeof(native_module._WinTrustData) == 88
        assert ctypes.sizeof(native_module._CryptProviderSigner) == 64
        assert ctypes.sizeof(native_module._CryptProviderCert) == 88
        assert ctypes.sizeof(native_module._CertContext) == 40
        assert ctypes.sizeof(native_module._CmsgSignerInfo) == 136


class _RecordingWinTrust:
    def __init__(
        self,
        *,
        verify_status: int = 0,
        verified_signature_index: int = 0,
        secondary_signature_count: int = 0,
        returned_signature_flags: int | None = None,
    ) -> None:
        self.verify_status = verify_status
        self.verified_signature_index = verified_signature_index
        self.secondary_signature_count = secondary_signature_count
        self.returned_signature_flags = returned_signature_flags
        self.calls: list[dict[str, object]] = []

    def WinVerifyTrustEx(
        self, window: ctypes.c_void_p, action: object, data_pointer: object
    ) -> int:
        action_value = ctypes.cast(action, ctypes.POINTER(native_module._Guid)).contents
        data = ctypes.cast(
            data_pointer, ctypes.POINTER(native_module._WinTrustData)
        ).contents
        file_info = data.file.contents
        settings = data.signature_settings.contents
        self.calls.append(
            {
                "window": window.value,
                "action": (
                    action_value.data1,
                    action_value.data2,
                    action_value.data3,
                    bytes(action_value.data4),
                ),
                "state_action": data.state_action,
                "ui_choice": data.ui_choice,
                "revocation_checks": data.revocation_checks,
                "union_choice": data.union_choice,
                "provider_flags": data.provider_flags,
                "signature_flags": settings.flags,
                "signature_index": settings.index,
                "file_handle": file_info.file_handle,
                "file_path": file_info.file_path,
            }
        )
        if data.state_action == native_module.WTD_STATEACTION_VERIFY:
            data.state_data = 123
            if self.returned_signature_flags is not None:
                settings.flags = self.returned_signature_flags
            settings.secondary_signature_count = self.secondary_signature_count
            settings.verified_signature_index = self.verified_signature_index
            return self.verify_status
        return 0


def _ctypes_api_with_fake_wintrust(wintrust: _RecordingWinTrust) -> object:
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = object()
    api._wintrust = wintrust
    return api


def test_wintrust_uses_reviewed_handle_flags_invalid_window_and_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wintrust = _RecordingWinTrust()
    api = _ctypes_api_with_fake_wintrust(wintrust)
    expected = native_module._TrustedFileSigner(_signer(), _HASH_A, 0, 0)

    def provider(
        _self: object,
        state_data: ctypes.c_void_p,
        timestamp: object,
        primary_signature: bytes,
    ) -> object:
        assert state_data == 123
        assert timestamp is None
        assert primary_signature == b"primary-signature"
        return expected

    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_provider_signer",
        provider,
    )

    result = api.verify_file(
        73,
        r"\\?\C:\Vendor\runtime.exe",
        None,
        b"primary-signature",
    )

    assert result is expected
    assert [call["state_action"] for call in wintrust.calls] == [1, 2]
    assert all(call["window"] == ctypes.c_void_p(-1).value for call in wintrust.calls)
    assert all(
        call["action"]
        == (
            0x00AAC56B,
            0xCD44,
            0x11D0,
            b"\x8c\xc2\x00\xc0O\xc2\x95\xee",
        )
        for call in wintrust.calls
    )
    verify = wintrust.calls[0]
    assert verify["ui_choice"] == 2
    assert verify["revocation_checks"] == 1
    assert verify["union_choice"] == 1
    assert verify["provider_flags"] == 0x3040
    assert verify["signature_flags"] == 3
    assert verify["signature_index"] == 0
    assert verify["file_handle"] == 73
    assert verify["file_path"] == r"\\?\C:\Vendor\runtime.exe"


def test_wintrust_always_closes_state_after_nonzero_status() -> None:
    wintrust = _RecordingWinTrust(verify_status=-1)
    api = _ctypes_api_with_fake_wintrust(wintrust)

    with pytest.raises(ValueError, match="validation failed"):
        api.verify_file(
            73,
            r"\\?\C:\Vendor\runtime.exe",
            None,
            b"primary-signature",
        )

    assert [call["state_action"] for call in wintrust.calls] == [1, 2]


@pytest.mark.parametrize(
    ("verified_signature_index", "secondary_signature_count"),
    [(1, 0), (0, 1)],
)
def test_wintrust_rejects_wrong_verified_index_or_secondary_signature_count(
    monkeypatch: pytest.MonkeyPatch,
    verified_signature_index: int,
    secondary_signature_count: int,
) -> None:
    wintrust = _RecordingWinTrust(
        verified_signature_index=verified_signature_index,
        secondary_signature_count=secondary_signature_count,
    )
    api = _ctypes_api_with_fake_wintrust(wintrust)

    def must_not_extract(*_args: object, **_kwargs: object) -> object:
        raise AssertionError(
            "provider evidence extracted after invalid signature selection"
        )

    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_provider_signer",
        must_not_extract,
    )

    with pytest.raises(ValueError, match="signature selection"):
        api.verify_file(
            73,
            r"\\?\C:\Vendor\runtime.exe",
            None,
            b"primary-signature",
        )

    assert [call["state_action"] for call in wintrust.calls] == [1, 2]


def test_wintrust_accepts_only_documented_signature_output_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = native_module._TrustedFileSigner(_signer(), _HASH_A, 0, 0)

    def provider(*_args: object, **_kwargs: object) -> object:
        return expected

    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_provider_signer",
        provider,
    )
    accepted = _RecordingWinTrust(returned_signature_flags=0xE0000003)
    accepted_api = _ctypes_api_with_fake_wintrust(accepted)
    assert (
        accepted_api.verify_file(
            73,
            r"\\?\C:\Vendor\runtime.exe",
            None,
            b"primary-signature",
        )
        is expected
    )

    unknown = _RecordingWinTrust(returned_signature_flags=0x10000003)
    unknown_api = _ctypes_api_with_fake_wintrust(unknown)
    with pytest.raises(ValueError, match="signature selection"):
        unknown_api.verify_file(
            73,
            r"\\?\C:\Vendor\runtime.exe",
            None,
            b"primary-signature",
        )

    assert [call["state_action"] for call in accepted.calls] == [1, 2]
    assert [call["state_action"] for call in unknown.calls] == [1, 2]


class _ProviderSignerWinTrust:
    def __init__(
        self,
        signer: object,
        *,
        extra_signer: object | None = None,
        countersigner: object | None = None,
        extra_countersigner: object | None = None,
    ) -> None:
        self.signer = signer
        self.extra_signer = extra_signer
        self.countersigner = countersigner
        self.extra_countersigner = extra_countersigner
        self.helper_calls: list[tuple[int, int, int]] = []

    def WTHelperProvDataFromStateData(self, _state: object) -> int:
        return 1

    def WTHelperGetProvSignerFromChain(
        self,
        _provider: object,
        signer_index: int,
        counter: int,
        _counter_index: int,
    ) -> object:
        self.helper_calls.append((signer_index, counter, _counter_index))
        if counter == 0 and signer_index == 0:
            return ctypes.pointer(self.signer)
        if counter == 0 and signer_index == 1 and self.extra_signer is not None:
            return ctypes.pointer(self.extra_signer)
        if counter == 1 and _counter_index == 0 and self.countersigner is not None:
            return ctypes.pointer(self.countersigner)
        if (
            counter == 1
            and _counter_index == 1
            and self.extra_countersigner is not None
        ):
            return ctypes.pointer(self.extra_countersigner)
        return None


def test_provider_structure_primary_signature_must_match_independent_cms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest_oid = ctypes.create_string_buffer(native_module._SHA256_OID.encode("ascii"))
    signature_oid = ctypes.create_string_buffer(
        native_module._RSA_ENCRYPTION_OID.encode("ascii")
    )
    provider_signature = ctypes.create_string_buffer(b"provider-signature")
    signer_info = native_module._CmsgSignerInfo()
    signer_info.hash_algorithm.oid = ctypes.cast(digest_oid, ctypes.c_void_p)
    signer_info.hash_encryption_algorithm.oid = ctypes.cast(
        signature_oid, ctypes.c_void_p
    )
    signer_info.encrypted_hash = native_module._CryptBlob(
        len(b"provider-signature"),
        ctypes.cast(provider_signature, ctypes.c_void_p),
    )
    provider_certs = (native_module._CryptProviderCert * 1)()
    chain = native_module._CertChainContext()
    signer = native_module._CryptProviderSigner()
    signer.size = ctypes.sizeof(native_module._CryptProviderSigner)
    signer.cert_chain_count = 1
    signer.cert_chain = provider_certs
    signer.signer_type = native_module._SGNR_TYPE_SIGNER
    signer.signer_info = ctypes.pointer(signer_info)
    signer.chain_context = ctypes.pointer(chain)
    wintrust = _ProviderSignerWinTrust(signer)
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = object()
    api._wintrust = wintrust

    def must_not_continue(_value: object) -> object:
        raise AssertionError("provider chain inspected after signature mismatch")

    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_provider_chain_certificates",
        staticmethod(must_not_continue),
    )

    with pytest.raises(ValueError, match="primary signature is inconsistent"):
        api._provider_signer(
            ctypes.c_void_p(123),
            None,
            b"independent-signature",
        )


def _provider_signer_structure(
    signature: bytes,
    *,
    signer_type: int = native_module._SGNR_TYPE_SIGNER,
    error: int = 0,
    countersigner_count: int = 0,
    verify_time: object | None = None,
) -> tuple[object, tuple[object, ...]]:
    digest_oid = ctypes.create_string_buffer(native_module._SHA256_OID.encode("ascii"))
    signature_oid = ctypes.create_string_buffer(
        native_module._RSA_ENCRYPTION_OID.encode("ascii")
    )
    signature_buffer = ctypes.create_string_buffer(signature)
    signer_info = native_module._CmsgSignerInfo()
    signer_info.hash_algorithm.oid = ctypes.cast(digest_oid, ctypes.c_void_p)
    signer_info.hash_encryption_algorithm.oid = ctypes.cast(
        signature_oid, ctypes.c_void_p
    )
    signer_info.encrypted_hash = native_module._CryptBlob(
        len(signature), ctypes.cast(signature_buffer, ctypes.c_void_p)
    )
    cert_context = native_module._CertContext()
    cert_context.cert_store = 222
    provider_certs = (native_module._CryptProviderCert * 1)()
    provider_certs[0].cert = ctypes.pointer(cert_context)
    chain = native_module._CertChainContext()
    signer = native_module._CryptProviderSigner()
    signer.size = ctypes.sizeof(native_module._CryptProviderSigner)
    signer.cert_chain_count = 1
    signer.cert_chain = provider_certs
    signer.signer_type = signer_type
    signer.signer_info = ctypes.pointer(signer_info)
    signer.error = error
    signer.countersigner_count = countersigner_count
    signer.chain_context = ctypes.pointer(chain)
    if verify_time is not None:
        signer.verify_as_of = verify_time
    return signer, (
        digest_oid,
        signature_oid,
        signature_buffer,
        signer_info,
        cert_context,
        provider_certs,
        chain,
    )


def test_provider_signer_matches_signature_helper_cardinality_and_chains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary, primary_keepalive = _provider_signer_structure(b"cms-primary-signature")
    assert primary_keepalive
    wintrust = _ProviderSignerWinTrust(primary)
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = object()
    api._wintrust = wintrust
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_provider_chain_certificates",
        staticmethod(lambda _signer: (b"publisher", b"issuer")),
    )
    chain_calls: list[tuple[int, int, tuple[int, int], str, int]] = []

    def build_chain(
        _self: object,
        certificate: object,
        store: ctypes.c_void_p,
        verify_time: object,
        *,
        required_eku: str,
        policy: int,
    ) -> tuple[bytes, ...]:
        chain_calls.append(
            (
                ctypes.cast(certificate, ctypes.c_void_p).value,
                int(store.value if isinstance(store, ctypes.c_void_p) else store),
                (verify_time.low, verify_time.high),
                required_eku,
                policy,
            )
        )
        return (b"publisher", b"issuer")

    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_build_independent_chain",
        build_chain,
    )
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_signer_certificate_facts",
        lambda _self, _certificate: _signer(),
    )

    result = api._provider_signer(
        ctypes.c_void_p(123),
        None,
        b"cms-primary-signature",
    )

    assert result.signer == _signer()
    assert result.chain_sha256 == native_module._chain_digest((b"publisher", b"issuer"))
    assert result.provider_timestamp_chain_sha256 is None
    assert chain_calls == [
        (
            ctypes.addressof(primary.cert_chain[0].cert.contents),
            222,
            (0, 0),
            native_module._CODE_SIGNING_EKU_OID,
            native_module._CERT_CHAIN_POLICY_AUTHENTICODE,
        )
    ]
    assert wintrust.helper_calls == [
        (0, 0, 0),
        (1, 0, 0),
        (0, 1, 0),
        (0, 1, 1),
    ]


def test_provider_signer_correlates_rfc3161_countersigner_time_and_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    epoch_ticks = 116_444_736_000_000_000
    verify_time = native_module._FileTime(epoch_ticks & 0xFFFFFFFF, epoch_ticks >> 32)
    primary, primary_keepalive = _provider_signer_structure(
        b"cms-primary-signature",
        countersigner_count=1,
        verify_time=verify_time,
    )
    counter, counter_keepalive = _provider_signer_structure(
        b"timestamp-signature",
        signer_type=native_module._SGNR_TYPE_TIMESTAMP,
        verify_time=verify_time,
    )
    assert primary_keepalive and counter_keepalive
    wintrust = _ProviderSignerWinTrust(primary, countersigner=counter)
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = object()
    api._wintrust = wintrust

    def provider_chain(value: object) -> tuple[bytes, ...]:
        return (
            (b"tsa", b"tsa-issuer")
            if value.signer_type == native_module._SGNR_TYPE_TIMESTAMP
            else (b"publisher", b"issuer")
        )

    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_provider_chain_certificates",
        staticmethod(provider_chain),
    )
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_build_independent_chain",
        lambda _self, *_args, **_kwargs: (b"publisher", b"issuer"),
    )
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_signer_certificate_facts",
        lambda _self, _certificate: _signer(),
    )
    expected_timestamp = native_module._TrustedTimestamp(
        "1970-01-01T00:00:00Z",
        "sha256",
        "rsa_pkcs1v15",
        True,
        native_module._chain_digest((b"tsa", b"tsa-issuer")),
    )

    result = api._provider_signer(
        ctypes.c_void_p(123),
        expected_timestamp,
        b"cms-primary-signature",
    )

    assert result.provider_timestamp_chain_sha256 == expected_timestamp.chain_sha256
    assert wintrust.helper_calls == [
        (0, 0, 0),
        (1, 0, 0),
        (0, 1, 0),
        (0, 1, 1),
    ]


@pytest.mark.parametrize(
    "invalid_counter",
    ["missing", "extra", "wrong_type", "error", "nested_counter"],
)
def test_provider_signer_rejects_timestamp_helper_cardinality_type_and_error(
    monkeypatch: pytest.MonkeyPatch, invalid_counter: str
) -> None:
    epoch_ticks = 116_444_736_000_000_000
    verify_time = native_module._FileTime(epoch_ticks & 0xFFFFFFFF, epoch_ticks >> 32)
    primary, primary_keepalive = _provider_signer_structure(
        b"cms-primary-signature",
        countersigner_count=1,
        verify_time=verify_time,
    )
    counter: object | None = None
    extra_counter: object | None = None
    counter_keepalive: tuple[object, ...] = ()
    extra_keepalive: tuple[object, ...] = ()
    if invalid_counter != "missing":
        counter, counter_keepalive = _provider_signer_structure(
            b"timestamp-signature",
            signer_type=(
                native_module._SGNR_TYPE_SIGNER
                if invalid_counter == "wrong_type"
                else native_module._SGNR_TYPE_TIMESTAMP
            ),
            error=1 if invalid_counter == "error" else 0,
            countersigner_count=1 if invalid_counter == "nested_counter" else 0,
            verify_time=verify_time,
        )
    if invalid_counter == "extra":
        extra_counter, extra_keepalive = _provider_signer_structure(
            b"extra-timestamp-signature",
            signer_type=native_module._SGNR_TYPE_TIMESTAMP,
            verify_time=verify_time,
        )
    assert primary_keepalive
    assert invalid_counter == "missing" or counter_keepalive
    assert invalid_counter != "extra" or extra_keepalive
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = object()
    api._wintrust = _ProviderSignerWinTrust(
        primary,
        countersigner=counter,
        extra_countersigner=extra_counter,
    )
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_provider_chain_certificates",
        staticmethod(lambda _signer: (b"publisher", b"issuer")),
    )
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_build_independent_chain",
        lambda _self, *_args, **_kwargs: (b"publisher", b"issuer"),
    )
    expected_timestamp = native_module._TrustedTimestamp(
        "1970-01-01T00:00:00Z",
        "sha256",
        "rsa_pkcs1v15",
        True,
        native_module._chain_digest((b"tsa",)),
    )

    with pytest.raises(ValueError, match="timestamp"):
        api._provider_signer(
            ctypes.c_void_p(123),
            expected_timestamp,
            b"cms-primary-signature",
        )


@pytest.mark.parametrize(
    ("signer_type", "error", "extra"),
    [
        (native_module._SGNR_TYPE_TIMESTAMP, 0, False),
        (native_module._SGNR_TYPE_SIGNER, 1, False),
        (native_module._SGNR_TYPE_SIGNER, 0, True),
    ],
)
def test_provider_signer_rejects_helper_type_error_and_extra_primary(
    signer_type: int, error: int, extra: bool
) -> None:
    primary, keepalive = _provider_signer_structure(
        b"cms-primary-signature",
        signer_type=signer_type,
        error=error,
    )
    extra_signer, extra_keepalive = _provider_signer_structure(b"cms-primary-signature")
    assert keepalive and extra_keepalive
    wintrust = _ProviderSignerWinTrust(
        primary,
        extra_signer=extra_signer if extra else None,
    )
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = object()
    api._wintrust = wintrust

    with pytest.raises(ValueError, match="trust signer"):
        api._provider_signer(
            ctypes.c_void_p(123),
            None,
            b"cms-primary-signature",
        )


def test_provider_signer_rejects_independent_publisher_chain_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary, keepalive = _provider_signer_structure(b"cms-primary-signature")
    assert keepalive
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = object()
    api._wintrust = _ProviderSignerWinTrust(primary)
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_provider_chain_certificates",
        staticmethod(lambda _signer: (b"provider-chain",)),
    )
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_build_independent_chain",
        lambda _self, *_args, **_kwargs: (b"independent-chain",),
    )

    with pytest.raises(ValueError, match="chain is inconsistent"):
        api._provider_signer(
            ctypes.c_void_p(123),
            None,
            b"cms-primary-signature",
        )


class _InterruptingQueryCrypt:
    def __init__(self, stage: str, primary: BaseException) -> None:
        self.stage = stage
        self.primary = primary
        self.message_cleanup = _Interruption("message cleanup")
        self.store_cleanup = _Interruption("store cleanup")
        self.cleanup_calls: list[str] = []

    def CryptQueryObject(self, *arguments: object) -> int:
        ctypes.cast(arguments[5], ctypes.POINTER(ctypes.c_uint32)).contents.value = (
            native_module._ENCODING_TYPES
        )
        ctypes.cast(arguments[6], ctypes.POINTER(ctypes.c_uint32)).contents.value = (
            native_module._CERT_QUERY_CONTENT_PKCS7_SIGNED
        )
        ctypes.cast(arguments[7], ctypes.POINTER(ctypes.c_uint32)).contents.value = (
            native_module._CERT_QUERY_FORMAT_BINARY
        )
        ctypes.cast(arguments[8], ctypes.POINTER(ctypes.c_void_p)).contents.value = 222
        ctypes.cast(arguments[9], ctypes.POINTER(ctypes.c_void_p)).contents.value = 333
        if self.stage == "acquisition":
            raise self.primary
        return 1

    def CryptMsgClose(self, _message: object) -> int:
        self.cleanup_calls.append("message")
        raise self.message_cleanup

    def CertCloseStore(self, _store: object, _flags: int) -> int:
        self.cleanup_calls.append("store")
        raise self.store_cleanup


@pytest.mark.parametrize("stage", ["acquisition", "extractor"])
def test_with_message_preserves_interruption_and_attempts_all_cleanup(
    stage: str,
) -> None:
    primary = _Interruption(f"primary {stage}")
    crypt32 = _InterruptingQueryCrypt(stage, primary)
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = crypt32
    api._wintrust = object()

    def extract(_message: object) -> object:
        if stage == "extractor":
            raise primary
        raise AssertionError("extractor ran after acquisition interruption")

    with pytest.raises(_Interruption) as caught:
        api._with_message(b"signed-message", extract)

    assert caught.value is primary
    assert crypt32.cleanup_calls == ["message", "store"]


def test_with_message_preserves_first_cleanup_interruption_and_continues_cleanup() -> (
    None
):
    crypt32 = _InterruptingQueryCrypt("success", _Interruption("unused"))
    api = _api_with_recording_crypt(crypt32)

    with pytest.raises(_Interruption) as caught:
        api._with_message(b"signed-message", lambda _message: "extracted")

    assert caught.value is crypt32.message_cleanup
    assert crypt32.cleanup_calls == ["message", "store"]


class _InterruptingWinTrust(_RecordingWinTrust):
    def __init__(self, stage: str, primary: BaseException) -> None:
        super().__init__()
        self.stage = stage
        self.primary = primary
        self.close_cleanup = _Interruption("WinTrust close interruption")

    def WinVerifyTrustEx(
        self, window: ctypes.c_void_p, action: object, data_pointer: object
    ) -> int:
        result = super().WinVerifyTrustEx(window, action, data_pointer)
        data = ctypes.cast(
            data_pointer, ctypes.POINTER(native_module._WinTrustData)
        ).contents
        if data.state_action == native_module.WTD_STATEACTION_VERIFY:
            if self.stage == "acquisition":
                raise self.primary
            return result
        raise self.close_cleanup


@pytest.mark.parametrize("stage", ["acquisition", "provider"])
def test_verify_file_preserves_interruption_and_always_attempts_close(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    primary = _Interruption(f"primary {stage}")
    wintrust = _InterruptingWinTrust(stage, primary)
    api = _ctypes_api_with_fake_wintrust(wintrust)

    def provider(
        _self: object,
        _state: object,
        _timestamp: object,
        _signature: bytes,
    ) -> object:
        if stage == "provider":
            raise primary
        raise AssertionError("provider ran after acquisition interruption")

    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_provider_signer",
        provider,
    )

    with pytest.raises(_Interruption) as caught:
        api.verify_file(
            73,
            r"\\?\C:\Vendor\runtime.exe",
            None,
            b"primary-signature",
        )

    assert caught.value is primary
    assert [call["state_action"] for call in wintrust.calls] == [1, 2]


def test_verify_file_preserves_close_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wintrust = _InterruptingWinTrust("success", _Interruption("unused"))
    api = _ctypes_api_with_fake_wintrust(wintrust)
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_provider_signer",
        lambda *_args, **_kwargs: native_module._TrustedFileSigner(
            _signer(), _HASH_A, 0, 0
        ),
    )

    with pytest.raises(_Interruption) as caught:
        api.verify_file(
            73,
            r"\\?\C:\Vendor\runtime.exe",
            None,
            b"primary-signature",
        )

    assert caught.value is wintrust.close_cleanup
    assert [call["state_action"] for call in wintrust.calls] == [1, 2]


class _InterruptingTimestampCrypt:
    def __init__(
        self,
        stage: str,
        primary: BaseException,
        *,
        encoded: bytes = _TIMESTAMP_DER,
    ) -> None:
        self.stage = stage
        self.primary = primary
        self.context_cleanup = _Interruption("context cleanup")
        self.signer_cleanup = _Interruption("signer cleanup")
        self.store_cleanup = _Interruption("store cleanup")
        self.cleanup_calls: list[str] = []
        self.verify_calls: list[tuple[bytes, int, bytes, int, object]] = []
        self.encoded = ctypes.create_string_buffer(encoded)
        self.imprint = ctypes.create_string_buffer(
            hashlib.sha256(b"primary-signature").digest()
        )
        self.digest_oid = ctypes.create_string_buffer(
            native_module._SHA256_OID.encode("ascii")
        )
        self.info = native_module._CryptTimestampInfo()
        self.info.version = 1
        self.info.hash_algorithm.oid = ctypes.cast(self.digest_oid, ctypes.c_void_p)
        self.info.hashed_message = native_module._CryptBlob(
            32, ctypes.cast(self.imprint, ctypes.c_void_p)
        )
        ticks = 116_444_736_000_000_000
        self.info.time = native_module._FileTime(ticks & 0xFFFFFFFF, ticks >> 32)
        self.context = native_module._CryptTimestampContext(
            len(encoded),
            ctypes.cast(self.encoded, ctypes.c_void_p),
            ctypes.pointer(self.info),
        )
        self.signer = native_module._CertContext()

    def CryptVerifyTimeStampSignature(self, *arguments: object) -> int:
        self.verify_calls.append(
            (
                ctypes.string_at(arguments[0], int(arguments[1])),
                int(arguments[1]),
                ctypes.string_at(arguments[2], int(arguments[3])),
                int(arguments[3]),
                arguments[4],
            )
        )
        ctypes.cast(
            arguments[5],
            ctypes.POINTER(ctypes.POINTER(native_module._CryptTimestampContext)),
        )[0] = ctypes.pointer(self.context)
        ctypes.cast(
            arguments[6],
            ctypes.POINTER(ctypes.POINTER(native_module._CertContext)),
        )[0] = ctypes.pointer(self.signer)
        ctypes.cast(arguments[7], ctypes.POINTER(ctypes.c_void_p)).contents.value = 444
        if self.stage == "acquisition":
            raise self.primary
        return 1

    def CryptMemFree(self, _context: object) -> None:
        self.cleanup_calls.append("context")
        raise self.context_cleanup

    def CertFreeCertificateContext(self, _signer: object) -> int:
        self.cleanup_calls.append("signer")
        raise self.signer_cleanup

    def CertCloseStore(self, _store: object, _flags: int) -> int:
        self.cleanup_calls.append("store")
        raise self.store_cleanup


@pytest.mark.parametrize("stage", ["acquisition", "timestamp_chain"])
def test_verify_timestamp_preserves_interruption_and_attempts_all_cleanup(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    primary = _Interruption(f"primary {stage}")
    crypt32 = _InterruptingTimestampCrypt(stage, primary)
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = crypt32
    api._wintrust = object()
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_timestamp_message_algorithms",
        lambda _self, _token: ("sha256", "rsa_pkcs1v15"),
    )

    def timestamp_chain(
        _self: object, _certificate: object, _store: object, _time: object
    ) -> str:
        if stage == "timestamp_chain":
            raise primary
        raise AssertionError("chain ran after acquisition interruption")

    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_timestamp_chain",
        timestamp_chain,
    )

    with pytest.raises(_Interruption) as caught:
        api.verify_timestamp(_TIMESTAMP_DER, b"primary-signature")

    assert caught.value is primary
    assert crypt32.cleanup_calls == ["context", "signer", "store"]


def test_verify_timestamp_preserves_first_cleanup_interruption_and_continues_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    crypt32 = _InterruptingTimestampCrypt("success", _Interruption("unused"))
    api = _api_with_recording_crypt(crypt32)
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_timestamp_message_algorithms",
        lambda _self, _token: ("sha256", "rsa_pkcs1v15"),
    )
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_timestamp_chain",
        lambda _self, *_args: _HASH_B,
    )

    with pytest.raises(_Interruption) as caught:
        api.verify_timestamp(_TIMESTAMP_DER, b"primary-signature")

    assert caught.value is crypt32.context_cleanup
    assert crypt32.cleanup_calls == ["context", "signer", "store"]


class _RecordingTimestampCrypt(_InterruptingTimestampCrypt):
    def __init__(self, *, encoded: bytes = _TIMESTAMP_DER) -> None:
        super().__init__("success", _Interruption("unused"), encoded=encoded)

    def CryptMemFree(self, _context: object) -> None:
        self.cleanup_calls.append("context")

    def CertFreeCertificateContext(self, _signer: object) -> int:
        self.cleanup_calls.append("signer")
        return 1

    def CertCloseStore(self, _store: object, _flags: int) -> int:
        self.cleanup_calls.append("store")
        return 1


def test_verify_timestamp_checks_version_imprint_time_chain_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    crypt32 = _RecordingTimestampCrypt()
    api = _api_with_recording_crypt(crypt32)
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_timestamp_message_algorithms",
        lambda _self, _token: ("sha256", "rsa_pkcs1v15"),
    )
    chain_calls: list[tuple[object, int, tuple[int, int], str, int]] = []

    def build_chain(
        _self: object,
        certificate: object,
        store: ctypes.c_void_p,
        verify_time: object,
        *,
        required_eku: str,
        policy: int,
    ) -> tuple[bytes, ...]:
        chain_calls.append(
            (
                ctypes.cast(certificate, ctypes.c_void_p).value,
                store.value,
                (verify_time.low, verify_time.high),
                required_eku,
                policy,
            )
        )
        return (b"timestamp", b"timestamp-issuer")

    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_build_independent_chain",
        build_chain,
    )

    result = api.verify_timestamp(_TIMESTAMP_DER, b"primary-signature")

    assert result.signing_time_utc == "1970-01-01T00:00:00Z"
    assert result.digest_algorithm == "sha256"
    assert result.signature_algorithm == "rsa_pkcs1v15"
    assert result.primary_signature_valid is True
    assert result.chain_sha256 == native_module._chain_digest(
        (b"timestamp", b"timestamp-issuer")
    )
    assert crypt32.verify_calls == [
        (
            _TIMESTAMP_DER,
            len(_TIMESTAMP_DER),
            b"primary-signature",
            len(b"primary-signature"),
            None,
        )
    ]
    assert chain_calls == [
        (
            ctypes.addressof(crypt32.signer),
            444,
            (crypt32.info.time.low, crypt32.info.time.high),
            native_module._TIME_STAMPING_EKU_OID,
            native_module._CERT_CHAIN_POLICY_AUTHENTICODE_TS,
        )
    ]
    assert crypt32.cleanup_calls == ["context", "signer", "store"]


@pytest.mark.parametrize("invalid_field", ["version", "imprint"])
def test_verify_timestamp_rejects_bad_version_or_imprint_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch, invalid_field: str
) -> None:
    crypt32 = _RecordingTimestampCrypt()
    if invalid_field == "version":
        crypt32.info.version = 2
    else:
        crypt32.info.hashed_message.size = 31
    api = _api_with_recording_crypt(crypt32)
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_timestamp_message_algorithms",
        lambda _self, _token: ("sha256", "rsa_pkcs1v15"),
    )

    with pytest.raises(ValueError, match="Timestamp evidence"):
        api.verify_timestamp(_TIMESTAMP_DER, b"primary-signature")

    assert crypt32.cleanup_calls == ["context", "signer", "store"]


@pytest.mark.parametrize(
    "encoded",
    [
        _TIMESTAMP_DER[:-1],
        b"\x30\x0f" + b"timestamp-tokem",
    ],
)
def test_verify_timestamp_binds_returned_encoded_context_size_and_bytes(
    monkeypatch: pytest.MonkeyPatch, encoded: bytes
) -> None:
    crypt32 = _RecordingTimestampCrypt(encoded=encoded)
    api = _api_with_recording_crypt(crypt32)
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_timestamp_message_algorithms",
        lambda _self, _token: ("sha256", "rsa_pkcs1v15"),
    )

    with pytest.raises(ValueError, match="Timestamp evidence"):
        api.verify_timestamp(_TIMESTAMP_DER, b"primary-signature")

    assert crypt32.cleanup_calls == ["context", "signer", "store"]


@pytest.mark.parametrize(
    "token",
    [
        _TIMESTAMP_DER + b"\x00",
        b"\x30\x81\x0f" + b"timestamp-token",
        b"\x30\x80\x00\x00",
    ],
)
def test_verify_timestamp_rejects_noncanonical_or_trailing_outer_der_before_native(
    monkeypatch: pytest.MonkeyPatch, token: bytes
) -> None:
    crypt32 = _RecordingTimestampCrypt()
    api = _api_with_recording_crypt(crypt32)

    def must_not_query(_self: object, _token: bytes) -> tuple[str, str]:
        raise AssertionError("timestamp CMS queried before outer DER validation")

    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_timestamp_message_algorithms",
        must_not_query,
    )

    with pytest.raises(ValueError, match="Timestamp token encoding is invalid"):
        api.verify_timestamp(token, b"primary-signature")

    assert crypt32.cleanup_calls == []


class _RecordingCertificateCrypt:
    def __init__(
        self,
        *,
        key_oid: str = native_module._RSA_ENCRYPTION_OID,
        ekus: tuple[str, ...] = (native_module._CODE_SIGNING_EKU_OID,),
    ) -> None:
        self.encoded_bytes = b"reviewed-signer-certificate"
        self.encoded = ctypes.create_string_buffer(self.encoded_bytes)
        self.serial = ctypes.create_string_buffer(b"\x34\x12")
        self.key_oid = ctypes.create_string_buffer(key_oid.encode("ascii"))
        self.cert_info = native_module._CertInfo()
        self.cert_info.serial_number = native_module._CryptBlob(
            2, ctypes.cast(self.serial, ctypes.c_void_p)
        )
        self.cert_info.subject_public_key_info.algorithm.oid = ctypes.cast(
            self.key_oid, ctypes.c_void_p
        )
        epoch_ticks = 116_444_736_000_000_000
        day_ticks = 86_400 * 10_000_000
        self.cert_info.not_before = native_module._FileTime(
            epoch_ticks & 0xFFFFFFFF, epoch_ticks >> 32
        )
        self.cert_info.not_after = native_module._FileTime(
            (epoch_ticks + day_ticks) & 0xFFFFFFFF,
            (epoch_ticks + day_ticks) >> 32,
        )
        self.context = native_module._CertContext(
            native_module._ENCODING_TYPES,
            ctypes.cast(self.encoded, ctypes.c_void_p),
            len(self.encoded_bytes),
            ctypes.pointer(self.cert_info),
            222,
        )
        self.names = {
            (0, native_module._SUBJECT_CN_OID): "Vendor Runtime Signer",
            (0, native_module._SUBJECT_O_OID): "Vendor Organization",
            (
                native_module._CERT_NAME_ISSUER_FLAG,
                native_module._SUBJECT_CN_OID,
            ): "Vendor Issuing CA",
        }
        self.eku_values = tuple(value.encode("ascii") for value in ekus)
        self.eku_array = (ctypes.c_char_p * len(self.eku_values))(*self.eku_values)
        self.name_calls: list[tuple[int, bytes, bool]] = []
        self.eku_calls: list[tuple[int, bool]] = []
        self.public_key_calls: list[int] = []

    def CertGetNameStringW(
        self,
        _certificate: object,
        name_type: int,
        flags: int,
        oid_pointer: object,
        output: object,
        output_size: int,
    ) -> int:
        oid = ctypes.cast(oid_pointer, ctypes.c_char_p).value
        assert isinstance(oid, bytes)
        self.name_calls.append((flags, oid, output is not None))
        assert name_type == native_module._CERT_NAME_ATTR_TYPE
        value = self.names[(flags, oid)]
        required = len(value) + 1
        if output is None:
            assert output_size == 0
            return required
        assert output_size == required
        output.value = value
        return required

    def CertGetEnhancedKeyUsage(
        self,
        _certificate: object,
        flags: int,
        output: object,
        size_pointer: object,
    ) -> int:
        self.eku_calls.append((flags, output is not None))
        assert flags == native_module._CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG
        size = ctypes.cast(size_pointer, ctypes.POINTER(ctypes.c_uint32)).contents
        required = ctypes.sizeof(native_module._CertEnhKeyUsage)
        if output is None:
            size.value = required
            return 1
        assert size.value == required
        usage = native_module._CertEnhKeyUsage(
            len(self.eku_values),
            ctypes.cast(self.eku_array, ctypes.POINTER(ctypes.c_char_p)),
        )
        ctypes.memmove(output, ctypes.byref(usage), required)
        size.value = required
        return 1

    def CertGetPublicKeyLength(self, encoding: int, _key: object) -> int:
        self.public_key_calls.append(encoding)
        return 3072


def test_signer_certificate_facts_extract_exact_identity_key_and_explicit_eku() -> None:
    crypt32 = _RecordingCertificateCrypt(
        ekus=(
            native_module._CODE_SIGNING_EKU_OID,
            native_module._TIME_STAMPING_EKU_OID,
        )
    )
    api = _api_with_recording_crypt(crypt32)

    facts = api._signer_certificate_facts(ctypes.pointer(crypt32.context))

    assert facts.certificate_sha256 == hashlib.sha256(crypt32.encoded_bytes).hexdigest()
    assert facts.subject_common_name == "Vendor Runtime Signer"
    assert facts.subject_organization == "Vendor Organization"
    assert facts.issuer_common_name == "Vendor Issuing CA"
    assert facts.serial_number == "1234"
    assert facts.not_before_utc == "1970-01-01T00:00:00Z"
    assert facts.not_after_utc == "1970-01-02T00:00:00Z"
    assert facts.public_key_algorithm == "rsa"
    assert facts.public_key_bits == 3072
    assert facts.code_signing_eku is True
    assert crypt32.public_key_calls == [native_module._ENCODING_TYPES]
    assert crypt32.name_calls == [
        (0, native_module._SUBJECT_CN_OID, False),
        (0, native_module._SUBJECT_CN_OID, True),
        (0, native_module._SUBJECT_O_OID, False),
        (0, native_module._SUBJECT_O_OID, True),
        (
            native_module._CERT_NAME_ISSUER_FLAG,
            native_module._SUBJECT_CN_OID,
            False,
        ),
        (
            native_module._CERT_NAME_ISSUER_FLAG,
            native_module._SUBJECT_CN_OID,
            True,
        ),
    ]
    assert crypt32.eku_calls == [
        (native_module._CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, False),
        (native_module._CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, True),
    ]


def test_signer_certificate_facts_reject_wrong_public_key_before_identity_copy() -> (
    None
):
    crypt32 = _RecordingCertificateCrypt(key_oid="1.2.840.10045.2.1")
    api = _api_with_recording_crypt(crypt32)

    with pytest.raises(ValueError, match="public key"):
        api._signer_certificate_facts(ctypes.pointer(crypt32.context))

    assert crypt32.public_key_calls == []
    assert crypt32.name_calls == []
    assert crypt32.eku_calls == []


def test_absent_explicit_code_signing_eku_fails_independent_publisher_chain() -> None:
    crypt32 = _RecordingCertificateCrypt(ekus=(native_module._TIME_STAMPING_EKU_OID,))
    api = _api_with_recording_crypt(crypt32)

    facts = api._signer_certificate_facts(ctypes.pointer(crypt32.context))
    assert facts.code_signing_eku is False

    with pytest.raises(ValueError, match="chain input"):
        api._build_independent_chain(
            ctypes.pointer(crypt32.context),
            ctypes.c_void_p(222),
            crypt32.cert_info.not_before,
            required_eku=native_module._CODE_SIGNING_EKU_OID,
            policy=native_module._CERT_CHAIN_POLICY_AUTHENTICODE,
        )

    assert crypt32.eku_calls == [
        (native_module._CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, False),
        (native_module._CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, True),
        (native_module._CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, False),
        (native_module._CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, True),
    ]


class _RecordingCryptChain:
    def __init__(
        self,
        *,
        aggregate_error: int = 0,
        simple_error: int = 0,
        element_error: int = 0,
        policy_error: int = 0,
    ) -> None:
        self.encoded = ctypes.create_string_buffer(b"reviewed-chain-cert")
        self.key_oid = ctypes.create_string_buffer(
            native_module._RSA_ENCRYPTION_OID.encode("ascii")
        )
        self.cert_info = native_module._CertInfo()
        self.cert_info.subject_public_key_info.algorithm.oid = ctypes.cast(
            self.key_oid, ctypes.c_void_p
        )
        self.cert_context = native_module._CertContext(
            native_module._ENCODING_TYPES,
            ctypes.cast(self.encoded, ctypes.c_void_p),
            len(b"reviewed-chain-cert"),
            ctypes.pointer(self.cert_info),
            222,
        )
        self.element = native_module._CertChainElement()
        self.element.size = ctypes.sizeof(native_module._CertChainElement)
        self.element.cert_context = ctypes.pointer(self.cert_context)
        self.element.trust_status.error_status = element_error
        self.elements = (ctypes.POINTER(native_module._CertChainElement) * 1)(
            ctypes.pointer(self.element)
        )
        self.simple = native_module._CertSimpleChain()
        self.simple.size = ctypes.sizeof(native_module._CertSimpleChain)
        self.simple.trust_status.error_status = simple_error
        self.simple.element_count = 1
        self.simple.elements = self.elements
        self.chains = (ctypes.POINTER(native_module._CertSimpleChain) * 1)(
            ctypes.pointer(self.simple)
        )
        self.chain = native_module._CertChainContext()
        self.chain.size = ctypes.sizeof(native_module._CertChainContext)
        self.chain.trust_status.error_status = aggregate_error
        self.chain.chain_count = 1
        self.chain.chains = self.chains
        self.chain_calls: list[dict[str, object]] = []
        self.policy_calls: list[int] = []
        self.free_calls = 0
        self.policy_error = policy_error

    def CertGetPublicKeyLength(self, _encoding: int, _key: object) -> int:
        return 4096

    def CertGetCertificateChain(
        self,
        engine: object,
        certificate: object,
        verify_time_pointer: object,
        store: ctypes.c_void_p,
        para_pointer: object,
        flags: int,
        reserved: object,
        chain_output: object,
    ) -> int:
        verify_time = ctypes.cast(
            verify_time_pointer, ctypes.POINTER(native_module._FileTime)
        ).contents
        para = ctypes.cast(
            para_pointer, ctypes.POINTER(native_module._CertChainPara)
        ).contents
        usage = para.requested_usage.usage.usages[0]
        strong = para.strong_sign.contents
        self.chain_calls.append(
            {
                "engine": engine,
                "certificate": ctypes.cast(certificate, ctypes.c_void_p).value,
                "verify_time": (verify_time.low, verify_time.high),
                "store": store.value,
                "flags": flags,
                "reserved": reserved,
                "para_size": para.size,
                "usage_match": para.requested_usage.match_type,
                "usage": usage,
                "strong_size": strong.size,
                "strong_choice": strong.info_choice,
                "strong_oid": ctypes.cast(strong.info, ctypes.c_char_p).value,
            }
        )
        output = ctypes.cast(
            chain_output,
            ctypes.POINTER(ctypes.POINTER(native_module._CertChainContext)),
        )
        output[0] = ctypes.pointer(self.chain)
        return 1

    def CertVerifyCertificateChainPolicy(
        self,
        policy: ctypes.c_void_p,
        _chain: object,
        para_pointer: object,
        status_pointer: object,
    ) -> int:
        para = ctypes.cast(
            para_pointer, ctypes.POINTER(native_module._CertChainPolicyPara)
        ).contents
        status = ctypes.cast(
            status_pointer, ctypes.POINTER(native_module._CertChainPolicyStatus)
        ).contents
        assert para.size == ctypes.sizeof(native_module._CertChainPolicyPara)
        assert para.flags == 0
        assert not para.extra_policy_para
        assert status.size == ctypes.sizeof(native_module._CertChainPolicyStatus)
        self.policy_calls.append(policy.value)
        status.error = self.policy_error
        return 1

    def CertFreeCertificateChain(self, _chain: object) -> None:
        self.free_calls += 1


@pytest.mark.parametrize(
    ("required_eku", "policy"),
    [
        (
            native_module._CODE_SIGNING_EKU_OID,
            native_module._CERT_CHAIN_POLICY_AUTHENTICODE,
        ),
        (
            native_module._TIME_STAMPING_EKU_OID,
            native_module._CERT_CHAIN_POLICY_AUTHENTICODE_TS,
        ),
    ],
)
def test_independent_chain_uses_both_cache_flags_exact_time_eku_and_policy(
    monkeypatch: pytest.MonkeyPatch, required_eku: str, policy: int
) -> None:
    crypt32 = _RecordingCryptChain()
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = crypt32
    api._wintrust = object()
    eku_calls: list[str] = []

    def has_eku(_self: object, _certificate: object, oid: str) -> bool:
        eku_calls.append(oid)
        return True

    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_certificate_has_eku",
        has_eku,
    )
    verify_time = native_module._FileTime(0x12345678, 0x01020304)

    certificates = api._build_independent_chain(
        ctypes.pointer(crypt32.cert_context),
        ctypes.c_void_p(222),
        verify_time,
        required_eku=required_eku,
        policy=policy,
    )

    assert certificates == (b"reviewed-chain-cert",)
    assert eku_calls == [required_eku]
    assert crypt32.policy_calls == [policy]
    assert crypt32.free_calls == 1
    assert len(crypt32.chain_calls) == 1
    call = crypt32.chain_calls[0]
    assert call["engine"] is None
    assert call["certificate"] == ctypes.addressof(crypt32.cert_context)
    assert call["verify_time"] == (0x12345678, 0x01020304)
    assert call["store"] == 222
    assert call["flags"] == 0xA0000304
    assert call["reserved"] is None
    assert call["para_size"] == 96
    assert call["usage_match"] == 0
    assert call["usage"] == required_eku.encode("ascii")
    assert call["strong_size"] == 16
    assert call["strong_choice"] == 2
    assert call["strong_oid"] == b"1.3.6.1.4.1.311.72.1.1"


@pytest.mark.parametrize(
    "error_location",
    ["aggregate", "simple", "element", "policy"],
)
def test_independent_chain_rejects_every_native_trust_error_and_frees_chain(
    monkeypatch: pytest.MonkeyPatch, error_location: str
) -> None:
    crypt32 = _RecordingCryptChain(
        aggregate_error=1 if error_location == "aggregate" else 0,
        simple_error=1 if error_location == "simple" else 0,
        element_error=1 if error_location == "element" else 0,
        policy_error=1 if error_location == "policy" else 0,
    )
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = crypt32
    api._wintrust = object()
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_certificate_has_eku",
        lambda _self, _certificate, _oid: True,
    )

    with pytest.raises(ValueError, match="chain"):
        api._build_independent_chain(
            ctypes.pointer(crypt32.cert_context),
            ctypes.c_void_p(222),
            native_module._FileTime(0x12345678, 0x01020304),
            required_eku=native_module._CODE_SIGNING_EKU_OID,
            policy=native_module._CERT_CHAIN_POLICY_AUTHENTICODE,
        )

    assert crypt32.free_calls == 1
    assert crypt32.policy_calls == (
        [native_module._CERT_CHAIN_POLICY_AUTHENTICODE]
        if error_location == "policy"
        else []
    )


class _InterruptingCryptChain(_RecordingCryptChain):
    def __init__(self, primary: BaseException) -> None:
        super().__init__()
        self.primary = primary

    def CertGetCertificateChain(self, *arguments: object) -> int:
        super().CertGetCertificateChain(*arguments)
        raise self.primary

    def CertFreeCertificateChain(self, _chain: object) -> None:
        self.free_calls += 1
        raise _Interruption("chain cleanup interruption")


def test_independent_chain_frees_partial_acquisition_and_preserves_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = _Interruption("chain acquisition interruption")
    crypt32 = _InterruptingCryptChain(primary)
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = crypt32
    api._wintrust = object()
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_certificate_has_eku",
        lambda _self, _certificate, _oid: True,
    )

    with pytest.raises(_Interruption) as caught:
        api._build_independent_chain(
            ctypes.pointer(crypt32.cert_context),
            ctypes.c_void_p(222),
            native_module._FileTime(0x12345678, 0x01020304),
            required_eku=native_module._CODE_SIGNING_EKU_OID,
            policy=native_module._CERT_CHAIN_POLICY_AUTHENTICODE,
        )

    assert caught.value is primary
    assert crypt32.free_calls == 1


class _CleanupInterruptingCryptChain(_RecordingCryptChain):
    def __init__(self) -> None:
        super().__init__()
        self.cleanup_error = _Interruption("chain cleanup interruption")

    def CertFreeCertificateChain(self, _chain: object) -> None:
        self.free_calls += 1
        raise self.cleanup_error


def test_independent_chain_preserves_cleanup_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    crypt32 = _CleanupInterruptingCryptChain()
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = crypt32
    api._wintrust = object()
    monkeypatch.setattr(
        native_module._CtypesWindowsAuthenticodeApi,
        "_certificate_has_eku",
        lambda _self, _certificate, _oid: True,
    )

    with pytest.raises(_Interruption) as caught:
        api._build_independent_chain(
            ctypes.pointer(crypt32.cert_context),
            ctypes.c_void_p(222),
            native_module._FileTime(0x12345678, 0x01020304),
            required_eku=native_module._CODE_SIGNING_EKU_OID,
            policy=native_module._CERT_CHAIN_POLICY_AUTHENTICODE,
        )

    assert caught.value is crypt32.cleanup_error
    assert crypt32.free_calls == 1


def _spc_content() -> bytes:
    algorithm = bytes.fromhex("300d06096086480165030402010500")
    digest_info = b"\x30\x31" + algorithm + b"\x04\x20" + (b"d" * 32)
    return b"\x30\x35\x30\x00" + digest_info


def test_spc_digest_parser_requires_exact_sha256_digest_info() -> None:
    assert native_module._spc_file_digest_algorithm(_spc_content()) == "sha256"

    sha1 = _spc_content().replace(
        bytes.fromhex("0609608648016503040201"),
        bytes.fromhex("06052b0e03021a") + b"\x00\x00\x00\x00",
    )
    wrong_length = _spc_content()[:-1]
    extra = _spc_content() + b"\x00"
    for value in (sha1, wrong_length, extra):
        with pytest.raises(ValueError):
            native_module._spc_file_digest_algorithm(value)


def test_cms_inner_content_type_is_exact_and_nul_terminated() -> None:
    assert (
        native_module._inner_content_oid(b"1.3.6.1.4.1.311.2.1.4\x00")
        == "1.3.6.1.4.1.311.2.1.4"
    )
    for value in (
        b"1.3.6.1.4.1.311.2.1.4",
        b"1.3.6.1.4.1.311.2.1.4\x00extra",
        b"\x00",
        b"content-type\x00",
    ):
        with pytest.raises(ValueError, match="content type"):
            native_module._inner_content_oid(value)


def _signer_info_with_attribute(
    oid: str, values: tuple[bytes, ...]
) -> tuple[object, tuple[object, ...]]:
    return _signer_info_with_attributes(((oid, values),))


def _signer_info_with_attributes(
    entries: tuple[tuple[str, tuple[bytes, ...]], ...],
) -> tuple[object, tuple[object, ...]]:
    oid_buffers: list[object] = []
    value_buffer_groups: list[tuple[object, ...]] = []
    blob_arrays: list[object] = []
    attribute_values: list[object] = []
    for oid, values in entries:
        oid_buffer = ctypes.create_string_buffer(oid.encode("ascii"))
        value_buffers = tuple(ctypes.create_string_buffer(value) for value in values)
        blobs = (native_module._CryptBlob * len(values))(
            *(
                native_module._CryptBlob(
                    len(value), ctypes.cast(buffer, ctypes.c_void_p)
                )
                for value, buffer in zip(values, value_buffers)
            )
        )
        attribute_values.append(
            native_module._CryptAttribute(
                ctypes.cast(oid_buffer, ctypes.c_void_p),
                len(values),
                (
                    ctypes.cast(blobs, ctypes.POINTER(native_module._CryptBlob))
                    if values
                    else None
                ),
            )
        )
        oid_buffers.append(oid_buffer)
        value_buffer_groups.append(value_buffers)
        blob_arrays.append(blobs)
    attributes = (native_module._CryptAttribute * len(entries))(*attribute_values)
    signer = native_module._CmsgSignerInfo()
    signer.unauthenticated_attributes = native_module._CryptAttributes(
        len(entries),
        (
            ctypes.cast(attributes, ctypes.POINTER(native_module._CryptAttribute))
            if entries
            else None
        ),
    )
    return signer, (
        oid_buffers,
        value_buffer_groups,
        blob_arrays,
        attributes,
    )


def test_unauthenticated_attribute_scanner_requires_nonempty_exact_forms() -> None:
    signer, keepalive = _signer_info_with_attribute(
        native_module._RFC3161_TIMESTAMP_OID, (b"token",)
    )
    assert keepalive
    assert native_module._CtypesWindowsAuthenticodeApi._unauthenticated_attributes(
        signer, maximum_copied_bytes=64
    ) == (0, 0, (b"token",))

    for oid, values in (
        (native_module._RFC3161_TIMESTAMP_OID, ()),
        (native_module._RFC3161_TIMESTAMP_OID, (b"one", b"two")),
        (native_module._LEGACY_COUNTERSIGNATURE_OID, ()),
        (native_module._NESTED_SIGNATURE_OID, ()),
        ("1.2.3.4.5", (b"unknown",)),
    ):
        signer, keepalive = _signer_info_with_attribute(oid, values)
        assert keepalive
        with pytest.raises(ValueError, match="attribute"):
            native_module._CtypesWindowsAuthenticodeApi._unauthenticated_attributes(
                signer, maximum_copied_bytes=64
            )


def test_unauthenticated_attributes_reject_before_disallowed_blob_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    copied_sizes: list[int] = []
    original_copy = native_module._copy_blob

    def recording_copy(blob: object, maximum: int) -> bytes:
        copied_sizes.append(int(blob.size))
        return original_copy(blob, maximum)

    monkeypatch.setattr(native_module, "_copy_blob", recording_copy)

    for entries, bound in (
        (
            (
                (native_module._RFC3161_TIMESTAMP_OID, (b"first",)),
                (native_module._RFC3161_TIMESTAMP_OID, (b"second",)),
            ),
            64,
        ),
        (
            (
                (native_module._RFC3161_TIMESTAMP_OID, (b"first",)),
                ("1.2.3.4.5", (b"unknown",)),
            ),
            64,
        ),
        (
            ((native_module._RFC3161_TIMESTAMP_OID, (b"one", b"two")),),
            64,
        ),
        (((native_module._RFC3161_TIMESTAMP_OID, (b"too-large",)),), 4),
    ):
        signer, keepalive = _signer_info_with_attributes(entries)
        assert keepalive
        with pytest.raises(ValueError, match="attribute"):
            native_module._CtypesWindowsAuthenticodeApi._unauthenticated_attributes(
                signer, maximum_copied_bytes=bound
            )
        assert copied_sizes == []

    for oid in (
        native_module._LEGACY_COUNTERSIGNATURE_OID,
        native_module._NESTED_SIGNATURE_OID,
    ):
        signer, keepalive = _signer_info_with_attribute(oid, (b"disallowed",))
        assert keepalive
        with pytest.raises(ValueError, match="signature form"):
            native_module._CtypesWindowsAuthenticodeApi._unauthenticated_attributes(
                signer, maximum_copied_bytes=64
            )
    assert copied_sizes == []

    signer, keepalive = _signer_info_with_attribute(
        native_module._RFC3161_TIMESTAMP_OID, (b"allowed",)
    )
    assert keepalive
    assert native_module._CtypesWindowsAuthenticodeApi._unauthenticated_attributes(
        signer, maximum_copied_bytes=7
    ) == (0, 0, (b"allowed",))
    assert copied_sizes == [7]


class _RecordingMessageCrypt:
    def __init__(
        self,
        *,
        inner_oid: str = native_module._SPC_INDIRECT_DATA_OID,
        digest_oid: str = native_module._SHA256_OID,
        signature_oid: str = native_module._RSA_ENCRYPTION_OID,
        signer_count: int = 1,
        timestamp_token: bytes | None = b"rfc3161-token",
    ) -> None:
        self.inner_content = inner_oid.encode("ascii") + b"\x00"
        self.content = _spc_content()
        entries = (
            ((native_module._RFC3161_TIMESTAMP_OID, (timestamp_token,)),)
            if timestamp_token is not None
            else ()
        )
        signer, keepalive = _signer_info_with_attributes(entries)
        self.signer = signer
        self.keepalive = keepalive
        self.digest_oid = ctypes.create_string_buffer(digest_oid.encode("ascii"))
        self.signature_oid = ctypes.create_string_buffer(signature_oid.encode("ascii"))
        self.signer_count = signer_count
        self.primary_signature = ctypes.create_string_buffer(b"cms-primary-signature")
        self.signer.hash_algorithm.oid = ctypes.cast(self.digest_oid, ctypes.c_void_p)
        self.signer.hash_encryption_algorithm.oid = ctypes.cast(
            self.signature_oid, ctypes.c_void_p
        )
        self.signer.encrypted_hash = native_module._CryptBlob(
            len(b"cms-primary-signature"),
            ctypes.cast(self.primary_signature, ctypes.c_void_p),
        )
        self.query_calls: list[tuple[int, int, int, bytes]] = []
        self.parameter_calls: list[int] = []
        self.cleanup_calls: list[str] = []

    def CryptQueryObject(self, *arguments: object) -> int:
        blob = ctypes.cast(
            arguments[1], ctypes.POINTER(native_module._CryptBlob)
        ).contents
        self.query_calls.append(
            (
                int(arguments[0]),
                int(arguments[2]),
                int(arguments[3]),
                ctypes.string_at(blob.data, blob.size),
            )
        )
        ctypes.cast(arguments[5], ctypes.POINTER(ctypes.c_uint32)).contents.value = (
            native_module._ENCODING_TYPES
        )
        ctypes.cast(arguments[6], ctypes.POINTER(ctypes.c_uint32)).contents.value = (
            native_module._CERT_QUERY_CONTENT_PKCS7_SIGNED
        )
        ctypes.cast(arguments[7], ctypes.POINTER(ctypes.c_uint32)).contents.value = (
            native_module._CERT_QUERY_FORMAT_BINARY
        )
        ctypes.cast(arguments[8], ctypes.POINTER(ctypes.c_void_p)).contents.value = 222
        ctypes.cast(arguments[9], ctypes.POINTER(ctypes.c_void_p)).contents.value = 333
        return 1

    def CryptMsgGetParam(
        self,
        _message: object,
        parameter: int,
        _index: int,
        output: object,
        size_pointer: object,
    ) -> int:
        self.parameter_calls.append(parameter)
        if parameter == native_module._CMSG_INNER_CONTENT_TYPE_PARAM:
            value = self.inner_content
        elif parameter == native_module._CMSG_SIGNER_COUNT_PARAM:
            value = struct.pack("<I", self.signer_count)
        elif parameter == native_module._CMSG_CONTENT_PARAM:
            value = self.content
        elif parameter == native_module._CMSG_SIGNER_INFO_PARAM:
            value = ctypes.string_at(
                ctypes.byref(self.signer),
                ctypes.sizeof(native_module._CmsgSignerInfo),
            )
        else:
            raise AssertionError(f"unexpected CMSG parameter {parameter}")
        size = ctypes.cast(size_pointer, ctypes.POINTER(ctypes.c_uint32)).contents
        if output:
            ctypes.memmove(output, value, len(value))
        size.value = len(value)
        return 1

    def CryptMsgClose(self, _message: object) -> int:
        self.cleanup_calls.append("message")
        return 1

    def CertCloseStore(self, _store: object, _flags: int) -> int:
        self.cleanup_calls.append("store")
        return 1


def _api_with_recording_crypt(crypt32: object) -> object:
    api = object.__new__(native_module._CtypesWindowsAuthenticodeApi)
    api._kernel32 = object()
    api._crypt32 = crypt32
    api._wintrust = object()
    return api


def test_query_embedded_message_enforces_blob_cms_content_signer_and_algorithms() -> (
    None
):
    pkcs7 = b"P" * 256
    crypt32 = _RecordingMessageCrypt()
    api = _api_with_recording_crypt(crypt32)

    message = api.query_embedded_message(pkcs7)

    assert message.primary_signer_count == 1
    assert message.file_digest_algorithm == "sha256"
    assert message.signer_signature_algorithm == "rsa_pkcs1v15"
    assert message.primary_signature == b"cms-primary-signature"
    assert message.rfc3161_tokens == (b"rfc3161-token",)
    assert crypt32.query_calls == [
        (
            native_module._CERT_QUERY_OBJECT_BLOB,
            native_module._CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
            native_module._CERT_QUERY_FORMAT_FLAG_BINARY,
            pkcs7,
        )
    ]
    assert crypt32.parameter_calls == [4, 4, 5, 5, 6, 6, 2, 2]
    assert crypt32.cleanup_calls == ["message", "store"]


@pytest.mark.parametrize(
    ("inner_oid", "digest_oid"),
    [
        ("1.2.3.4", native_module._SHA256_OID),
        (native_module._SPC_INDIRECT_DATA_OID, "1.3.14.3.2.26"),
    ],
)
def test_query_embedded_message_rejects_wrong_content_or_digest_and_cleans_up(
    inner_oid: str, digest_oid: str
) -> None:
    crypt32 = _RecordingMessageCrypt(
        inner_oid=inner_oid,
        digest_oid=digest_oid,
    )
    api = _api_with_recording_crypt(crypt32)

    with pytest.raises(ValueError):
        api.query_embedded_message(b"P" * 256)

    assert crypt32.cleanup_calls == ["message", "store"]


@pytest.mark.parametrize("signer_count", [0, 2])
def test_query_embedded_message_rejects_native_signer_cardinality_and_cleans_up(
    signer_count: int,
) -> None:
    crypt32 = _RecordingMessageCrypt(signer_count=signer_count)
    api = _api_with_recording_crypt(crypt32)

    with pytest.raises(ValueError, match="signer count"):
        api.query_embedded_message(b"P" * 256)

    assert crypt32.cleanup_calls == ["message", "store"]


def test_query_embedded_message_rejects_wrong_signature_algorithm_and_cleans_up() -> (
    None
):
    crypt32 = _RecordingMessageCrypt(signature_oid="1.2.840.10045.4.3.2")
    api = _api_with_recording_crypt(crypt32)

    with pytest.raises(ValueError, match="signature algorithm"):
        api.query_embedded_message(b"P" * 256)

    assert crypt32.cleanup_calls == ["message", "store"]


def test_timestamp_cms_requires_tstinfo_inner_content_and_exact_algorithms() -> None:
    crypt32 = _RecordingMessageCrypt(
        inner_oid=native_module._RFC3161_TSTINFO_OID,
        timestamp_token=None,
    )
    api = _api_with_recording_crypt(crypt32)

    assert api._timestamp_message_algorithms(b"T" * 128) == (
        "sha256",
        "rsa_pkcs1v15",
    )
    assert crypt32.cleanup_calls == ["message", "store"]


def test_native_module_has_no_process_mutation_or_path_reopen_api() -> None:
    source_path = ROOT / "launcher" / "towerscout_launcher" / "authenticode_native.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }

    assert "subprocess" not in imports
    assert "shutil" not in imports
    assert "winreg" not in imports
    assert "CreateFileW" not in source
    assert "ShellExecute" not in source
    assert "CERT_QUERY_OBJECT_FILE" not in source
    assert "WTD_REVOKE_NONE" not in source
    assert "WTD_REVOCATION_CHECK_NONE" not in source


def test_repr_does_not_disclose_handle_or_path() -> None:
    value = _build_pe()
    api = _FakeNativeApi(value)
    backend = NativeWindowsAuthenticodeBackend(api=api)

    rendered = repr(backend)

    assert rendered == "NativeWindowsAuthenticodeBackend(state='supported')"
    assert "runtime.exe" not in rendered
    assert "73" not in rendered
