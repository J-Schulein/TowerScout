"""Native, verification-only Windows Authenticode evidence extraction.

This module never discovers, launches, or mutates a runtime.  It reads the
same no-write/no-delete-share handle captured by :mod:`windows_security`,
validates the embedded PE certificate container with the pure bounded parser,
and asks Windows to validate the file and any RFC 3161 timestamp using only
cached revocation information.  Native failures cross the boundary only as a
sanitized :class:`WindowsSecurityError`.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol, TypeVar

from .authenticode import (
    NativeAuthenticodeFacts,
    NativeTrustStatus,
    SignerCertificateFacts,
    TimestampFacts,
    TimestampForm,
)
from .authenticode_pe import (
    MAX_CERTIFICATE_TABLE_BYTES,
    parse_embedded_authenticode_pe,
)
from .runtime_policy import SignatureForm
from .windows_security import FileSnapshot, WindowsSecurityError

# WinTrust policy constants.  These are intentionally fixed rather than
# caller-selectable; weakening any one of them changes the package trust root.
WTD_UI_NONE = 2
WTD_REVOKE_WHOLECHAIN = 1
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_REVOCATION_CHECK_CHAIN = 0x00000040
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000
WTD_DISABLE_MD2_MD4 = 0x00002000
WSS_VERIFY_SPECIFIC = 0x00000001
WSS_GET_SECONDARY_SIG_COUNT = 0x00000002

_WINTRUST_PROVIDER_FLAGS = (
    WTD_REVOCATION_CHECK_CHAIN | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4
)
_WINTRUST_SIGNATURE_FLAGS = WSS_VERIFY_SPECIFIC | WSS_GET_SECONDARY_SIG_COUNT
_WINTRUST_SIGNATURE_OUTPUT_FLAGS = 0xE0000000
_WINTRUST_SIGNATURE_KNOWN_FLAGS = (
    _WINTRUST_SIGNATURE_FLAGS | _WINTRUST_SIGNATURE_OUTPUT_FLAGS
)

_CERT_QUERY_OBJECT_BLOB = 2
_CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = 0x00000100
_CERT_QUERY_FORMAT_FLAG_BINARY = 0x00000002
_CERT_QUERY_CONTENT_PKCS7_SIGNED = 8
_CERT_QUERY_FORMAT_BINARY = 1
_X509_ASN_ENCODING = 0x00000001
_PKCS_7_ASN_ENCODING = 0x00010000
_ENCODING_TYPES = _X509_ASN_ENCODING | _PKCS_7_ASN_ENCODING

_CMSG_CONTENT_PARAM = 2
_CMSG_INNER_CONTENT_TYPE_PARAM = 4
_CMSG_SIGNER_COUNT_PARAM = 5
_CMSG_SIGNER_INFO_PARAM = 6

_CERT_NAME_ISSUER_FLAG = 0x00000001
_CERT_NAME_ATTR_TYPE = 3
_CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG = 0x00000002
_CERT_STRONG_SIGN_OID_INFO_CHOICE = 2
_CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL = 0x00000004
_CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE = 0x00000100
_CERT_CHAIN_TIMESTAMP_TIME = 0x00000200
_CERT_CHAIN_REVOCATION_CHECK_CHAIN = 0x20000000
_CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY = 0x80000000
_CERT_CHAIN_POLICY_AUTHENTICODE = 2
_CERT_CHAIN_POLICY_AUTHENTICODE_TS = 3
_USAGE_MATCH_TYPE_AND = 0
_SGNR_TYPE_SIGNER = 0x00000000
_SGNR_TYPE_TIMESTAMP = 0x00000010

_SHA256_OID = "2.16.840.1.101.3.4.2.1"
_RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"
_CODE_SIGNING_EKU_OID = "1.3.6.1.5.5.7.3.3"
_TIME_STAMPING_EKU_OID = "1.3.6.1.5.5.7.3.8"
_RFC3161_TIMESTAMP_OID = "1.3.6.1.4.1.311.3.3.1"
_RFC3161_TSTINFO_OID = "1.2.840.113549.1.9.16.1.4"
_LEGACY_COUNTERSIGNATURE_OID = "1.2.840.113549.1.9.6"
_NESTED_SIGNATURE_OID = "1.3.6.1.4.1.311.2.4.1"
_SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4"
_STRONG_SIGN_OS_OID = b"1.3.6.1.4.1.311.72.1.1"
_SUBJECT_CN_OID = b"2.5.4.3"
_SUBJECT_O_OID = b"2.5.4.10"

_MAX_NATIVE_ITEMS = 16
_MAX_CERTIFICATE_BYTES = 1024 * 1024
_MAX_MESSAGE_PARAMETER_BYTES = MAX_CERTIFICATE_TABLE_BYTES
_MAX_SIGNATURE_BYTES = 64 * 1024
_MAX_NAME_CHARACTERS = 512
_MAX_EKU_BYTES = 64 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_FILETIME_EPOCH_TICKS = 116_444_736_000_000_000

_CHAIN_DIGEST_DOMAIN = b"TowerScout.AuthenticodeChain.v1"


def _security_error() -> WindowsSecurityError:
    return WindowsSecurityError(
        "authenticode_verification_failed",
        "The Windows runtime signature could not be authenticated safely.",
    )


def _raise_security_error() -> None:
    raise _security_error()


@dataclass(frozen=True, slots=True, repr=False)
class _EmbeddedMessage:
    primary_signer_count: int
    file_digest_algorithm: str
    signer_signature_algorithm: str
    primary_signature: bytes = field(repr=False)
    nested_signature_count: int
    legacy_countersignature_count: int
    rfc3161_tokens: tuple[bytes, ...] = field(repr=False)

    def __post_init__(self) -> None:
        counts = (
            self.primary_signer_count,
            self.nested_signature_count,
            self.legacy_countersignature_count,
        )
        if (
            any(
                type(value) is not int or not 0 <= value <= _MAX_NATIVE_ITEMS
                for value in counts
            )
            or self.file_digest_algorithm != "sha256"
            or self.signer_signature_algorithm != "rsa_pkcs1v15"
            or not isinstance(self.primary_signature, bytes)
            or not 0 < len(self.primary_signature) <= _MAX_SIGNATURE_BYTES
            or type(self.rfc3161_tokens) is not tuple
            or len(self.rfc3161_tokens) > _MAX_NATIVE_ITEMS
            or any(
                not isinstance(token, bytes)
                or not 0 < len(token) <= MAX_CERTIFICATE_TABLE_BYTES
                for token in self.rfc3161_tokens
            )
        ):
            raise ValueError("Embedded signature evidence is invalid.")

    def __repr__(self) -> str:
        return "_EmbeddedMessage(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class _TrustedFileSigner:
    signer: SignerCertificateFacts = field(repr=False)
    chain_sha256: str = field(repr=False)
    secondary_signature_count: int
    wintrust_status: int
    provider_timestamp_chain_sha256: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.signer) is not SignerCertificateFacts
            or not _is_sha256(self.chain_sha256)
            or type(self.secondary_signature_count) is not int
            or not 0 <= self.secondary_signature_count <= _MAX_NATIVE_ITEMS
            or type(self.wintrust_status) is not int
            or isinstance(self.wintrust_status, bool)
            or (
                self.provider_timestamp_chain_sha256 is not None
                and not _is_sha256(self.provider_timestamp_chain_sha256)
            )
        ):
            raise ValueError("Trusted signer evidence is invalid.")

    def __repr__(self) -> str:
        return "_TrustedFileSigner(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class _TrustedTimestamp:
    signing_time_utc: str
    digest_algorithm: str
    signature_algorithm: str
    primary_signature_valid: bool
    chain_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not _is_utc_text(self.signing_time_utc)
            or self.digest_algorithm != "sha256"
            or self.signature_algorithm != "rsa_pkcs1v15"
            or self.primary_signature_valid is not True
            or not _is_sha256(self.chain_sha256)
        ):
            raise ValueError("Trusted timestamp evidence is invalid.")

    def __repr__(self) -> str:
        return "_TrustedTimestamp(<redacted>)"


class _AuthenticodeNativeApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def read_at(self, handle: object, offset: int, length: int) -> bytes: ...

    def query_embedded_message(self, pkcs7_der: bytes) -> _EmbeddedMessage: ...

    def verify_file(
        self,
        handle: object,
        final_path: str,
        expected_timestamp: _TrustedTimestamp | None,
        expected_primary_signature: bytes,
    ) -> _TrustedFileSigner: ...

    def verify_timestamp(
        self, token: bytes, primary_signature: bytes
    ) -> _TrustedTimestamp: ...


class _HeldHandleReader:
    __slots__ = ("_api", "_handle", "_size")

    def __init__(self, api: _AuthenticodeNativeApi, handle: object, size: int) -> None:
        if type(size) is not int or size < 0:
            raise ValueError("Held executable size is invalid.")
        self._api = api
        self._handle = handle
        self._size = size

    @property
    def size(self) -> int:
        return self._size

    def read_at(self, offset: int, length: int) -> bytes:
        return self._api.read_at(self._handle, offset, length)


class NativeWindowsAuthenticodeBackend:
    """Extract strict Authenticode facts from one already-held file handle."""

    __slots__ = ("_api",)

    def __init__(self, *, api: _AuthenticodeNativeApi | None = None) -> None:
        self._api = api if api is not None else _CtypesWindowsAuthenticodeApi()

    @property
    def supported(self) -> bool:
        try:
            return self._api.supported is True
        except Exception:
            return False

    def inspect_open_file(
        self,
        *,
        handle: object,
        snapshot: FileSnapshot,
    ) -> NativeAuthenticodeFacts:
        """Validate an embedded signature without reopening the path."""

        try:
            if (
                self._api.supported is not True
                or type(handle) is not int
                or handle <= 0
                or type(snapshot) is not FileSnapshot
            ):
                _raise_security_error()
            reader = _HeldHandleReader(self._api, handle, snapshot.size)
            pe = parse_embedded_authenticode_pe(reader)
            pkcs7_der = reader.read_at(pe.pkcs7_der_offset, pe.pkcs7_der_size)
            if not isinstance(pkcs7_der, bytes) or len(pkcs7_der) != pe.pkcs7_der_size:
                _raise_security_error()

            message = self._api.query_embedded_message(pkcs7_der)
            if (
                type(message) is not _EmbeddedMessage
                or message.primary_signer_count != 1
                or message.nested_signature_count != 0
                or message.legacy_countersignature_count != 0
                or len(message.rfc3161_tokens) > 1
            ):
                _raise_security_error()

            trusted_timestamp: _TrustedTimestamp | None = None
            if message.rfc3161_tokens:
                trusted_timestamp = self._api.verify_timestamp(
                    message.rfc3161_tokens[0], message.primary_signature
                )
                if type(trusted_timestamp) is not _TrustedTimestamp:
                    _raise_security_error()

            trusted_signer = self._api.verify_file(
                handle,
                snapshot.final_path,
                trusted_timestamp,
                message.primary_signature,
            )
            if (
                type(trusted_signer) is not _TrustedFileSigner
                or trusted_signer.wintrust_status != 0
                or trusted_signer.secondary_signature_count != 0
                or (trusted_timestamp is None)
                != (trusted_signer.provider_timestamp_chain_sha256 is None)
                or (
                    trusted_timestamp is not None
                    and trusted_signer.provider_timestamp_chain_sha256
                    != trusted_timestamp.chain_sha256
                )
            ):
                _raise_security_error()

            timestamps: tuple[TimestampFacts, ...] = ()
            if trusted_timestamp is not None:
                token = message.rfc3161_tokens[0]
                timestamps = (
                    TimestampFacts(
                        form=TimestampForm.RFC3161,
                        token_sha256=hashlib.sha256(token).hexdigest(),
                        signing_time_utc=trusted_timestamp.signing_time_utc,
                        digest_algorithm=trusted_timestamp.digest_algorithm,
                        signature_algorithm=trusted_timestamp.signature_algorithm,
                        primary_signature_valid=(
                            trusted_timestamp.primary_signature_valid
                        ),
                        chain_status=NativeTrustStatus.TRUSTED,
                        chain_sha256=trusted_timestamp.chain_sha256,
                    ),
                )

            return NativeAuthenticodeFacts(
                signature_form=SignatureForm.EMBEDDED_AUTHENTICODE,
                certificate_table_entry_count=pe.certificate_count,
                primary_signer_count=message.primary_signer_count,
                secondary_signature_count=(trusted_signer.secondary_signature_count),
                nested_signature_count=message.nested_signature_count,
                legacy_countersignature_count=(message.legacy_countersignature_count),
                embedded_signature_sha256=hashlib.sha256(pkcs7_der).hexdigest(),
                file_digest_algorithm=message.file_digest_algorithm,
                signer_signature_algorithm=message.signer_signature_algorithm,
                wintrust_status=trusted_signer.wintrust_status,
                signer_chain_status=NativeTrustStatus.TRUSTED,
                signer_chain_sha256=trusted_signer.chain_sha256,
                signer=trusted_signer.signer,
                timestamps=timestamps,
            )
        except WindowsSecurityError:
            raise
        except Exception:
            raise _security_error() from None

    def __repr__(self) -> str:
        state = "supported" if self.supported else "unavailable"
        return f"NativeWindowsAuthenticodeBackend(state={state!r})"


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_utc_text(value: object) -> bool:
    if type(value) is not str or len(value) != 20:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return value.endswith("Z")


class _Guid(ctypes.Structure):
    _fields_ = (
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    )


class _FileTime(ctypes.Structure):
    _fields_ = (("low", ctypes.c_uint32), ("high", ctypes.c_uint32))


class _CryptBlob(ctypes.Structure):
    _fields_ = (("size", ctypes.c_uint32), ("data", ctypes.c_void_p))


class _CryptBitBlob(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
        ("unused_bits", ctypes.c_uint32),
    )


class _CryptAlgorithmIdentifier(ctypes.Structure):
    _fields_ = (("oid", ctypes.c_void_p), ("parameters", _CryptBlob))


class _CertPublicKeyInfo(ctypes.Structure):
    _fields_ = (
        ("algorithm", _CryptAlgorithmIdentifier),
        ("public_key", _CryptBitBlob),
    )


class _CertExtension(ctypes.Structure):
    _fields_ = (
        ("oid", ctypes.c_void_p),
        ("critical", ctypes.c_int),
        ("value", _CryptBlob),
    )


class _CertInfo(ctypes.Structure):
    _fields_ = (
        ("version", ctypes.c_uint32),
        ("serial_number", _CryptBlob),
        ("signature_algorithm", _CryptAlgorithmIdentifier),
        ("issuer", _CryptBlob),
        ("not_before", _FileTime),
        ("not_after", _FileTime),
        ("subject", _CryptBlob),
        ("subject_public_key_info", _CertPublicKeyInfo),
        ("issuer_unique_id", _CryptBitBlob),
        ("subject_unique_id", _CryptBitBlob),
        ("extension_count", ctypes.c_uint32),
        ("extensions", ctypes.POINTER(_CertExtension)),
    )


class _CertContext(ctypes.Structure):
    _fields_ = (
        ("encoding_type", ctypes.c_uint32),
        ("encoded", ctypes.c_void_p),
        ("encoded_size", ctypes.c_uint32),
        ("cert_info", ctypes.POINTER(_CertInfo)),
        ("cert_store", ctypes.c_void_p),
    )


class _CryptAttribute(ctypes.Structure):
    _fields_ = (
        ("oid", ctypes.c_void_p),
        ("value_count", ctypes.c_uint32),
        ("values", ctypes.POINTER(_CryptBlob)),
    )


class _CryptAttributes(ctypes.Structure):
    _fields_ = (
        ("attribute_count", ctypes.c_uint32),
        ("attributes", ctypes.POINTER(_CryptAttribute)),
    )


class _CmsgSignerInfo(ctypes.Structure):
    _fields_ = (
        ("version", ctypes.c_uint32),
        ("issuer", _CryptBlob),
        ("serial_number", _CryptBlob),
        ("hash_algorithm", _CryptAlgorithmIdentifier),
        ("hash_encryption_algorithm", _CryptAlgorithmIdentifier),
        ("encrypted_hash", _CryptBlob),
        ("authenticated_attributes", _CryptAttributes),
        ("unauthenticated_attributes", _CryptAttributes),
    )


class _CertTrustStatus(ctypes.Structure):
    _fields_ = (("error_status", ctypes.c_uint32), ("info_status", ctypes.c_uint32))


class _CertChainElement(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("cert_context", ctypes.POINTER(_CertContext)),
        ("trust_status", _CertTrustStatus),
        ("revocation_info", ctypes.c_void_p),
        ("issuance_usage", ctypes.c_void_p),
        ("application_usage", ctypes.c_void_p),
        ("extended_error_info", ctypes.c_wchar_p),
    )


class _CertSimpleChain(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("trust_status", _CertTrustStatus),
        ("element_count", ctypes.c_uint32),
        ("elements", ctypes.POINTER(ctypes.POINTER(_CertChainElement))),
        ("trust_list_info", ctypes.c_void_p),
        ("has_revocation_freshness_time", ctypes.c_int),
        ("revocation_freshness_time", ctypes.c_uint32),
    )


class _CertChainContext(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("trust_status", _CertTrustStatus),
        ("chain_count", ctypes.c_uint32),
        ("chains", ctypes.POINTER(ctypes.POINTER(_CertSimpleChain))),
        ("lower_quality_chain_count", ctypes.c_uint32),
        ("lower_quality_chains", ctypes.c_void_p),
        ("has_revocation_freshness_time", ctypes.c_int),
        ("revocation_freshness_time", ctypes.c_uint32),
        ("create_flags", ctypes.c_uint32),
        ("chain_id", _Guid),
    )


class _CryptProviderCert(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("cert", ctypes.POINTER(_CertContext)),
        ("commercial", ctypes.c_int),
        ("trusted_root", ctypes.c_int),
        ("self_signed", ctypes.c_int),
        ("test_cert", ctypes.c_int),
        ("revoked_reason", ctypes.c_uint32),
        ("confidence", ctypes.c_uint32),
        ("error", ctypes.c_uint32),
        ("trust_list_context", ctypes.c_void_p),
        ("trust_list_signer_cert", ctypes.c_int),
        ("ctl_context", ctypes.c_void_p),
        ("ctl_error", ctypes.c_uint32),
        ("cyclic", ctypes.c_int),
        ("chain_element", ctypes.POINTER(_CertChainElement)),
    )


class _CryptProviderSigner(ctypes.Structure):
    pass


_CryptProviderSigner._fields_ = (
    ("size", ctypes.c_uint32),
    ("verify_as_of", _FileTime),
    ("cert_chain_count", ctypes.c_uint32),
    ("cert_chain", ctypes.POINTER(_CryptProviderCert)),
    ("signer_type", ctypes.c_uint32),
    ("signer_info", ctypes.POINTER(_CmsgSignerInfo)),
    ("error", ctypes.c_uint32),
    ("countersigner_count", ctypes.c_uint32),
    ("countersigners", ctypes.POINTER(_CryptProviderSigner)),
    ("chain_context", ctypes.POINTER(_CertChainContext)),
)


class _WinTrustFileInfo(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("file_path", ctypes.c_wchar_p),
        ("file_handle", ctypes.c_void_p),
        ("known_subject", ctypes.c_void_p),
    )


class _CertStrongSignPara(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("info_choice", ctypes.c_uint32),
        ("info", ctypes.c_void_p),
    )


class _WinTrustSignatureSettings(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("index", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("secondary_signature_count", ctypes.c_uint32),
        ("verified_signature_index", ctypes.c_uint32),
        ("crypto_policy", ctypes.POINTER(_CertStrongSignPara)),
    )


class _WinTrustDataChoice(ctypes.Union):
    _fields_ = (("file", ctypes.POINTER(_WinTrustFileInfo)), ("raw", ctypes.c_void_p))


class _WinTrustData(ctypes.Structure):
    _anonymous_ = ("choice",)
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("policy_callback_data", ctypes.c_void_p),
        ("sip_client_data", ctypes.c_void_p),
        ("ui_choice", ctypes.c_uint32),
        ("revocation_checks", ctypes.c_uint32),
        ("union_choice", ctypes.c_uint32),
        ("choice", _WinTrustDataChoice),
        ("state_action", ctypes.c_uint32),
        ("state_data", ctypes.c_void_p),
        ("url_reference", ctypes.c_wchar_p),
        ("provider_flags", ctypes.c_uint32),
        ("ui_context", ctypes.c_uint32),
        ("signature_settings", ctypes.POINTER(_WinTrustSignatureSettings)),
    )


class _CertEnhKeyUsage(ctypes.Structure):
    _fields_ = (
        ("usage_count", ctypes.c_uint32),
        ("usages", ctypes.POINTER(ctypes.c_char_p)),
    )


class _CryptTimestampAccuracy(ctypes.Structure):
    _fields_ = (
        ("seconds", ctypes.c_uint32),
        ("millis", ctypes.c_uint32),
        ("micros", ctypes.c_uint32),
    )


class _CryptTimestampInfo(ctypes.Structure):
    _fields_ = (
        ("version", ctypes.c_uint32),
        ("policy_id", ctypes.c_void_p),
        ("hash_algorithm", _CryptAlgorithmIdentifier),
        ("hashed_message", _CryptBlob),
        ("serial_number", _CryptBlob),
        ("time", _FileTime),
        ("accuracy", ctypes.POINTER(_CryptTimestampAccuracy)),
        ("ordering", ctypes.c_int),
        ("nonce", _CryptBlob),
        ("tsa", _CryptBlob),
        ("extension_count", ctypes.c_uint32),
        ("extensions", ctypes.POINTER(_CertExtension)),
    )


class _CryptTimestampContext(ctypes.Structure):
    _fields_ = (
        ("encoded_size", ctypes.c_uint32),
        ("encoded", ctypes.c_void_p),
        ("timestamp_info", ctypes.POINTER(_CryptTimestampInfo)),
    )


class _CertUsageMatch(ctypes.Structure):
    _fields_ = (("match_type", ctypes.c_uint32), ("usage", _CertEnhKeyUsage))


class _CertChainPara(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("requested_usage", _CertUsageMatch),
        ("requested_issuance_policy", _CertUsageMatch),
        ("url_retrieval_timeout", ctypes.c_uint32),
        ("check_revocation_freshness", ctypes.c_int),
        ("revocation_freshness_time", ctypes.c_uint32),
        ("cache_resync", ctypes.POINTER(_FileTime)),
        ("strong_sign", ctypes.POINTER(_CertStrongSignPara)),
        ("strong_sign_flags", ctypes.c_uint32),
    )


class _CertChainPolicyPara(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("extra_policy_para", ctypes.c_void_p),
    )


class _CertChainPolicyStatus(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("error", ctypes.c_uint32),
        ("chain_index", ctypes.c_int32),
        ("element_index", ctypes.c_int32),
        ("extra_policy_status", ctypes.c_void_p),
    )


_ACTION_GENERIC_VERIFY_V2 = _Guid(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1)


def _abi_layout_supported() -> bool:
    """Fail closed unless ctypes matches the reviewed AMD64 Windows SDK ABI."""

    return ctypes.sizeof(ctypes.c_void_p) == 8 and all(
        ctypes.sizeof(structure) == expected
        for structure, expected in (
            (_WinTrustFileInfo, 32),
            (_WinTrustSignatureSettings, 32),
            (_CertStrongSignPara, 16),
            (_WinTrustData, 88),
            (_CryptProviderSigner, 64),
            (_CryptProviderCert, 88),
            (_CertContext, 40),
            (_CmsgSignerInfo, 136),
            (_CertInfo, 208),
            (_CertChainPara, 96),
            (_CertChainContext, 72),
            (_CertSimpleChain, 40),
            (_CertChainElement, 56),
            (_CryptTimestampInfo, 144),
        )
    )


def _handle(value: object) -> ctypes.c_void_p:
    if type(value) is not int or value <= 0:
        raise OSError("Native handle is unavailable.")
    return ctypes.c_void_p(value)


def _copy_pointer(pointer: int | None, size: int, maximum: int) -> bytes:
    if (
        type(size) is not int
        or size < 0
        or size > maximum
        or (size and (type(pointer) is not int or pointer <= 0))
    ):
        raise ValueError("Native byte range is invalid.")
    if not size:
        return b""
    if not isinstance(pointer, int):
        raise ValueError("Native byte range is invalid.")
    return ctypes.string_at(pointer, size)


def _copy_blob(blob: _CryptBlob, maximum: int) -> bytes:
    return _copy_pointer(blob.data, int(blob.size), maximum)


def _read_oid(pointer: int | None) -> str:
    if not pointer:
        raise ValueError("Native algorithm identifier is invalid.")
    value = ctypes.cast(pointer, ctypes.c_char_p).value
    if (
        not isinstance(value, bytes)
        or not 1 <= len(value) <= 127
        or any(byte not in b"0123456789." for byte in value)
    ):
        raise ValueError("Native algorithm identifier is invalid.")
    return value.decode("ascii")


def _algorithm_name(oid: str, *, signature: bool = False) -> str:
    if signature:
        if oid != _RSA_ENCRYPTION_OID:
            raise ValueError("Native signature algorithm is invalid.")
        return "rsa_pkcs1v15"
    if oid != _SHA256_OID:
        raise ValueError("Native digest algorithm is invalid.")
    return "sha256"


def _inner_content_oid(value: bytes) -> str:
    if (
        not isinstance(value, bytes)
        or not 2 <= len(value) <= 128
        or value[-1:] != b"\x00"
        or b"\x00" in value[:-1]
        or any(byte not in b"0123456789." for byte in value[:-1])
    ):
        raise ValueError("Native signed-message content type is invalid.")
    return value[:-1].decode("ascii")


def _filetime_text(value: _FileTime) -> str:
    ticks = (int(value.high) << 32) | int(value.low)
    if ticks < _FILETIME_EPOCH_TICKS:
        raise ValueError("Native time is invalid.")
    seconds, remainder = divmod(ticks - _FILETIME_EPOCH_TICKS, 10_000_000)
    if remainder:
        raise ValueError("Native time precision is unsupported.")
    parsed = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _chain_digest(certificates: tuple[bytes, ...]) -> str:
    if (
        not certificates
        or len(certificates) > _MAX_NATIVE_ITEMS
        or any(
            not isinstance(value, bytes) or not 0 < len(value) <= _MAX_CERTIFICATE_BYTES
            for value in certificates
        )
    ):
        raise ValueError("Native certificate chain is invalid.")
    digest = hashlib.sha256()
    for value in (_CHAIN_DIGEST_DOMAIN, *certificates):
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _der_item(data: bytes, offset: int) -> tuple[int, int, int, int]:
    if type(offset) is not int or offset < 0 or offset + 2 > len(data):
        raise ValueError("DER value is invalid.")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise ValueError("DER value is invalid.")
    first = data[offset + 1]
    cursor = offset + 2
    if first < 0x80:
        length = first
    else:
        octets = first & 0x7F
        if octets == 0 or octets > 4 or cursor + octets > len(data):
            raise ValueError("DER value is invalid.")
        encoded = data[cursor : cursor + octets]
        if encoded[0] == 0:
            raise ValueError("DER value is invalid.")
        length = int.from_bytes(encoded, "big")
        if length < 0x80:
            raise ValueError("DER value is invalid.")
        cursor += octets
    end = cursor + length
    if end < cursor or end > len(data):
        raise ValueError("DER value is invalid.")
    return tag, cursor, end, end


def _spc_file_digest_algorithm(content: bytes) -> str:
    """Read the DigestInfo algorithm from strict SpcIndirectDataContent DER."""

    outer_tag, outer_start, outer_end, next_offset = _der_item(content, 0)
    if outer_tag != 0x30 or next_offset != len(content):
        raise ValueError("Authenticode signed content is invalid.")
    data_tag, _data_start, _data_end, cursor = _der_item(content, outer_start)
    if data_tag != 0x30:
        raise ValueError("Authenticode signed content is invalid.")
    digest_tag, digest_start, digest_end, cursor = _der_item(content, cursor)
    if digest_tag != 0x30 or cursor != outer_end:
        raise ValueError("Authenticode signed content is invalid.")
    algorithm_tag, algorithm_start, algorithm_end, cursor = _der_item(
        content, digest_start
    )
    if algorithm_tag != 0x30:
        raise ValueError("Authenticode signed content is invalid.")
    oid_tag, oid_start, oid_end, algorithm_cursor = _der_item(content, algorithm_start)
    if oid_tag != 0x06:
        raise ValueError("Authenticode signed content is invalid.")
    sha256_der_oid = bytes.fromhex("608648016503040201")
    if content[oid_start:oid_end] != sha256_der_oid:
        raise ValueError("Authenticode signed content is invalid.")
    if algorithm_cursor < algorithm_end:
        null_tag, null_start, null_end, algorithm_cursor = _der_item(
            content, algorithm_cursor
        )
        if null_tag != 0x05 or null_start != null_end:
            raise ValueError("Authenticode signed content is invalid.")
    if algorithm_cursor != algorithm_end:
        raise ValueError("Authenticode signed content is invalid.")
    value_tag, value_start, value_end, cursor = _der_item(content, cursor)
    if value_tag != 0x04 or value_end - value_start != 32 or cursor != digest_end:
        raise ValueError("Authenticode signed content is invalid.")
    return "sha256"


_Result = TypeVar("_Result")


class _CtypesWindowsAuthenticodeApi:
    """Small ctypes boundary around WinTrust, Crypt32, and held-handle I/O."""

    __slots__ = ("_crypt32", "_kernel32", "_wintrust")

    def __init__(self) -> None:
        self._crypt32 = None
        self._kernel32 = None
        self._wintrust = None
        if os.name != "nt":
            return
        try:
            win_dll = getattr(ctypes, "WinDLL")
            self._kernel32 = win_dll("kernel32", use_last_error=True)
            self._crypt32 = win_dll("crypt32", use_last_error=True)
            self._wintrust = win_dll("wintrust", use_last_error=True)
            self._configure_signatures()
        except (AttributeError, OSError, TypeError, ValueError):
            self._crypt32 = None
            self._kernel32 = None
            self._wintrust = None

    @property
    def supported(self) -> bool:
        return (
            _abi_layout_supported()
            and self._crypt32 is not None
            and self._kernel32 is not None
            and self._wintrust is not None
        )

    def _require_libraries(self) -> tuple[Any, Any, Any]:
        if not self.supported:
            raise OSError("Native Authenticode verification is unavailable.")
        return self._kernel32, self._crypt32, self._wintrust

    def _configure_signatures(self) -> None:
        kernel32, crypt32, wintrust = self._require_libraries()
        kernel32.SetFilePointerEx.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int64,
            ctypes.POINTER(ctypes.c_int64),
            ctypes.c_uint32,
        )
        kernel32.SetFilePointerEx.restype = ctypes.c_int
        kernel32.ReadFile.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        )
        kernel32.ReadFile.restype = ctypes.c_int

        crypt32.CryptQueryObject.argtypes = (
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
        )
        crypt32.CryptQueryObject.restype = ctypes.c_int
        crypt32.CryptMsgGetParam.argtypes = (
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        )
        crypt32.CryptMsgGetParam.restype = ctypes.c_int
        crypt32.CryptMsgClose.argtypes = (ctypes.c_void_p,)
        crypt32.CryptMsgClose.restype = ctypes.c_int
        crypt32.CertCloseStore.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        crypt32.CertCloseStore.restype = ctypes.c_int
        crypt32.CertGetNameStringW.argtypes = (
            ctypes.POINTER(_CertContext),
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        )
        crypt32.CertGetNameStringW.restype = ctypes.c_uint32
        crypt32.CertGetEnhancedKeyUsage.argtypes = (
            ctypes.POINTER(_CertContext),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        )
        crypt32.CertGetEnhancedKeyUsage.restype = ctypes.c_int
        crypt32.CertGetPublicKeyLength.argtypes = (
            ctypes.c_uint32,
            ctypes.POINTER(_CertPublicKeyInfo),
        )
        crypt32.CertGetPublicKeyLength.restype = ctypes.c_uint32
        crypt32.CryptVerifyTimeStampSignature.argtypes = (
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(_CryptTimestampContext)),
            ctypes.POINTER(ctypes.POINTER(_CertContext)),
            ctypes.POINTER(ctypes.c_void_p),
        )
        crypt32.CryptVerifyTimeStampSignature.restype = ctypes.c_int
        crypt32.CryptMemFree.argtypes = (ctypes.c_void_p,)
        crypt32.CryptMemFree.restype = None
        crypt32.CertFreeCertificateContext.argtypes = (ctypes.POINTER(_CertContext),)
        crypt32.CertFreeCertificateContext.restype = ctypes.c_int
        crypt32.CertGetCertificateChain.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CertContext),
            ctypes.POINTER(_FileTime),
            ctypes.c_void_p,
            ctypes.POINTER(_CertChainPara),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(_CertChainContext)),
        )
        crypt32.CertGetCertificateChain.restype = ctypes.c_int
        crypt32.CertFreeCertificateChain.argtypes = (ctypes.POINTER(_CertChainContext),)
        crypt32.CertFreeCertificateChain.restype = None
        crypt32.CertVerifyCertificateChainPolicy.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CertChainContext),
            ctypes.POINTER(_CertChainPolicyPara),
            ctypes.POINTER(_CertChainPolicyStatus),
        )
        crypt32.CertVerifyCertificateChainPolicy.restype = ctypes.c_int

        wintrust.WinVerifyTrustEx.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_Guid),
            ctypes.POINTER(_WinTrustData),
        )
        # LONG is a fixed signed 32-bit Windows type even on AMD64.
        wintrust.WinVerifyTrustEx.restype = ctypes.c_int32
        wintrust.WTHelperProvDataFromStateData.argtypes = (ctypes.c_void_p,)
        wintrust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
        wintrust.WTHelperGetProvSignerFromChain.argtypes = (
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint32,
        )
        wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.POINTER(
            _CryptProviderSigner
        )

    def read_at(self, handle: object, offset: int, length: int) -> bytes:
        kernel32, _crypt32, _wintrust = self._require_libraries()
        if (
            type(offset) is not int
            or type(length) is not int
            or offset < 0
            or length < 0
            or length > MAX_CERTIFICATE_TABLE_BYTES
        ):
            raise ValueError("Native read range is invalid.")
        native_handle = _handle(handle)
        new_position = ctypes.c_int64()
        if (
            not kernel32.SetFilePointerEx(
                native_handle,
                ctypes.c_int64(offset),
                ctypes.byref(new_position),
                0,
            )
            or int(new_position.value) != offset
        ):
            raise OSError("Native read positioning failed.")
        result = bytearray()
        remaining = length
        while remaining:
            amount = min(remaining, _READ_CHUNK_BYTES)
            buffer = ctypes.create_string_buffer(amount)
            read = ctypes.c_uint32()
            if not kernel32.ReadFile(
                native_handle,
                buffer,
                amount,
                ctypes.byref(read),
                None,
            ):
                raise OSError("Native held-handle read failed.")
            if read.value == 0 or read.value > amount:
                raise OSError("Native held-handle read was incomplete.")
            result.extend(buffer.raw[: read.value])
            remaining -= int(read.value)
        return bytes(result)

    def _message_parameter(
        self, message: ctypes.c_void_p, parameter: int, index: int = 0
    ) -> bytes:
        _kernel32, crypt32, _wintrust = self._require_libraries()
        required = ctypes.c_uint32()
        if not crypt32.CryptMsgGetParam(
            message, parameter, index, None, ctypes.byref(required)
        ):
            raise OSError("Native signed-message inspection failed.")
        if not 0 < required.value <= _MAX_MESSAGE_PARAMETER_BYTES:
            raise ValueError("Native signed-message parameter is invalid.")
        buffer = ctypes.create_string_buffer(required.value)
        supplied = ctypes.c_uint32(required.value)
        if (
            not crypt32.CryptMsgGetParam(
                message,
                parameter,
                index,
                buffer,
                ctypes.byref(supplied),
            )
            or supplied.value != required.value
        ):
            raise OSError("Native signed-message inspection failed.")
        return buffer.raw[: supplied.value]

    def _message_parameter_buffer(
        self, message: ctypes.c_void_p, parameter: int, index: int = 0
    ) -> ctypes.Array[ctypes.c_char]:
        """Retain the exact allocation used for a pointer-bearing result."""

        _kernel32, crypt32, _wintrust = self._require_libraries()
        required = ctypes.c_uint32()
        if not crypt32.CryptMsgGetParam(
            message, parameter, index, None, ctypes.byref(required)
        ):
            raise OSError("Native signed-message inspection failed.")
        if not 0 < required.value <= _MAX_MESSAGE_PARAMETER_BYTES:
            raise ValueError("Native signed-message parameter is invalid.")
        buffer = ctypes.create_string_buffer(required.value)
        supplied = ctypes.c_uint32(required.value)
        if (
            not crypt32.CryptMsgGetParam(
                message,
                parameter,
                index,
                buffer,
                ctypes.byref(supplied),
            )
            or supplied.value != required.value
        ):
            raise OSError("Native signed-message inspection failed.")
        return buffer

    def _with_message(
        self,
        encoded: bytes,
        extractor: Callable[[ctypes.c_void_p], _Result],
    ) -> _Result:
        _kernel32, crypt32, _wintrust = self._require_libraries()
        if (
            not isinstance(encoded, bytes)
            or not 0 < len(encoded) <= MAX_CERTIFICATE_TABLE_BYTES
            or not callable(extractor)
        ):
            raise ValueError("Native signed-message input is invalid.")
        encoded_buffer = ctypes.create_string_buffer(encoded)
        blob = _CryptBlob(len(encoded), ctypes.cast(encoded_buffer, ctypes.c_void_p))
        encoding = ctypes.c_uint32()
        content_type = ctypes.c_uint32()
        format_type = ctypes.c_uint32()
        cert_store = ctypes.c_void_p()
        message = ctypes.c_void_p()
        primary_error: BaseException | None = None
        result: _Result | None = None
        cleanup_failed = False
        try:
            try:
                if not crypt32.CryptQueryObject(
                    _CERT_QUERY_OBJECT_BLOB,
                    ctypes.byref(blob),
                    _CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                    _CERT_QUERY_FORMAT_FLAG_BINARY,
                    0,
                    ctypes.byref(encoding),
                    ctypes.byref(content_type),
                    ctypes.byref(format_type),
                    ctypes.byref(cert_store),
                    ctypes.byref(message),
                    None,
                ):
                    raise OSError("Native signed-message query failed.")
                if (
                    not message.value
                    or encoding.value != _ENCODING_TYPES
                    or content_type.value != _CERT_QUERY_CONTENT_PKCS7_SIGNED
                    or format_type.value != _CERT_QUERY_FORMAT_BINARY
                ):
                    raise ValueError("Native signed-message type is invalid.")
                result = extractor(message)
            except BaseException as error:
                primary_error = error
        finally:
            try:
                try:
                    if message.value and not crypt32.CryptMsgClose(message):
                        cleanup_failed = True
                except BaseException as cleanup_error:
                    if primary_error is None:
                        primary_error = cleanup_error
                    else:
                        cleanup_failed = True
            finally:
                try:
                    if cert_store.value and not crypt32.CertCloseStore(cert_store, 0):
                        cleanup_failed = True
                except BaseException as cleanup_error:
                    if primary_error is None:
                        primary_error = cleanup_error
                    else:
                        cleanup_failed = True
        if primary_error is not None:
            raise primary_error
        if cleanup_failed or result is None:
            raise OSError("Native signed-message cleanup failed.")
        return result

    def _signer_info(
        self, message: ctypes.c_void_p
    ) -> tuple[int, _CmsgSignerInfo, object]:
        signer_count_raw = self._message_parameter(message, _CMSG_SIGNER_COUNT_PARAM)
        if len(signer_count_raw) != 4:
            raise ValueError("Native signer count is invalid.")
        signer_count = struct.unpack("<I", signer_count_raw)[0]
        if signer_count != 1:
            raise ValueError("Native signer count is invalid.")
        signer_buffer = self._message_parameter_buffer(
            message, _CMSG_SIGNER_INFO_PARAM, 0
        )
        if ctypes.sizeof(signer_buffer) < ctypes.sizeof(_CmsgSignerInfo):
            raise ValueError("Native signer information is invalid.")
        signer_info = ctypes.cast(
            signer_buffer, ctypes.POINTER(_CmsgSignerInfo)
        ).contents
        return signer_count, signer_info, signer_buffer

    @staticmethod
    def _unauthenticated_attributes(
        signer_info: _CmsgSignerInfo,
        *,
        maximum_copied_bytes: int,
    ) -> tuple[int, int, tuple[bytes, ...]]:
        if (
            type(maximum_copied_bytes) is not int
            or not 0 < maximum_copied_bytes <= MAX_CERTIFICATE_TABLE_BYTES
        ):
            raise ValueError("Native unauthenticated attribute bound is invalid.")
        attributes = signer_info.unauthenticated_attributes
        count = int(attributes.attribute_count)
        if count > _MAX_NATIVE_ITEMS or (count and not attributes.attributes):
            raise ValueError("Native unauthenticated attributes are invalid.")
        timestamp_blob: _CryptBlob | None = None
        aggregate_copy_bytes = 0
        for index in range(count):
            attribute = attributes.attributes[index]
            oid = _read_oid(attribute.oid)
            if oid in {
                _LEGACY_COUNTERSIGNATURE_OID,
                _NESTED_SIGNATURE_OID,
            }:
                raise ValueError(
                    "Native unauthenticated attribute signature form is unsupported."
                )
            if oid != _RFC3161_TIMESTAMP_OID:
                # Classify before touching attacker-controlled value blobs.
                raise ValueError("Native unauthenticated attribute is unsupported.")
            if timestamp_blob is not None:
                # Reject a second token before even consulting its value array.
                raise ValueError("Native RFC 3161 timestamp attribute is invalid.")
            value_count = int(attribute.value_count)
            if value_count != 1 or not attribute.values:
                raise ValueError("Native unauthenticated attributes are invalid.")
            timestamp_blob = attribute.values[0]
            token_size = int(timestamp_blob.size)
            if (
                token_size <= 0
                or token_size > maximum_copied_bytes - aggregate_copy_bytes
                or not timestamp_blob.data
            ):
                raise ValueError("Native unauthenticated attribute bytes are invalid.")
            aggregate_copy_bytes += token_size
        if timestamp_blob is None:
            timestamps: tuple[bytes, ...] = ()
        else:
            timestamps = (_copy_blob(timestamp_blob, aggregate_copy_bytes),)
        return 0, 0, timestamps

    def query_embedded_message(self, pkcs7_der: bytes) -> _EmbeddedMessage:
        def extract(message: ctypes.c_void_p) -> _EmbeddedMessage:
            if (
                _inner_content_oid(
                    self._message_parameter(message, _CMSG_INNER_CONTENT_TYPE_PARAM)
                )
                != _SPC_INDIRECT_DATA_OID
            ):
                raise ValueError("Authenticode signed content type is invalid.")
            signer_count, signer_info, signer_buffer = self._signer_info(message)
            signer_hash_algorithm = _algorithm_name(
                _read_oid(signer_info.hash_algorithm.oid)
            )
            if signer_hash_algorithm != "sha256":
                raise ValueError("Native signer digest is invalid.")
            signature_algorithm = _algorithm_name(
                _read_oid(signer_info.hash_encryption_algorithm.oid),
                signature=True,
            )
            primary_signature = _copy_blob(
                signer_info.encrypted_hash, _MAX_SIGNATURE_BYTES
            )
            nested, legacy, timestamps = self._unauthenticated_attributes(
                signer_info,
                maximum_copied_bytes=len(pkcs7_der),
            )
            content = self._message_parameter(message, _CMSG_CONTENT_PARAM)
            result = _EmbeddedMessage(
                primary_signer_count=signer_count,
                file_digest_algorithm=_spc_file_digest_algorithm(content),
                signer_signature_algorithm=signature_algorithm,
                primary_signature=primary_signature,
                nested_signature_count=nested,
                legacy_countersignature_count=legacy,
                rfc3161_tokens=timestamps,
            )
            # CMSG_SIGNER_INFO contains pointers into this caller-owned buffer.
            # Keep it live until every pointed-to value has been copied.
            del signer_buffer
            return result

        return self._with_message(pkcs7_der, extract)

    def _certificate_name(
        self,
        certificate: Any,
        oid: bytes,
        *,
        issuer: bool = False,
    ) -> str:
        _kernel32, crypt32, _wintrust = self._require_libraries()
        oid_buffer = ctypes.create_string_buffer(oid)
        flags = _CERT_NAME_ISSUER_FLAG if issuer else 0
        required = crypt32.CertGetNameStringW(
            certificate,
            _CERT_NAME_ATTR_TYPE,
            flags,
            ctypes.cast(oid_buffer, ctypes.c_void_p),
            None,
            0,
        )
        if not 1 < required <= _MAX_NAME_CHARACTERS:
            raise ValueError("Native certificate name is invalid.")
        buffer = ctypes.create_unicode_buffer(required)
        written = crypt32.CertGetNameStringW(
            certificate,
            _CERT_NAME_ATTR_TYPE,
            flags,
            ctypes.cast(oid_buffer, ctypes.c_void_p),
            buffer,
            required,
        )
        value = buffer.value
        if (
            written != required
            or not value
            or len(value) != required - 1
            or any(
                ord(character) < 0x20 or ord(character) > 0x7E for character in value
            )
        ):
            raise ValueError("Native certificate name is invalid.")
        return value

    def _certificate_has_eku(self, certificate: Any, expected_oid: str) -> bool:
        _kernel32, crypt32, _wintrust = self._require_libraries()
        required = ctypes.c_uint32()
        if not crypt32.CertGetEnhancedKeyUsage(
            certificate,
            _CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
            None,
            ctypes.byref(required),
        ):
            return False
        if not ctypes.sizeof(_CertEnhKeyUsage) <= required.value <= _MAX_EKU_BYTES:
            return False
        buffer = ctypes.create_string_buffer(required.value)
        supplied = ctypes.c_uint32(required.value)
        if (
            not crypt32.CertGetEnhancedKeyUsage(
                certificate,
                _CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
                buffer,
                ctypes.byref(supplied),
            )
            or supplied.value != required.value
        ):
            return False
        usage = ctypes.cast(buffer, ctypes.POINTER(_CertEnhKeyUsage)).contents
        if (
            usage.usage_count == 0
            or usage.usage_count > _MAX_NATIVE_ITEMS
            or not usage.usages
        ):
            return False
        values: list[str] = []
        for index in range(int(usage.usage_count)):
            raw = usage.usages[index]
            if (
                not isinstance(raw, bytes)
                or not 1 <= len(raw) <= 127
                or any(byte not in b"0123456789." for byte in raw)
            ):
                return False
            values.append(raw.decode("ascii"))
        return expected_oid in values

    def _signer_certificate_facts(self, certificate: Any) -> SignerCertificateFacts:
        _kernel32, crypt32, _wintrust = self._require_libraries()
        if not certificate:
            raise ValueError("Native signer certificate is invalid.")
        context = certificate.contents
        if (
            context.encoding_type != _ENCODING_TYPES
            or not context.cert_info
            or not 0 < context.encoded_size <= _MAX_CERTIFICATE_BYTES
        ):
            raise ValueError("Native signer certificate is invalid.")
        encoded = _copy_pointer(
            context.encoded, int(context.encoded_size), _MAX_CERTIFICATE_BYTES
        )
        cert_info = context.cert_info.contents
        serial_little_endian = _copy_blob(cert_info.serial_number, 32)
        if not serial_little_endian:
            raise ValueError("Native signer certificate is invalid.")
        public_algorithm = _read_oid(cert_info.subject_public_key_info.algorithm.oid)
        if public_algorithm != _RSA_ENCRYPTION_OID:
            raise ValueError("Native signer public key is invalid.")
        public_key_bits = crypt32.CertGetPublicKeyLength(
            context.encoding_type,
            ctypes.byref(cert_info.subject_public_key_info),
        )
        if not 1024 <= public_key_bits <= 16384:
            raise ValueError("Native signer public key is invalid.")
        return SignerCertificateFacts(
            certificate_sha256=hashlib.sha256(encoded).hexdigest(),
            subject_common_name=self._certificate_name(certificate, _SUBJECT_CN_OID),
            subject_organization=self._certificate_name(certificate, _SUBJECT_O_OID),
            issuer_common_name=self._certificate_name(
                certificate, _SUBJECT_CN_OID, issuer=True
            ),
            serial_number=serial_little_endian[::-1].hex(),
            not_before_utc=_filetime_text(cert_info.not_before),
            not_after_utc=_filetime_text(cert_info.not_after),
            public_key_algorithm="rsa",
            public_key_bits=int(public_key_bits),
            code_signing_eku=self._certificate_has_eku(
                certificate, _CODE_SIGNING_EKU_OID
            ),
        )

    @staticmethod
    def _require_chain_context(
        chain: Any,
    ) -> tuple[bytes, ...]:
        if not chain:
            raise ValueError("Native certificate chain is invalid.")
        context = chain.contents
        if (
            context.size != ctypes.sizeof(_CertChainContext)
            or context.trust_status.error_status != 0
            or context.chain_count != 1
            or not context.chains
        ):
            raise ValueError("Native certificate chain is invalid.")
        simple = context.chains[0]
        if not simple:
            raise ValueError("Native certificate chain is invalid.")
        simple_value = simple.contents
        if (
            simple_value.size != ctypes.sizeof(_CertSimpleChain)
            or simple_value.trust_status.error_status != 0
            or not 1 <= simple_value.element_count <= _MAX_NATIVE_ITEMS
            or not simple_value.elements
        ):
            raise ValueError("Native certificate chain is invalid.")
        certificates: list[bytes] = []
        for index in range(int(simple_value.element_count)):
            element = simple_value.elements[index]
            if not element:
                raise ValueError("Native certificate chain is invalid.")
            element_value = element.contents
            if (
                element_value.size != ctypes.sizeof(_CertChainElement)
                or element_value.trust_status.error_status != 0
                or not element_value.cert_context
            ):
                raise ValueError("Native certificate chain is invalid.")
            cert = element_value.cert_context.contents
            certificates.append(
                _copy_pointer(
                    cert.encoded,
                    int(cert.encoded_size),
                    _MAX_CERTIFICATE_BYTES,
                )
            )
        return tuple(certificates)

    @staticmethod
    def _provider_chain_certificates(
        signer: _CryptProviderSigner,
    ) -> tuple[bytes, ...]:
        if (
            not 1 <= signer.cert_chain_count <= _MAX_NATIVE_ITEMS
            or not signer.cert_chain
            or not signer.chain_context
        ):
            raise ValueError("Native trust certificate chain is invalid.")
        certificates: list[bytes] = []
        for index in range(int(signer.cert_chain_count)):
            provider_cert = signer.cert_chain[index]
            if (
                provider_cert.size != ctypes.sizeof(_CryptProviderCert)
                or provider_cert.error != 0
                or provider_cert.ctl_error != 0
                or not provider_cert.cert
            ):
                raise ValueError("Native trust certificate is invalid.")
            if provider_cert.chain_element:
                chain_element = provider_cert.chain_element.contents
                if (
                    chain_element.size != ctypes.sizeof(_CertChainElement)
                    or chain_element.trust_status.error_status != 0
                ):
                    raise ValueError("Native trust certificate is invalid.")
            cert = provider_cert.cert.contents
            certificates.append(
                _copy_pointer(
                    cert.encoded,
                    int(cert.encoded_size),
                    _MAX_CERTIFICATE_BYTES,
                )
            )
        context_certificates = _CtypesWindowsAuthenticodeApi._require_chain_context(
            signer.chain_context
        )
        if tuple(certificates) != context_certificates:
            raise ValueError("Native trust certificate chain is inconsistent.")
        return tuple(certificates)

    def _build_independent_chain(
        self,
        certificate: Any,
        store: ctypes.c_void_p,
        verify_time: _FileTime,
        *,
        required_eku: str,
        policy: int,
    ) -> tuple[bytes, ...]:
        _kernel32, crypt32, _wintrust = self._require_libraries()
        if (
            not certificate
            or not self._certificate_has_eku(certificate, required_eku)
            or policy
            not in {
                _CERT_CHAIN_POLICY_AUTHENTICODE,
                _CERT_CHAIN_POLICY_AUTHENTICODE_TS,
            }
        ):
            raise ValueError("Native certificate chain input is invalid.")
        cert_info = certificate.contents.cert_info
        if not cert_info:
            raise ValueError("Native certificate chain input is invalid.")
        if (
            _read_oid(cert_info.contents.subject_public_key_info.algorithm.oid)
            != _RSA_ENCRYPTION_OID
        ):
            raise ValueError("Native certificate chain key is invalid.")
        key_bits = crypt32.CertGetPublicKeyLength(
            certificate.contents.encoding_type,
            ctypes.byref(cert_info.contents.subject_public_key_info),
        )
        if key_bits < 2048:
            raise ValueError("Native certificate chain key is invalid.")

        usage_oid = ctypes.c_char_p(required_eku.encode("ascii"))
        usage_array = (ctypes.c_char_p * 1)(usage_oid)
        strong_oid = ctypes.create_string_buffer(_STRONG_SIGN_OS_OID)
        strong = _CertStrongSignPara(
            ctypes.sizeof(_CertStrongSignPara),
            _CERT_STRONG_SIGN_OID_INFO_CHOICE,
            ctypes.cast(strong_oid, ctypes.c_void_p),
        )
        chain_para = _CertChainPara()
        chain_para.size = ctypes.sizeof(_CertChainPara)
        chain_para.requested_usage.match_type = _USAGE_MATCH_TYPE_AND
        chain_para.requested_usage.usage = _CertEnhKeyUsage(
            1, ctypes.cast(usage_array, ctypes.POINTER(ctypes.c_char_p))
        )
        chain_para.strong_sign = ctypes.pointer(strong)
        chain = ctypes.POINTER(_CertChainContext)()
        flags = (
            _CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
            | _CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE
            | _CERT_CHAIN_TIMESTAMP_TIME
            | _CERT_CHAIN_REVOCATION_CHECK_CHAIN
            | _CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY
        )
        primary_error: BaseException | None = None
        result: tuple[bytes, ...] | None = None
        cleanup_failed = False
        try:
            try:
                if (
                    not crypt32.CertGetCertificateChain(
                        None,
                        certificate,
                        ctypes.byref(verify_time),
                        store,
                        ctypes.byref(chain_para),
                        flags,
                        None,
                        ctypes.byref(chain),
                    )
                    or not chain
                ):
                    raise OSError("Native certificate chain validation failed.")
                certificates = self._require_chain_context(chain)
                policy_para = _CertChainPolicyPara(
                    ctypes.sizeof(_CertChainPolicyPara), 0, None
                )
                policy_status = _CertChainPolicyStatus()
                policy_status.size = ctypes.sizeof(_CertChainPolicyStatus)
                if (
                    not crypt32.CertVerifyCertificateChainPolicy(
                        ctypes.c_void_p(policy),
                        chain,
                        ctypes.byref(policy_para),
                        ctypes.byref(policy_status),
                    )
                    or policy_status.error != 0
                ):
                    raise ValueError("Native certificate chain is untrusted.")
                result = certificates
            except BaseException as error:
                primary_error = error
        finally:
            try:
                if chain:
                    crypt32.CertFreeCertificateChain(chain)
            except BaseException as cleanup_error:
                if primary_error is None:
                    primary_error = cleanup_error
                else:
                    cleanup_failed = True
        if primary_error is not None:
            raise primary_error
        if cleanup_failed or result is None:
            raise OSError("Native certificate chain cleanup failed.")
        return result

    def _provider_signer(
        self,
        state_data: ctypes.c_void_p,
        expected_timestamp: _TrustedTimestamp | None,
        expected_primary_signature: bytes,
    ) -> _TrustedFileSigner:
        _kernel32, _crypt32, wintrust = self._require_libraries()
        if (
            expected_timestamp is not None
            and type(expected_timestamp) is not _TrustedTimestamp
        ) or (
            not isinstance(expected_primary_signature, bytes)
            or not 0 < len(expected_primary_signature) <= _MAX_SIGNATURE_BYTES
        ):
            raise ValueError("Native trust comparison evidence is invalid.")
        provider = wintrust.WTHelperProvDataFromStateData(state_data)
        if not provider:
            raise ValueError("Native trust provider state is invalid.")
        signer = wintrust.WTHelperGetProvSignerFromChain(provider, 0, 0, 0)
        extra_signer = wintrust.WTHelperGetProvSignerFromChain(provider, 1, 0, 0)
        if not signer or extra_signer:
            raise ValueError("Native trust signer count is invalid.")
        value = signer.contents
        if (
            value.size != ctypes.sizeof(_CryptProviderSigner)
            or value.error != 0
            or value.signer_type != _SGNR_TYPE_SIGNER
            or value.countersigner_count != (1 if expected_timestamp else 0)
            or not value.signer_info
            or not 1 <= value.cert_chain_count <= _MAX_NATIVE_ITEMS
            or not value.cert_chain
            or not value.chain_context
        ):
            raise ValueError("Native trust signer evidence is invalid.")
        provider_info = value.signer_info.contents
        _algorithm_name(_read_oid(provider_info.hash_algorithm.oid))
        _algorithm_name(
            _read_oid(provider_info.hash_encryption_algorithm.oid), signature=True
        )
        provider_primary_signature = _copy_blob(
            provider_info.encrypted_hash, _MAX_SIGNATURE_BYTES
        )
        if not hmac.compare_digest(
            provider_primary_signature, expected_primary_signature
        ):
            raise ValueError("Native trust primary signature is inconsistent.")
        provider_certificates = self._provider_chain_certificates(value)
        independent_certificates = self._build_independent_chain(
            value.cert_chain[0].cert,
            value.cert_chain[0].cert.contents.cert_store,
            value.verify_as_of,
            required_eku=_CODE_SIGNING_EKU_OID,
            policy=_CERT_CHAIN_POLICY_AUTHENTICODE,
        )
        if independent_certificates != provider_certificates:
            raise ValueError("Native trust certificate chain is inconsistent.")

        provider_timestamp_chain_sha256: str | None = None
        counter = wintrust.WTHelperGetProvSignerFromChain(provider, 0, 1, 0)
        extra_counter = wintrust.WTHelperGetProvSignerFromChain(provider, 0, 1, 1)
        if expected_timestamp is None:
            if counter or extra_counter:
                raise ValueError("Native trust timestamp count is invalid.")
        else:
            if (
                not counter
                or extra_counter
                or _filetime_text(value.verify_as_of)
                != expected_timestamp.signing_time_utc
            ):
                raise ValueError("Native trust timestamp is inconsistent.")
            counter_value = counter.contents
            if (
                counter_value.size != ctypes.sizeof(_CryptProviderSigner)
                or counter_value.error != 0
                or counter_value.signer_type != _SGNR_TYPE_TIMESTAMP
                or counter_value.countersigner_count != 0
                or not counter_value.signer_info
                or _filetime_text(counter_value.verify_as_of)
                != expected_timestamp.signing_time_utc
            ):
                raise ValueError("Native trust timestamp is invalid.")
            counter_info = counter_value.signer_info.contents
            _algorithm_name(_read_oid(counter_info.hash_algorithm.oid))
            _algorithm_name(
                _read_oid(counter_info.hash_encryption_algorithm.oid),
                signature=True,
            )
            counter_certificates = self._provider_chain_certificates(counter_value)
            provider_timestamp_chain_sha256 = _chain_digest(counter_certificates)
            if provider_timestamp_chain_sha256 != expected_timestamp.chain_sha256:
                raise ValueError("Native trust timestamp chain is inconsistent.")
        return _TrustedFileSigner(
            signer=self._signer_certificate_facts(value.cert_chain[0].cert),
            chain_sha256=_chain_digest(provider_certificates),
            secondary_signature_count=0,
            wintrust_status=0,
            provider_timestamp_chain_sha256=(provider_timestamp_chain_sha256),
        )

    def verify_file(
        self,
        handle: object,
        final_path: str,
        expected_timestamp: _TrustedTimestamp | None,
        expected_primary_signature: bytes,
    ) -> _TrustedFileSigner:
        _kernel32, _crypt32, wintrust = self._require_libraries()
        if (
            type(final_path) is not str
            or not final_path
            or "\x00" in final_path
            or len(final_path) > 32_768
            or not isinstance(expected_primary_signature, bytes)
            or not 0 < len(expected_primary_signature) <= _MAX_SIGNATURE_BYTES
        ):
            raise ValueError("Native trust path is invalid.")
        native_handle = _handle(handle)
        path_buffer = ctypes.create_unicode_buffer(final_path)
        file_info = _WinTrustFileInfo(
            ctypes.sizeof(_WinTrustFileInfo),
            ctypes.cast(path_buffer, ctypes.c_wchar_p),
            native_handle,
            None,
        )
        strong_oid = ctypes.create_string_buffer(_STRONG_SIGN_OS_OID)
        strong = _CertStrongSignPara(
            ctypes.sizeof(_CertStrongSignPara),
            _CERT_STRONG_SIGN_OID_INFO_CHOICE,
            ctypes.cast(strong_oid, ctypes.c_void_p),
        )
        settings = _WinTrustSignatureSettings(
            ctypes.sizeof(_WinTrustSignatureSettings),
            0,
            _WINTRUST_SIGNATURE_FLAGS,
            0,
            0,
            ctypes.pointer(strong),
        )
        data = _WinTrustData()
        data.size = ctypes.sizeof(_WinTrustData)
        data.ui_choice = WTD_UI_NONE
        data.revocation_checks = WTD_REVOKE_WHOLECHAIN
        data.union_choice = WTD_CHOICE_FILE
        data.file = ctypes.pointer(file_info)
        data.state_action = WTD_STATEACTION_VERIFY
        data.provider_flags = _WINTRUST_PROVIDER_FLAGS
        data.signature_settings = ctypes.pointer(settings)

        result: _TrustedFileSigner | None = None
        primary_error: BaseException | None = None
        close_failed = False
        close_status = -1
        try:
            try:
                status = int(
                    wintrust.WinVerifyTrustEx(
                        _INVALID_HANDLE_VALUE,
                        ctypes.byref(_ACTION_GENERIC_VERIFY_V2),
                        ctypes.byref(data),
                    )
                )
                if status != 0:
                    raise ValueError("Native trust validation failed.")
                if (
                    settings.flags & _WINTRUST_SIGNATURE_FLAGS
                    != _WINTRUST_SIGNATURE_FLAGS
                    or settings.flags & ~_WINTRUST_SIGNATURE_KNOWN_FLAGS
                    or settings.index != 0
                    or settings.verified_signature_index != 0
                    or settings.secondary_signature_count != 0
                    or not data.state_data
                ):
                    raise ValueError("Native trust signature selection is invalid.")
                result = self._provider_signer(
                    data.state_data,
                    expected_timestamp,
                    expected_primary_signature,
                )
            except BaseException as error:
                primary_error = error
        finally:
            try:
                data.state_action = WTD_STATEACTION_CLOSE
                close_status = int(
                    wintrust.WinVerifyTrustEx(
                        _INVALID_HANDLE_VALUE,
                        ctypes.byref(_ACTION_GENERIC_VERIFY_V2),
                        ctypes.byref(data),
                    )
                )
            except BaseException as cleanup_error:
                if primary_error is None:
                    primary_error = cleanup_error
                else:
                    close_failed = True
        if primary_error is not None:
            raise primary_error
        if close_failed or close_status != 0 or result is None:
            raise OSError("Native trust state cleanup failed.")
        return result

    def _timestamp_message_algorithms(self, token: bytes) -> tuple[str, str]:
        def extract(message: ctypes.c_void_p) -> tuple[str, str]:
            if (
                _inner_content_oid(
                    self._message_parameter(message, _CMSG_INNER_CONTENT_TYPE_PARAM)
                )
                != _RFC3161_TSTINFO_OID
            ):
                raise ValueError("Timestamp signed content type is invalid.")
            _count, signer_info, signer_buffer = self._signer_info(message)
            if signer_info.unauthenticated_attributes.attribute_count != 0:
                raise ValueError("Timestamp signer attributes are invalid.")
            result = (
                _algorithm_name(_read_oid(signer_info.hash_algorithm.oid)),
                _algorithm_name(
                    _read_oid(signer_info.hash_encryption_algorithm.oid),
                    signature=True,
                ),
            )
            del signer_buffer
            return result

        return self._with_message(token, extract)

    def _timestamp_chain(
        self,
        certificate: Any,
        store: ctypes.c_void_p,
        verify_time: _FileTime,
    ) -> str:
        return _chain_digest(
            self._build_independent_chain(
                certificate,
                store,
                verify_time,
                required_eku=_TIME_STAMPING_EKU_OID,
                policy=_CERT_CHAIN_POLICY_AUTHENTICODE_TS,
            )
        )

    def verify_timestamp(
        self, token: bytes, primary_signature: bytes
    ) -> _TrustedTimestamp:
        _kernel32, crypt32, _wintrust = self._require_libraries()
        if (
            not isinstance(token, bytes)
            or not 0 < len(token) <= MAX_CERTIFICATE_TABLE_BYTES
            or not isinstance(primary_signature, bytes)
            or not 0 < len(primary_signature) <= _MAX_SIGNATURE_BYTES
        ):
            raise ValueError("Timestamp input is invalid.")
        try:
            outer_tag, _outer_start, _outer_end, next_offset = _der_item(token, 0)
        except ValueError:
            raise ValueError("Timestamp token encoding is invalid.") from None
        if outer_tag != 0x30 or next_offset != len(token):
            raise ValueError("Timestamp token encoding is invalid.")
        digest_algorithm, signature_algorithm = self._timestamp_message_algorithms(
            token
        )
        token_buffer = ctypes.create_string_buffer(token)
        signature_buffer = ctypes.create_string_buffer(primary_signature)
        timestamp_context = ctypes.POINTER(_CryptTimestampContext)()
        timestamp_signer = ctypes.POINTER(_CertContext)()
        timestamp_store = ctypes.c_void_p()
        verified = False
        primary_error: BaseException | None = None
        result: _TrustedTimestamp | None = None
        cleanup_failed = False
        try:
            try:
                verified = bool(
                    crypt32.CryptVerifyTimeStampSignature(
                        token_buffer,
                        len(token),
                        signature_buffer,
                        len(primary_signature),
                        None,
                        ctypes.byref(timestamp_context),
                        ctypes.byref(timestamp_signer),
                        ctypes.byref(timestamp_store),
                    )
                )
                if (
                    not verified
                    or not timestamp_context
                    or not timestamp_context.contents.timestamp_info
                    or not timestamp_signer
                    or not timestamp_store.value
                    or timestamp_context.contents.encoded_size != len(token)
                    or not timestamp_context.contents.encoded
                ):
                    raise ValueError("Timestamp evidence is invalid.")
                context_token = _copy_pointer(
                    timestamp_context.contents.encoded,
                    int(timestamp_context.contents.encoded_size),
                    len(token),
                )
                if not hmac.compare_digest(context_token, token):
                    raise ValueError("Timestamp evidence is inconsistent.")
                timestamp_info = timestamp_context.contents.timestamp_info.contents
                if (
                    timestamp_info.version != 1
                    or timestamp_info.hashed_message.size != 32
                    or not timestamp_info.hashed_message.data
                    or _copy_blob(timestamp_info.hashed_message, 32)
                    != hashlib.sha256(primary_signature).digest()
                ):
                    raise ValueError("Timestamp evidence is invalid.")
                info_digest = _algorithm_name(
                    _read_oid(timestamp_info.hash_algorithm.oid)
                )
                if info_digest != digest_algorithm:
                    raise ValueError("Timestamp digest is inconsistent.")
                signing_time = _filetime_text(timestamp_info.time)
                chain_sha256 = self._timestamp_chain(
                    timestamp_signer, timestamp_store, timestamp_info.time
                )
                result = _TrustedTimestamp(
                    signing_time_utc=signing_time,
                    digest_algorithm=digest_algorithm,
                    signature_algorithm=signature_algorithm,
                    primary_signature_valid=True,
                    chain_sha256=chain_sha256,
                )
            except BaseException as error:
                primary_error = error
        finally:
            try:
                try:
                    if timestamp_context:
                        crypt32.CryptMemFree(timestamp_context)
                except BaseException as cleanup_error:
                    if primary_error is None:
                        primary_error = cleanup_error
                    else:
                        cleanup_failed = True
            finally:
                try:
                    try:
                        if timestamp_signer and not crypt32.CertFreeCertificateContext(
                            timestamp_signer
                        ):
                            cleanup_failed = True
                    except BaseException as cleanup_error:
                        if primary_error is None:
                            primary_error = cleanup_error
                        else:
                            cleanup_failed = True
                finally:
                    try:
                        if timestamp_store.value and not crypt32.CertCloseStore(
                            timestamp_store, 0
                        ):
                            cleanup_failed = True
                    except BaseException as cleanup_error:
                        if primary_error is None:
                            primary_error = cleanup_error
                        else:
                            cleanup_failed = True
        if primary_error is not None:
            raise primary_error
        if cleanup_failed or result is None:
            raise OSError("Timestamp verification cleanup failed.")
        return result


__all__ = [
    "NativeWindowsAuthenticodeBackend",
]
