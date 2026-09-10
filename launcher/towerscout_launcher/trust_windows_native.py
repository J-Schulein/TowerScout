"""Verification-only Windows trust acquisition for provider TLS repair.

The production entry point in this module has no caller-selectable hostname,
trust store, proxy, TLS policy, or native adapter.  It negotiates one fixed
provider endpoint with WinHTTP, snapshots eligible certificates from the
Windows ``ROOT`` stores, and rebuilds every returned chain candidate with a
Crypt32 engine whose exclusive anchors contain only that snapshot.  Windows
``CA`` stores and certificates supplied by the server are available only as
intermediates.  Nothing in this module writes to a certificate store or
enables repair mutation.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .target_contracts import MapProvider
from .trust_policy import (
    EligibleWindowsRoot,
    NativeChainCandidate,
    NativeWindowsTrustEvidence,
    SelectedWindowsRootMaterial,
    TrustPolicyError,
    TrustPurpose,
    reject_ambient_ca_redirects,
    select_eligible_windows_root,
)

_PROVIDER_HOSTS = {
    MapProvider.GOOGLE: "maps.googleapis.com",
    MapProvider.AZURE: "atlas.microsoft.com",
}

_X509_ASN_ENCODING = 0x00000001
_PKCS_7_ASN_ENCODING = 0x00010000
_KNOWN_ENCODINGS = _X509_ASN_ENCODING | _PKCS_7_ASN_ENCODING

_CERT_STORE_PROV_MEMORY = 2
_CERT_STORE_PROV_SYSTEM_W = 10
_CERT_STORE_PROV_COLLECTION = 11
_CERT_STORE_CREATE_NEW_FLAG = 0x00002000
_CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000
_CERT_STORE_READONLY_FLAG = 0x00008000
_CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
_CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
_CERT_STORE_ADD_ALWAYS = 4
_CRYPT_E_NOT_FOUND = 0x80092004

_CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL = 0x00000004
_CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS = 0x00000080
_CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE = 0x00000100
_CERT_CHAIN_DISABLE_AIA = 0x00002000
_CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x40000000
_CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY = 0x80000000
_CERT_CHAIN_POLICY_SSL = 4
_AUTHTYPE_SERVER = 2
_USAGE_MATCH_TYPE_AND = 0

_WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4
_WINHTTP_FLAG_SECURE = 0x00800000
_WINHTTP_OPTION_CLIENT_CERT_CONTEXT = 47
_WINHTTP_OPTION_DISABLE_FEATURE = 63
_WINHTTP_OPTION_AUTOLOGON_POLICY = 77
_WINHTTP_OPTION_SECURE_PROTOCOLS = 84
_WINHTTP_OPTION_REDIRECT_POLICY = 88
_WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT = 147
_WINHTTP_DISABLE_COOKIES = 0x00000001
_WINHTTP_DISABLE_REDIRECTS = 0x00000002
_WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM = 0
_WINHTTP_OPTION_REDIRECT_POLICY_NEVER = 0
_WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 = 0x00000800
_WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 = 0x00002000
_ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED = 12044
_ERROR_WINHTTP_CLIENT_CERT_NO_PRIVATE_KEY = 12185

_SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"
_ANY_PURPOSE_OID = "2.5.29.37.0"

_MAX_CHAIN_ELEMENTS = 16
_MAX_CANDIDATES = 16
_MAX_ELIGIBLE_ROOTS = 2048
_MAX_CERTIFICATE_DER_BYTES = 128 * 1024
_MAX_ROOT_SNAPSHOT_BYTES = 32 * 1024 * 1024
_MAX_EKU_BYTES = 64 * 1024
_MAX_EKU_ITEMS = 64
_WINHTTP_TIMEOUT_MS = 10_000


class _CertTrustStatus(ctypes.Structure):
    _fields_ = (("error_status", ctypes.c_uint32), ("info_status", ctypes.c_uint32))


class _CertContext(ctypes.Structure):
    _fields_ = (
        ("encoding_type", ctypes.c_uint32),
        ("encoded", ctypes.c_void_p),
        ("encoded_size", ctypes.c_uint32),
        ("cert_info", ctypes.c_void_p),
        ("cert_store", ctypes.c_void_p),
    )


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


class _Guid(ctypes.Structure):
    _fields_ = (
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    )


class _CertChainContext(ctypes.Structure):
    pass


_CertChainContext._fields_ = (
    ("size", ctypes.c_uint32),
    ("trust_status", _CertTrustStatus),
    ("chain_count", ctypes.c_uint32),
    ("chains", ctypes.POINTER(ctypes.POINTER(_CertSimpleChain))),
    ("lower_quality_chain_count", ctypes.c_uint32),
    (
        "lower_quality_chains",
        ctypes.POINTER(ctypes.POINTER(_CertChainContext)),
    ),
    ("has_revocation_freshness_time", ctypes.c_int),
    ("revocation_freshness_time", ctypes.c_uint32),
    ("create_flags", ctypes.c_uint32),
    ("chain_id", _Guid),
)


class _CertEnhKeyUsage(ctypes.Structure):
    _fields_ = (
        ("usage_count", ctypes.c_uint32),
        ("usages", ctypes.POINTER(ctypes.c_char_p)),
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
        ("cache_resync", ctypes.c_void_p),
        ("strong_sign", ctypes.c_void_p),
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


class _SslExtraCertChainPolicyPara(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("auth_type", ctypes.c_uint32),
        ("checks", ctypes.c_uint32),
        ("server_name", ctypes.c_wchar_p),
    )


class _CertChainEngineConfig(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("restricted_root", ctypes.c_void_p),
        ("restricted_trust", ctypes.c_void_p),
        ("restricted_other", ctypes.c_void_p),
        ("additional_store_count", ctypes.c_uint32),
        ("additional_stores", ctypes.POINTER(ctypes.c_void_p)),
        ("flags", ctypes.c_uint32),
        ("url_retrieval_timeout", ctypes.c_uint32),
        ("maximum_cached_certificates", ctypes.c_uint32),
        ("cycle_detection_modulus", ctypes.c_uint32),
        ("exclusive_root", ctypes.c_void_p),
        ("exclusive_trusted_people", ctypes.c_void_p),
        ("exclusive_flags", ctypes.c_uint32),
    )


def _abi_layout_supported() -> bool:
    """Fail closed unless ctypes matches the reviewed Windows AMD64 ABI."""

    return ctypes.sizeof(ctypes.c_void_p) == 8 and all(
        ctypes.sizeof(structure) == expected
        for structure, expected in (
            (_CertContext, 40),
            (_CertChainElement, 56),
            (_CertSimpleChain, 40),
            (_CertChainContext, 72),
            (_CertChainPara, 96),
            (_CertChainPolicyPara, 16),
            (_CertChainPolicyStatus, 24),
            (_SslExtraCertChainPolicyPara, 24),
            (_CertChainEngineConfig, 88),
        )
    )


def _copy_certificate(certificate: Any) -> bytes:
    if not certificate:
        raise ValueError("Native certificate is invalid.")
    context = certificate.contents
    if (
        not context.encoding_type & _X509_ASN_ENCODING
        or context.encoding_type & ~_KNOWN_ENCODINGS
        or not 1 <= context.encoded_size <= _MAX_CERTIFICATE_DER_BYTES
        or not context.encoded
    ):
        raise ValueError("Native certificate is invalid.")
    return ctypes.string_at(context.encoded, int(context.encoded_size))


def _classify_eku_oids(oids: tuple[str, ...] | None) -> TrustPurpose | None:
    """Classify combined Windows EKU evidence; ``None`` means all purposes."""

    if oids is None:
        return TrustPurpose.ALL_PURPOSE
    if type(oids) is not tuple or any(
        type(oid) is not str
        or not 1 <= len(oid) <= 127
        or any(character not in "0123456789." for character in oid)
        for oid in oids
    ):
        raise ValueError("Native certificate purpose is invalid.")
    if _SERVER_AUTH_OID in oids:
        return TrustPurpose.SERVER_AUTH
    if _ANY_PURPOSE_OID in oids:
        return TrustPurpose.ALL_PURPOSE
    return None


class _WindowsTrustNativeApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def capture(
        self, provider: MapProvider, hostname: str
    ) -> NativeWindowsTrustEvidence: ...


def _capture_selected_windows_root_with_api(
    provider: MapProvider,
    *,
    environment: Mapping[str, str],
    api: _WindowsTrustNativeApi,
) -> SelectedWindowsRootMaterial:
    """Test seam around the fixed production native adapter."""

    reject_ambient_ca_redirects(environment)
    if type(provider) is not MapProvider:
        raise TrustPolicyError("unsupported_provider")
    hostname = _PROVIDER_HOSTS.get(provider)
    if hostname is None:
        raise TrustPolicyError("unsupported_provider")
    try:
        if api.supported is not True:
            raise TrustPolicyError("windows_trust_unavailable")
        evidence = api.capture(provider, hostname)
    except TrustPolicyError:
        raise
    except Exception:
        raise TrustPolicyError("windows_trust_unavailable") from None
    if (
        type(evidence) is not NativeWindowsTrustEvidence
        or evidence.provider is not provider
        or evidence.verified_hostname.casefold() != hostname
    ):
        raise TrustPolicyError("chain_invalid")
    return select_eligible_windows_root(evidence, environment={})


def capture_selected_windows_root(
    provider: MapProvider,
) -> SelectedWindowsRootMaterial:
    """Select one provider root using the actual process environment."""

    environment = dict(os.environ)
    reject_ambient_ca_redirects(environment)
    return _capture_selected_windows_root_with_api(
        provider,
        environment=environment,
        api=_CtypesWindowsTrustApi(),
    )


@dataclass(slots=True)
class _Cleanup:
    callback: Any


class _CtypesWindowsTrustApi:
    """Small fixed ctypes boundary around WinHTTP and Crypt32."""

    __slots__ = ("_crypt32", "_winhttp")

    def __init__(self) -> None:
        self._crypt32 = None
        self._winhttp = None
        if os.name != "nt":
            return
        try:
            win_dll = getattr(ctypes, "WinDLL")
            self._crypt32 = win_dll("crypt32", use_last_error=True)
            self._winhttp = win_dll("winhttp", use_last_error=True)
            self._configure_signatures()
        except (AttributeError, OSError, TypeError, ValueError):
            self._crypt32 = None
            self._winhttp = None

    @property
    def supported(self) -> bool:
        return (
            _abi_layout_supported()
            and self._crypt32 is not None
            and self._winhttp is not None
        )

    def _require_libraries(self) -> tuple[Any, Any]:
        if not self.supported:
            raise OSError("Windows trust verification is unavailable.")
        return self._crypt32, self._winhttp

    def _configure_signatures(self) -> None:
        crypt32, winhttp = self._require_libraries()
        crypt32.CertOpenStore.argtypes = (
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
        )
        crypt32.CertOpenStore.restype = ctypes.c_void_p
        crypt32.CertCloseStore.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        crypt32.CertCloseStore.restype = ctypes.c_int
        crypt32.CertEnumCertificatesInStore.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CertContext),
        )
        crypt32.CertEnumCertificatesInStore.restype = ctypes.POINTER(_CertContext)
        crypt32.CertGetEnhancedKeyUsage.argtypes = (
            ctypes.POINTER(_CertContext),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        )
        crypt32.CertGetEnhancedKeyUsage.restype = ctypes.c_int
        crypt32.CertAddEncodedCertificateToStore.argtypes = (
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        )
        crypt32.CertAddEncodedCertificateToStore.restype = ctypes.c_int
        crypt32.CertAddStoreToCollection.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        )
        crypt32.CertAddStoreToCollection.restype = ctypes.c_int
        crypt32.CertCreateCertificateContext.argtypes = (
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
        )
        crypt32.CertCreateCertificateContext.restype = ctypes.POINTER(_CertContext)
        crypt32.CertFreeCertificateContext.argtypes = (ctypes.POINTER(_CertContext),)
        crypt32.CertFreeCertificateContext.restype = ctypes.c_int
        crypt32.CertCreateCertificateChainEngine.argtypes = (
            ctypes.POINTER(_CertChainEngineConfig),
            ctypes.POINTER(ctypes.c_void_p),
        )
        crypt32.CertCreateCertificateChainEngine.restype = ctypes.c_int
        crypt32.CertFreeCertificateChainEngine.argtypes = (ctypes.c_void_p,)
        crypt32.CertFreeCertificateChainEngine.restype = None
        crypt32.CertGetCertificateChain.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CertContext),
            ctypes.c_void_p,
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

        winhttp.WinHttpOpen.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        )
        winhttp.WinHttpOpen.restype = ctypes.c_void_p
        winhttp.WinHttpSetTimeouts.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
        )
        winhttp.WinHttpSetTimeouts.restype = ctypes.c_int
        winhttp.WinHttpConnect.argtypes = (
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint16,
            ctypes.c_uint32,
        )
        winhttp.WinHttpConnect.restype = ctypes.c_void_p
        winhttp.WinHttpOpenRequest.argtypes = (
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
        )
        winhttp.WinHttpOpenRequest.restype = ctypes.c_void_p
        winhttp.WinHttpSetOption.argtypes = (
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
        )
        winhttp.WinHttpSetOption.restype = ctypes.c_int
        winhttp.WinHttpSendRequest.argtypes = (
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_size_t,
        )
        winhttp.WinHttpSendRequest.restype = ctypes.c_int
        winhttp.WinHttpReceiveResponse.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        winhttp.WinHttpReceiveResponse.restype = ctypes.c_int
        winhttp.WinHttpQueryOption.argtypes = (
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        )
        winhttp.WinHttpQueryOption.restype = ctypes.c_int
        winhttp.WinHttpCloseHandle.argtypes = (ctypes.c_void_p,)
        winhttp.WinHttpCloseHandle.restype = ctypes.c_int

    @staticmethod
    def _provider_pointer(value: int) -> ctypes.c_void_p:
        return ctypes.c_void_p(value)

    @staticmethod
    def _set_last_error(value: int) -> None:
        setter = getattr(ctypes, "set_last_error", None)
        if setter is not None:
            setter(value)

    @staticmethod
    def _get_last_error() -> int:
        getter = getattr(ctypes, "get_last_error", None)
        if getter is None:
            return 0
        return int(getter()) & 0xFFFFFFFF

    def _open_system_store(self, name: str, location: int) -> ctypes.c_void_p:
        crypt32, _winhttp = self._require_libraries()
        name_buffer = ctypes.create_unicode_buffer(name)
        store = crypt32.CertOpenStore(
            self._provider_pointer(_CERT_STORE_PROV_SYSTEM_W),
            0,
            None,
            location | _CERT_STORE_OPEN_EXISTING_FLAG | _CERT_STORE_READONLY_FLAG,
            ctypes.cast(name_buffer, ctypes.c_void_p),
        )
        if not store:
            raise OSError("Windows certificate store is unavailable.")
        return ctypes.c_void_p(store)

    def _open_memory_store(self, provider: int) -> ctypes.c_void_p:
        crypt32, _winhttp = self._require_libraries()
        store = crypt32.CertOpenStore(
            self._provider_pointer(provider),
            0,
            None,
            _CERT_STORE_CREATE_NEW_FLAG,
            None,
        )
        if not store:
            raise OSError("Windows certificate store is unavailable.")
        return ctypes.c_void_p(store)

    def _certificate_purpose(self, certificate: Any) -> TrustPurpose | None:
        crypt32, _winhttp = self._require_libraries()
        required = ctypes.c_uint32()
        self._set_last_error(0)
        if not crypt32.CertGetEnhancedKeyUsage(
            certificate, 0, None, ctypes.byref(required)
        ):
            if self._get_last_error() == _CRYPT_E_NOT_FOUND:
                return _classify_eku_oids(None)
            raise OSError("Windows certificate purpose is unavailable.")
        if not ctypes.sizeof(_CertEnhKeyUsage) <= required.value <= _MAX_EKU_BYTES:
            raise ValueError("Windows certificate purpose is invalid.")
        buffer = ctypes.create_string_buffer(required.value)
        supplied = ctypes.c_uint32(required.value)
        self._set_last_error(0)
        if (
            not crypt32.CertGetEnhancedKeyUsage(
                certificate, 0, buffer, ctypes.byref(supplied)
            )
            or supplied.value != required.value
        ):
            raise OSError("Windows certificate purpose is unavailable.")
        usage = ctypes.cast(buffer, ctypes.POINTER(_CertEnhKeyUsage)).contents
        if usage.usage_count > _MAX_EKU_ITEMS or (
            usage.usage_count and not usage.usages
        ):
            raise ValueError("Windows certificate purpose is invalid.")
        oids: list[str] = []
        for index in range(int(usage.usage_count)):
            value = usage.usages[index]
            if not isinstance(value, bytes):
                raise ValueError("Windows certificate purpose is invalid.")
            try:
                oids.append(value.decode("ascii"))
            except UnicodeDecodeError:
                raise ValueError("Windows certificate purpose is invalid.") from None
        return _classify_eku_oids(tuple(oids))

    def _eligible_roots(
        self, stores: tuple[ctypes.c_void_p, ...]
    ) -> tuple[EligibleWindowsRoot, ...]:
        crypt32, _winhttp = self._require_libraries()
        roots: dict[str, EligibleWindowsRoot] = {}
        total_bytes = 0
        for store in stores:
            current = ctypes.POINTER(_CertContext)()
            try:
                while True:
                    self._set_last_error(0)
                    following = crypt32.CertEnumCertificatesInStore(store, current)
                    current = ctypes.POINTER(_CertContext)()
                    if not following:
                        if self._get_last_error() != _CRYPT_E_NOT_FOUND:
                            raise OSError("Windows certificate enumeration failed.")
                        break
                    current = following
                    purpose = self._certificate_purpose(current)
                    if purpose is None:
                        continue
                    der_bytes = _copy_certificate(current)
                    fingerprint = hashlib.sha256(der_bytes).hexdigest()
                    previous = roots.get(fingerprint)
                    if previous is None:
                        total_bytes += len(der_bytes)
                        if (
                            len(roots) >= _MAX_ELIGIBLE_ROOTS
                            or total_bytes > _MAX_ROOT_SNAPSHOT_BYTES
                        ):
                            raise ValueError("Windows root snapshot is too large.")
                        roots[fingerprint] = EligibleWindowsRoot(der_bytes, purpose)
                    elif (
                        previous.purpose is TrustPurpose.ALL_PURPOSE
                        and purpose is TrustPurpose.SERVER_AUTH
                    ):
                        roots[fingerprint] = EligibleWindowsRoot(der_bytes, purpose)
            finally:
                if current and not crypt32.CertFreeCertificateContext(current):
                    raise OSError("Windows certificate cleanup failed.")
        if not roots:
            raise TrustPolicyError("root_ineligible")
        return tuple(roots[key] for key in sorted(roots))

    def _add_der(self, store: ctypes.c_void_p, der_bytes: bytes) -> None:
        crypt32, _winhttp = self._require_libraries()
        if (
            type(der_bytes) is not bytes
            or not 1 <= len(der_bytes) <= _MAX_CERTIFICATE_DER_BYTES
        ):
            raise ValueError("Certificate material is invalid.")
        buffer = ctypes.create_string_buffer(der_bytes)
        if not crypt32.CertAddEncodedCertificateToStore(
            store,
            _X509_ASN_ENCODING,
            ctypes.cast(buffer, ctypes.c_void_p),
            len(der_bytes),
            _CERT_STORE_ADD_ALWAYS,
            None,
        ):
            raise OSError("Certificate material could not be staged.")

    def _set_option_dword(
        self, handle: ctypes.c_void_p, option: int, value: int
    ) -> None:
        _crypt32, winhttp = self._require_libraries()
        option_value = ctypes.c_uint32(value)
        if not winhttp.WinHttpSetOption(
            handle,
            option,
            ctypes.byref(option_value),
            ctypes.sizeof(option_value),
        ):
            raise OSError("WinHTTP security policy could not be applied.")

    @staticmethod
    def _simple_chain_der(chain: Any, *, minimum: int) -> tuple[bytes, ...]:
        if not chain:
            raise ValueError("Native certificate chain is invalid.")
        context = chain.contents
        if (
            context.size != ctypes.sizeof(_CertChainContext)
            or context.chain_count != 1
            or not context.chains
        ):
            raise ValueError("Native certificate chain is invalid.")
        simple = context.chains[0]
        if not simple:
            raise ValueError("Native certificate chain is invalid.")
        value = simple.contents
        if (
            value.size != ctypes.sizeof(_CertSimpleChain)
            or not minimum <= value.element_count <= _MAX_CHAIN_ELEMENTS
            or not value.elements
        ):
            raise ValueError("Native certificate chain is invalid.")
        certificates: list[bytes] = []
        for index in range(int(value.element_count)):
            element = value.elements[index]
            if (
                not element
                or element.contents.size != ctypes.sizeof(_CertChainElement)
                or not element.contents.cert_context
            ):
                raise ValueError("Native certificate chain is invalid.")
            certificates.append(_copy_certificate(element.contents.cert_context))
        return tuple(certificates)

    def _server_chain(self, hostname: str) -> tuple[bytes, ...]:
        crypt32, winhttp = self._require_libraries()
        cleanups: list[_Cleanup] = []
        result: tuple[bytes, ...] | None = None
        primary_error: BaseException | None = None
        try:
            session = winhttp.WinHttpOpen(
                "TowerScout Launcher",
                _WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                None,
                None,
                0,
            )
            if not session:
                raise OSError("WinHTTP session could not be opened.")
            session_handle = ctypes.c_void_p(session)
            cleanups.append(_Cleanup(lambda: self._close_http(session_handle)))
            if not winhttp.WinHttpSetTimeouts(
                session_handle,
                _WINHTTP_TIMEOUT_MS,
                _WINHTTP_TIMEOUT_MS,
                _WINHTTP_TIMEOUT_MS,
                _WINHTTP_TIMEOUT_MS,
            ):
                raise OSError("WinHTTP timeouts could not be applied.")
            self._set_option_dword(
                session_handle,
                _WINHTTP_OPTION_SECURE_PROTOCOLS,
                _WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
                | _WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
            )
            connection = winhttp.WinHttpConnect(session_handle, hostname, 443, 0)
            if not connection:
                raise OSError("WinHTTP connection could not be opened.")
            connection_handle = ctypes.c_void_p(connection)
            cleanups.append(_Cleanup(lambda: self._close_http(connection_handle)))
            request = winhttp.WinHttpOpenRequest(
                connection_handle,
                "HEAD",
                "/",
                None,
                None,
                None,
                _WINHTTP_FLAG_SECURE,
            )
            if not request:
                raise OSError("WinHTTP request could not be opened.")
            request_handle = ctypes.c_void_p(request)
            cleanups.append(_Cleanup(lambda: self._close_http(request_handle)))
            self._set_option_dword(
                request_handle,
                _WINHTTP_OPTION_DISABLE_FEATURE,
                _WINHTTP_DISABLE_COOKIES | _WINHTTP_DISABLE_REDIRECTS,
            )
            # MEDIUM permits integrated authentication to an intranet proxy,
            # while withholding default credentials from the public provider.
            self._set_option_dword(
                request_handle,
                _WINHTTP_OPTION_AUTOLOGON_POLICY,
                _WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM,
            )
            self._set_option_dword(
                request_handle,
                _WINHTTP_OPTION_REDIRECT_POLICY,
                _WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
            )
            # The public provider probe never authenticates as a client.  This
            # also prevents WinHTTP from auto-selecting an unrelated user cert.
            if not winhttp.WinHttpSetOption(
                request_handle,
                _WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                None,
                0,
            ):
                raise OSError("WinHTTP client-certificate policy failed.")
            send_succeeded = bool(
                winhttp.WinHttpSendRequest(request_handle, None, 0, None, 0, 0, 0)
            )
            if not send_succeeded:
                send_error = self._get_last_error()
                if send_error in {
                    _ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED,
                    _ERROR_WINHTTP_CLIENT_CERT_NO_PRIVATE_KEY,
                }:
                    if not winhttp.WinHttpSetOption(
                        request_handle,
                        _WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                        None,
                        0,
                    ):
                        raise OSError("WinHTTP client-certificate policy failed.")
                    send_succeeded = bool(
                        winhttp.WinHttpSendRequest(
                            request_handle, None, 0, None, 0, 0, 0
                        )
                    )
                if not send_succeeded:
                    raise OSError(
                        self._get_last_error(), "Provider TLS request failed."
                    )
            if send_succeeded and not winhttp.WinHttpReceiveResponse(
                request_handle, None
            ):
                raise OSError(self._get_last_error(), "Provider TLS response failed.")
            chain = ctypes.POINTER(_CertChainContext)()
            length = ctypes.c_uint32(ctypes.sizeof(ctypes.c_void_p))
            if (
                not winhttp.WinHttpQueryOption(
                    request_handle,
                    _WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT,
                    ctypes.byref(chain),
                    ctypes.byref(length),
                )
                or not chain
                or length.value != ctypes.sizeof(ctypes.c_void_p)
            ):
                raise OSError("Provider TLS chain could not be captured.")
            cleanups.append(_Cleanup(lambda: crypt32.CertFreeCertificateChain(chain)))
            result = self._simple_chain_der(chain, minimum=1)
        except BaseException as error:
            primary_error = error
        cleanup_error = self._run_cleanups(cleanups)
        if primary_error is not None:
            raise primary_error
        if cleanup_error is not None:
            raise cleanup_error
        if result is None:
            raise OSError("Provider TLS chain could not be captured.")
        return result

    def _close_http(self, handle: ctypes.c_void_p) -> None:
        _crypt32, winhttp = self._require_libraries()
        if not winhttp.WinHttpCloseHandle(handle):
            raise OSError("WinHTTP cleanup failed.")

    @staticmethod
    def _run_cleanups(cleanups: list[_Cleanup]) -> BaseException | None:
        first_error: BaseException | None = None
        for cleanup in reversed(cleanups):
            try:
                cleanup.callback()
            except BaseException as error:
                if first_error is None:
                    first_error = error
        return first_error

    def _candidate(self, chain: Any, hostname: str) -> NativeChainCandidate:
        crypt32, _winhttp = self._require_libraries()
        certificates = self._simple_chain_der(chain, minimum=2)
        hostname_buffer = ctypes.create_unicode_buffer(hostname)
        ssl_extra = _SslExtraCertChainPolicyPara(
            ctypes.sizeof(_SslExtraCertChainPolicyPara),
            _AUTHTYPE_SERVER,
            0,
            ctypes.cast(hostname_buffer, ctypes.c_wchar_p),
        )
        policy_para = _CertChainPolicyPara(
            ctypes.sizeof(_CertChainPolicyPara),
            0,
            ctypes.cast(ctypes.pointer(ssl_extra), ctypes.c_void_p),
        )
        policy_status = _CertChainPolicyStatus()
        policy_status.size = ctypes.sizeof(_CertChainPolicyStatus)
        if not crypt32.CertVerifyCertificateChainPolicy(
            ctypes.c_void_p(_CERT_CHAIN_POLICY_SSL),
            chain,
            ctypes.byref(policy_para),
            ctypes.byref(policy_status),
        ):
            raise OSError("Windows TLS chain policy is unavailable.")
        return NativeChainCandidate(
            tuple(hashlib.sha256(value).hexdigest() for value in certificates),
            int(chain.contents.trust_status.error_status),
            int(policy_status.error),
        )

    def _build_candidates(
        self,
        hostname: str,
        leaf_der: bytes,
        engine: ctypes.c_void_p,
    ) -> tuple[NativeChainCandidate, ...]:
        crypt32, _winhttp = self._require_libraries()
        leaf_buffer = ctypes.create_string_buffer(leaf_der)
        leaf = crypt32.CertCreateCertificateContext(
            _X509_ASN_ENCODING,
            ctypes.cast(leaf_buffer, ctypes.c_void_p),
            len(leaf_der),
        )
        if not leaf:
            raise OSError("Provider leaf certificate could not be opened.")
        chain = ctypes.POINTER(_CertChainContext)()
        usage_oid = ctypes.c_char_p(_SERVER_AUTH_OID.encode("ascii"))
        usages = (ctypes.c_char_p * 1)(usage_oid)
        chain_para = _CertChainPara()
        chain_para.size = ctypes.sizeof(_CertChainPara)
        chain_para.requested_usage.match_type = _USAGE_MATCH_TYPE_AND
        chain_para.requested_usage.usage = _CertEnhKeyUsage(
            1, ctypes.cast(usages, ctypes.POINTER(ctypes.c_char_p))
        )
        chain_para.url_retrieval_timeout = _WINHTTP_TIMEOUT_MS
        flags = (
            _CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
            | _CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS
            | _CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE
            | _CERT_CHAIN_DISABLE_AIA
            | _CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            | _CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY
        )
        primary_error: BaseException | None = None
        result: tuple[NativeChainCandidate, ...] | None = None
        try:
            if (
                not crypt32.CertGetCertificateChain(
                    engine,
                    leaf,
                    None,
                    None,
                    ctypes.byref(chain_para),
                    flags,
                    None,
                    ctypes.byref(chain),
                )
                or not chain
            ):
                raise OSError("Windows TLS chain could not be built.")
            context = chain.contents
            if context.lower_quality_chain_count >= _MAX_CANDIDATES or (
                context.lower_quality_chain_count and not context.lower_quality_chains
            ):
                raise ValueError("Windows TLS candidate set is invalid.")
            pointers = [chain]
            pointers.extend(
                context.lower_quality_chains[index]
                for index in range(int(context.lower_quality_chain_count))
            )
            candidates: list[NativeChainCandidate] = []
            seen: set[tuple[tuple[str, ...], int, int]] = set()
            for pointer in pointers:
                candidate = self._candidate(pointer, hostname)
                key = (
                    candidate.element_fingerprints_sha256,
                    candidate.native_trust_error_status,
                    candidate.ssl_policy_error,
                )
                if key not in seen:
                    seen.add(key)
                    candidates.append(candidate)
            result = tuple(candidates)
        except BaseException as error:
            primary_error = error
        cleanup_error: BaseException | None = None
        try:
            if chain:
                crypt32.CertFreeCertificateChain(chain)
        except BaseException as error:
            cleanup_error = error
        try:
            if not crypt32.CertFreeCertificateContext(leaf) and cleanup_error is None:
                cleanup_error = OSError("Provider leaf cleanup failed.")
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
        if primary_error is not None:
            raise primary_error
        if cleanup_error is not None:
            raise cleanup_error
        if not result:
            raise OSError("Windows TLS chain could not be built.")
        return result

    def capture(
        self, provider: MapProvider, hostname: str
    ) -> NativeWindowsTrustEvidence:
        if (
            type(provider) is not MapProvider
            or _PROVIDER_HOSTS.get(provider) != hostname
        ):
            raise ValueError("Provider trust target is invalid.")
        crypt32, _winhttp = self._require_libraries()
        cleanups: list[_Cleanup] = []
        result: NativeWindowsTrustEvidence | None = None
        primary_error: BaseException | None = None
        try:
            opened_roots: list[ctypes.c_void_p] = []
            for location in (
                _CERT_SYSTEM_STORE_CURRENT_USER,
                _CERT_SYSTEM_STORE_LOCAL_MACHINE,
            ):
                store = self._open_system_store("ROOT", location)
                opened_roots.append(store)
                cleanups.append(_Cleanup(lambda store=store: self._close_store(store)))
            root_stores = tuple(opened_roots)
            opened_cas: list[ctypes.c_void_p] = []
            for location in (
                _CERT_SYSTEM_STORE_CURRENT_USER,
                _CERT_SYSTEM_STORE_LOCAL_MACHINE,
            ):
                store = self._open_system_store("CA", location)
                opened_cas.append(store)
                cleanups.append(_Cleanup(lambda store=store: self._close_store(store)))
            ca_stores = tuple(opened_cas)
            eligible_roots = self._eligible_roots(root_stores)
            root_memory = self._open_memory_store(_CERT_STORE_PROV_MEMORY)
            cleanups.append(_Cleanup(lambda: self._close_store(root_memory)))
            for root in eligible_roots:
                self._add_der(root_memory, root.der_bytes)

            server_chain = self._server_chain(hostname)
            server_memory = self._open_memory_store(_CERT_STORE_PROV_MEMORY)
            cleanups.append(_Cleanup(lambda: self._close_store(server_memory)))
            for certificate in dict.fromkeys(server_chain):
                self._add_der(server_memory, certificate)
            intermediate_collection = self._open_memory_store(
                _CERT_STORE_PROV_COLLECTION
            )
            cleanups.append(
                _Cleanup(lambda: self._close_store(intermediate_collection))
            )
            for store in (*ca_stores, server_memory):
                if not crypt32.CertAddStoreToCollection(
                    intermediate_collection, store, 0, 0
                ):
                    raise OSError("Windows intermediate store could not be assembled.")

            config = _CertChainEngineConfig()
            config.size = ctypes.sizeof(_CertChainEngineConfig)
            config.restricted_other = intermediate_collection
            config.flags = (
                _CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | _CERT_CHAIN_DISABLE_AIA
            )
            config.url_retrieval_timeout = _WINHTTP_TIMEOUT_MS
            config.exclusive_root = root_memory
            config.exclusive_flags = 0
            engine = ctypes.c_void_p()
            if (
                not crypt32.CertCreateCertificateChainEngine(
                    ctypes.byref(config), ctypes.byref(engine)
                )
                or not engine
            ):
                raise OSError("Exclusive Windows chain engine could not be created.")
            cleanups.append(
                _Cleanup(lambda: crypt32.CertFreeCertificateChainEngine(engine))
            )
            candidates = self._build_candidates(hostname, server_chain[0], engine)
            result = NativeWindowsTrustEvidence(
                provider,
                hostname,
                candidates,
                eligible_roots,
            )
        except BaseException as error:
            primary_error = error
        cleanup_error = self._run_cleanups(cleanups)
        if primary_error is not None:
            raise primary_error
        if cleanup_error is not None:
            raise cleanup_error
        if result is None:
            raise OSError("Windows trust evidence could not be captured.")
        return result

    def _close_store(self, store: ctypes.c_void_p) -> None:
        crypt32, _winhttp = self._require_libraries()
        if not crypt32.CertCloseStore(store, 0):
            raise OSError("Windows certificate store cleanup failed.")
