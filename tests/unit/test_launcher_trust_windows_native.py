from __future__ import annotations

import ctypes
import hashlib
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher import trust_windows_native as native_module  # noqa: E402
from towerscout_launcher.target_contracts import MapProvider  # noqa: E402
from towerscout_launcher.trust_policy import (  # noqa: E402
    EligibleWindowsRoot,
    NativeChainCandidate,
    NativeWindowsTrustEvidence,
    TrustPolicyError,
    TrustPurpose,
)
from towerscout_launcher.trust_windows_native import (  # noqa: E402
    _capture_selected_windows_root_with_api,
    capture_selected_windows_root,
)


class _Interruption(BaseException):
    pass


class _FakeNativeApi:
    def __init__(
        self,
        *,
        supported: object = True,
        evidence: NativeWindowsTrustEvidence | object | None = None,
        error: BaseException | None = None,
    ) -> None:
        self._supported = supported
        self.evidence = evidence
        self.error = error
        self.calls: list[tuple[MapProvider, str]] = []

    @property
    def supported(self) -> object:
        return self._supported

    def capture(self, provider: MapProvider, hostname: str) -> object:
        self.calls.append((provider, hostname))
        if self.error is not None:
            raise self.error
        return self.evidence


def _native_chain(
    certificates: tuple[bytes, ...],
    *,
    trust_error: int = 0,
) -> tuple[object, list[object]]:
    references: list[object] = []
    element_pointers: list[object] = []
    for der_bytes in certificates:
        encoded = ctypes.create_string_buffer(der_bytes)
        context = native_module._CertContext(
            native_module._X509_ASN_ENCODING,
            ctypes.cast(encoded, ctypes.c_void_p),
            len(der_bytes),
            None,
            None,
        )
        context_pointer = ctypes.pointer(context)
        element = native_module._CertChainElement()
        element.size = ctypes.sizeof(native_module._CertChainElement)
        element.cert_context = context_pointer
        element_pointer = ctypes.pointer(element)
        references.extend((encoded, context, context_pointer, element, element_pointer))
        element_pointers.append(element_pointer)
    element_array = (
        ctypes.POINTER(native_module._CertChainElement) * len(element_pointers)
    )(*element_pointers)
    simple = native_module._CertSimpleChain()
    simple.size = ctypes.sizeof(native_module._CertSimpleChain)
    simple.element_count = len(element_pointers)
    simple.elements = element_array
    simple_pointer = ctypes.pointer(simple)
    simple_array = (ctypes.POINTER(native_module._CertSimpleChain) * 1)(simple_pointer)
    context = native_module._CertChainContext()
    context.size = ctypes.sizeof(native_module._CertChainContext)
    context.trust_status.error_status = trust_error
    context.chain_count = 1
    context.chains = simple_array
    context_pointer = ctypes.pointer(context)
    references.extend(
        (
            element_array,
            simple,
            simple_pointer,
            simple_array,
            context,
            context_pointer,
        )
    )
    return context_pointer, references


def _native_api(crypt32: object, winhttp: object) -> object:
    api = native_module._CtypesWindowsTrustApi.__new__(
        native_module._CtypesWindowsTrustApi
    )
    api._crypt32 = crypt32
    api._winhttp = winhttp
    return api


def _void_value(value: object) -> int | None:
    return ctypes.cast(value, ctypes.c_void_p).value


def _evidence(provider: MapProvider) -> NativeWindowsTrustEvidence:
    hostname = {
        MapProvider.GOOGLE: "maps.googleapis.com",
        MapProvider.AZURE: "atlas.microsoft.com",
    }[provider]
    root = EligibleWindowsRoot(b"eligible-root", TrustPurpose.SERVER_AUTH)
    return NativeWindowsTrustEvidence(
        provider,
        hostname,
        (
            NativeChainCandidate(
                (
                    hashlib.sha256(b"leaf").hexdigest(),
                    hashlib.sha256(b"intermediate").hexdigest(),
                    root.fingerprint_sha256,
                ),
                0,
                0,
            ),
        ),
        (root,),
    )


@pytest.mark.parametrize(
    ("provider", "hostname"),
    (
        (MapProvider.GOOGLE, "maps.googleapis.com"),
        (MapProvider.AZURE, "atlas.microsoft.com"),
    ),
)
def test_capture_uses_only_the_fixed_provider_hostname(
    provider: MapProvider, hostname: str
) -> None:
    api = _FakeNativeApi(evidence=_evidence(provider))

    selected = _capture_selected_windows_root_with_api(
        provider, environment={}, api=api  # type: ignore[arg-type]
    )

    assert api.calls == [(provider, hostname)]
    assert selected.provider is provider
    assert selected.der_bytes == b"eligible-root"


def test_ambient_ca_redirect_is_rejected_before_any_native_call() -> None:
    api = _FakeNativeApi(evidence=_evidence(MapProvider.GOOGLE))

    with pytest.raises(TrustPolicyError) as failure:
        _capture_selected_windows_root_with_api(
            MapProvider.GOOGLE,
            environment={"SSL_CERT_FILE": r"C:\private\injected.pem"},
            api=api,  # type: ignore[arg-type]
        )

    assert failure.value.code == "ambient_ca_redirect"
    assert api.calls == []


@pytest.mark.parametrize("supported", (False, 1, "yes", None))
def test_native_support_must_be_exact_true(supported: object) -> None:
    api = _FakeNativeApi(
        supported=supported,
        evidence=_evidence(MapProvider.GOOGLE),
    )

    with pytest.raises(TrustPolicyError) as failure:
        _capture_selected_windows_root_with_api(
            MapProvider.GOOGLE, environment={}, api=api  # type: ignore[arg-type]
        )

    assert failure.value.code == "windows_trust_unavailable"
    assert api.calls == []


@pytest.mark.parametrize(
    "native_error",
    (
        OSError(r"private C:\Users\operator\root.cer"),
        ctypes.ArgumentError("private DER bytes"),
        ValueError("private provider chain"),
    ),
)
def test_native_failures_cross_the_boundary_only_as_sanitized_errors(
    native_error: Exception,
) -> None:
    api = _FakeNativeApi(error=native_error)

    with pytest.raises(TrustPolicyError) as failure:
        _capture_selected_windows_root_with_api(
            MapProvider.GOOGLE, environment={}, api=api  # type: ignore[arg-type]
        )

    assert failure.value.code == "windows_trust_unavailable"
    assert "private" not in str(failure.value)
    assert "private" not in repr(failure.value)


def test_native_interruption_is_not_swallowed() -> None:
    api = _FakeNativeApi(error=_Interruption())

    with pytest.raises(_Interruption):
        _capture_selected_windows_root_with_api(
            MapProvider.GOOGLE, environment={}, api=api  # type: ignore[arg-type]
        )


def test_untyped_or_mismatched_native_evidence_fails_closed() -> None:
    with pytest.raises(TrustPolicyError) as untyped:
        _capture_selected_windows_root_with_api(
            MapProvider.GOOGLE,
            environment={},
            api=_FakeNativeApi(evidence=object()),  # type: ignore[arg-type]
        )
    assert untyped.value.code == "chain_invalid"

    with pytest.raises(TrustPolicyError) as mismatch:
        _capture_selected_windows_root_with_api(
            MapProvider.GOOGLE,
            environment={},
            api=_FakeNativeApi(evidence=_evidence(MapProvider.AZURE)),  # type: ignore[arg-type]
        )
    assert mismatch.value.code == "chain_invalid"


def test_eku_classification_admits_only_server_auth_or_all_purpose() -> None:
    assert native_module._classify_eku_oids(None) is TrustPurpose.ALL_PURPOSE
    assert (
        native_module._classify_eku_oids(("1.3.6.1.5.5.7.3.1",))
        is TrustPurpose.SERVER_AUTH
    )
    assert (
        native_module._classify_eku_oids(("2.5.29.37.0",)) is TrustPurpose.ALL_PURPOSE
    )
    assert native_module._classify_eku_oids(("1.3.6.1.5.5.7.3.2",)) is None
    assert native_module._classify_eku_oids(()) is None
    with pytest.raises(ValueError, match="purpose is invalid"):
        native_module._classify_eku_oids(("not-an-oid",))


def test_fixed_native_flags_and_amd64_ctypes_layouts() -> None:
    assert native_module._CERT_CHAIN_POLICY_SSL == 4
    assert native_module._AUTHTYPE_SERVER == 2
    assert native_module._WINHTTP_OPTION_CLIENT_CERT_CONTEXT == 47
    assert native_module._WINHTTP_OPTION_AUTOLOGON_POLICY == 77
    assert native_module._WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM == 0
    assert native_module._WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT == 147
    assert native_module._WINHTTP_OPTION_REDIRECT_POLICY_NEVER == 0
    assert native_module._WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 == 0x800
    assert native_module._WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 == 0x2000
    assert native_module._ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED == 12044
    assert native_module._ERROR_WINHTTP_CLIENT_CERT_NO_PRIVATE_KEY == 12185
    assert native_module._CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS == 0x80
    assert native_module._CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE == 0x100
    assert native_module._CERT_CHAIN_DISABLE_AIA == 0x2000
    assert native_module._CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT == 0x40000000
    assert native_module._CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY == 0x80000000
    assert native_module._abi_layout_supported() is (
        ctypes.sizeof(ctypes.c_void_p) == 8
    )
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert ctypes.sizeof(native_module._CertChainEngineConfig) == 88
        assert ctypes.sizeof(native_module._CertChainContext) == 72
        assert ctypes.sizeof(native_module._CertChainPara) == 96
        assert ctypes.sizeof(native_module._SslExtraCertChainPolicyPara) == 24


def _certificate_context(der_bytes: bytes) -> tuple[object, tuple[object, ...]]:
    encoded = ctypes.create_string_buffer(der_bytes)
    context = native_module._CertContext(
        native_module._X509_ASN_ENCODING,
        ctypes.cast(encoded, ctypes.c_void_p),
        len(der_bytes),
        None,
        None,
    )
    pointer = ctypes.pointer(context)
    return pointer, (encoded, context, pointer)


class _RootEnumerationCrypt:
    def __init__(self) -> None:
        first, first_references = _certificate_context(b"eligible-root")
        excluded, excluded_references = _certificate_context(b"client-root")
        duplicate, duplicate_references = _certificate_context(b"eligible-root")
        self.references = (
            *first_references,
            *excluded_references,
            *duplicate_references,
        )
        self.stores = {
            11: (first, excluded),
            12: (duplicate,),
        }
        self.purposes = {
            _void_value(first): None,
            _void_value(excluded): ("1.3.6.1.5.5.7.3.2",),
            _void_value(duplicate): ("1.3.6.1.5.5.7.3.1",),
        }
        self.last_error = 0
        self.eku_references: list[object] = []
        self.freed: list[int | None] = []

    def CertEnumCertificatesInStore(self, store: object, current: object) -> object:
        certificates = self.stores[int(_void_value(store) or 0)]
        current_value = _void_value(current)
        if current_value is None:
            index = 0
        else:
            index = next(
                position + 1
                for position, certificate in enumerate(certificates)
                if _void_value(certificate) == current_value
            )
        if index >= len(certificates):
            self.last_error = native_module._CRYPT_E_NOT_FOUND
            return ctypes.POINTER(native_module._CertContext)()
        self.last_error = 0
        return certificates[index]

    def CertGetEnhancedKeyUsage(
        self,
        certificate: object,
        flags: int,
        buffer: object,
        size_pointer: object,
    ) -> int:
        assert flags == 0
        purpose = self.purposes[_void_value(certificate)]
        if purpose is None:
            self.last_error = native_module._CRYPT_E_NOT_FOUND
            return 0
        size = ctypes.cast(size_pointer, ctypes.POINTER(ctypes.c_uint32))
        if buffer is None:
            size.contents.value = ctypes.sizeof(native_module._CertEnhKeyUsage)
            self.last_error = 0
            return 1
        encoded_oids = tuple(value.encode("ascii") for value in purpose)
        oid_array = (ctypes.c_char_p * len(encoded_oids))(*encoded_oids)
        usage = native_module._CertEnhKeyUsage(len(encoded_oids), oid_array)
        self.eku_references.extend((encoded_oids, oid_array, usage))
        ctypes.memmove(buffer, ctypes.byref(usage), ctypes.sizeof(usage))
        self.last_error = 0
        return 1

    def CertFreeCertificateContext(self, certificate: object) -> int:
        self.freed.append(_void_value(certificate))
        return 1


class _RootEnumerationApi(native_module._CtypesWindowsTrustApi):
    def __init__(self, crypt32: _RootEnumerationCrypt) -> None:
        self._crypt32 = crypt32
        self._winhttp = object()

    @staticmethod
    def _set_last_error(_value: int) -> None:
        return None

    def _get_last_error(self) -> int:
        return self._crypt32.last_error


def test_root_enumeration_uses_combined_eku_and_prefers_server_auth() -> None:
    crypt32 = _RootEnumerationCrypt()
    api = _RootEnumerationApi(crypt32)

    roots = api._eligible_roots((ctypes.c_void_p(11), ctypes.c_void_p(12)))

    assert crypt32.references
    assert len(roots) == 1
    assert roots[0].der_bytes == b"eligible-root"
    assert roots[0].purpose is TrustPurpose.SERVER_AUTH
    assert crypt32.freed == []


class _CaptureCrypt:
    def __init__(self) -> None:
        self.collection_additions: list[tuple[int | None, int | None]] = []
        self.engine_configs: list[tuple[int | None, int | None, int, int, int]] = []
        self.freed_engines: list[int | None] = []

    def CertAddStoreToCollection(
        self, collection: object, store: object, priority: int, flags: int
    ) -> int:
        assert (priority, flags) == (0, 0)
        self.collection_additions.append((_void_value(collection), _void_value(store)))
        return 1

    def CertCreateCertificateChainEngine(
        self, config_pointer: object, engine_pointer: object
    ) -> int:
        config = ctypes.cast(
            config_pointer,
            ctypes.POINTER(native_module._CertChainEngineConfig),
        ).contents
        self.engine_configs.append(
            (
                _void_value(config.restricted_other),
                _void_value(config.exclusive_root),
                int(config.flags),
                int(config.exclusive_flags),
                int(config.url_retrieval_timeout),
            )
        )
        ctypes.cast(engine_pointer, ctypes.POINTER(ctypes.c_void_p))[0] = (
            ctypes.c_void_p(90)
        )
        return 1

    def CertFreeCertificateChainEngine(self, engine: object) -> None:
        self.freed_engines.append(_void_value(engine))


class _CaptureApi(native_module._CtypesWindowsTrustApi):
    def __init__(self, error: BaseException | None = None) -> None:
        self.crypt32 = _CaptureCrypt()
        self._crypt32 = self.crypt32
        self._winhttp = object()
        self.error = error
        self.system_store_calls: list[tuple[str, int]] = []
        self.memory_provider_calls: list[int] = []
        self.eligible_store_values: tuple[int | None, ...] = ()
        self.der_additions: list[tuple[int | None, bytes]] = []
        self.build_calls: list[tuple[str, bytes, int | None]] = []
        self.closed: list[int | None] = []
        self._system_handles = iter((11, 12, 21, 22))
        self._memory_handles = iter((31, 32, 33))

    def _open_system_store(self, name: str, location: int) -> ctypes.c_void_p:
        self.system_store_calls.append((name, location))
        return ctypes.c_void_p(next(self._system_handles))

    def _open_memory_store(self, provider: int) -> ctypes.c_void_p:
        self.memory_provider_calls.append(provider)
        return ctypes.c_void_p(next(self._memory_handles))

    def _eligible_roots(
        self, stores: tuple[ctypes.c_void_p, ...]
    ) -> tuple[EligibleWindowsRoot, ...]:
        self.eligible_store_values = tuple(_void_value(store) for store in stores)
        return (EligibleWindowsRoot(b"eligible-root", TrustPurpose.SERVER_AUTH),)

    def _add_der(self, store: ctypes.c_void_p, der_bytes: bytes) -> None:
        self.der_additions.append((_void_value(store), der_bytes))

    def _server_chain(self, hostname: str) -> tuple[bytes, ...]:
        assert hostname == "maps.googleapis.com"
        return (b"leaf", b"intermediate", b"intermediate")

    def _build_candidates(
        self, hostname: str, leaf_der: bytes, engine: ctypes.c_void_p
    ) -> tuple[NativeChainCandidate, ...]:
        self.build_calls.append((hostname, leaf_der, _void_value(engine)))
        if self.error is not None:
            raise self.error
        return _evidence(MapProvider.GOOGLE).candidates

    def _close_store(self, store: ctypes.c_void_p) -> None:
        self.closed.append(_void_value(store))


def test_native_capture_separates_roots_intermediates_and_cleans_up() -> None:
    api = _CaptureApi()

    evidence = api.capture(MapProvider.GOOGLE, "maps.googleapis.com")

    assert evidence == _evidence(MapProvider.GOOGLE)
    assert [name for name, _location in api.system_store_calls] == [
        "ROOT",
        "ROOT",
        "CA",
        "CA",
    ]
    assert api.memory_provider_calls == [
        native_module._CERT_STORE_PROV_MEMORY,
        native_module._CERT_STORE_PROV_MEMORY,
        native_module._CERT_STORE_PROV_COLLECTION,
    ]
    assert api.eligible_store_values == (11, 12)
    assert api.der_additions == [
        (31, b"eligible-root"),
        (32, b"leaf"),
        (32, b"intermediate"),
    ]
    assert api.crypt32.collection_additions == [(33, 21), (33, 22), (33, 32)]
    assert api.crypt32.engine_configs == [
        (
            33,
            31,
            native_module._CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
            | native_module._CERT_CHAIN_DISABLE_AIA,
            0,
            10_000,
        )
    ]
    assert api.build_calls == [("maps.googleapis.com", b"leaf", 90)]
    assert api.crypt32.freed_engines == [90]
    assert api.closed == [33, 32, 31, 22, 21, 12, 11]


@pytest.mark.parametrize("error", (OSError("capture failed"), _Interruption()))
def test_native_capture_preserves_primary_error_and_cleans_once(
    error: BaseException,
) -> None:
    api = _CaptureApi(error)

    with pytest.raises(type(error)) as failure:
        api.capture(MapProvider.GOOGLE, "maps.googleapis.com")

    assert failure.value is error
    assert api.crypt32.freed_engines == [90]
    assert api.closed == [33, 32, 31, 22, 21, 12, 11]
    assert len(api.closed) == len(set(api.closed))


class _RecordingPolicyCrypt:
    def __init__(self, policy_error: int) -> None:
        self.policy_error = policy_error
        self.calls: list[tuple[int, str, int, int]] = []

    def CertVerifyCertificateChainPolicy(
        self,
        policy: ctypes.c_void_p,
        chain: object,
        policy_para_pointer: object,
        policy_status_pointer: object,
    ) -> int:
        policy_para = ctypes.cast(
            policy_para_pointer,
            ctypes.POINTER(native_module._CertChainPolicyPara),
        ).contents
        ssl_extra = ctypes.cast(
            policy_para.extra_policy_para,
            ctypes.POINTER(native_module._SslExtraCertChainPolicyPara),
        ).contents
        policy_status = ctypes.cast(
            policy_status_pointer,
            ctypes.POINTER(native_module._CertChainPolicyStatus),
        ).contents
        policy_status.error = self.policy_error
        self.calls.append(
            (
                int(policy.value),
                str(ssl_extra.server_name),
                int(ssl_extra.auth_type),
                int(ssl_extra.checks),
            )
        )
        return 1


def test_candidate_binds_ssl_policy_to_hostname_and_native_chain_status() -> None:
    chain, references = _native_chain(
        (b"leaf", b"intermediate", b"eligible-root"),
        trust_error=0x20,
    )
    crypt32 = _RecordingPolicyCrypt(policy_error=0x40)
    api = _native_api(crypt32, object())

    candidate = api._candidate(chain, "maps.googleapis.com")

    assert references
    assert candidate.element_fingerprints_sha256 == tuple(
        hashlib.sha256(value).hexdigest()
        for value in (b"leaf", b"intermediate", b"eligible-root")
    )
    assert candidate.native_trust_error_status == 0x20
    assert candidate.ssl_policy_error == 0x40
    assert crypt32.calls == [(4, "maps.googleapis.com", 2, 0)]


class _RecordingBuildCrypt(_RecordingPolicyCrypt):
    def __init__(self, primary: object) -> None:
        super().__init__(policy_error=0)
        self.primary = primary
        self.flags: list[int] = []
        self.requested_oids: list[str] = []
        self.freed_chains = 0
        self.freed_certificates = 0

    def CertCreateCertificateContext(
        self, encoding: int, encoded: object, size: int
    ) -> object:
        context = native_module._CertContext(
            encoding,
            encoded,
            size,
            None,
            None,
        )
        self.leaf = context
        self.leaf_pointer = ctypes.pointer(context)
        return self.leaf_pointer

    def CertGetCertificateChain(
        self,
        engine: object,
        leaf: object,
        verify_time: object,
        additional_store: object,
        chain_para_pointer: object,
        flags: int,
        reserved: object,
        result_pointer: object,
    ) -> int:
        assert _void_value(engine) == 91
        assert leaf == self.leaf_pointer
        assert verify_time is None
        assert additional_store is None
        assert reserved is None
        chain_para = ctypes.cast(
            chain_para_pointer,
            ctypes.POINTER(native_module._CertChainPara),
        ).contents
        oid = chain_para.requested_usage.usage.usages[0]
        self.requested_oids.append(oid.decode("ascii"))
        self.flags.append(flags)
        ctypes.cast(
            result_pointer,
            ctypes.POINTER(ctypes.POINTER(native_module._CertChainContext)),
        )[0] = self.primary
        return 1

    def CertFreeCertificateChain(self, chain: object) -> None:
        assert _void_value(chain) == _void_value(self.primary)
        self.freed_chains += 1

    def CertFreeCertificateContext(self, leaf: object) -> int:
        assert _void_value(leaf) == _void_value(self.leaf_pointer)
        self.freed_certificates += 1
        return 1


def test_chain_builder_requests_cache_only_server_auth_and_lower_candidates() -> None:
    lower, lower_references = _native_chain(
        (b"leaf", b"other-intermediate", b"eligible-root")
    )
    primary, primary_references = _native_chain(
        (b"leaf", b"intermediate", b"eligible-root")
    )
    lower_array = (ctypes.POINTER(native_module._CertChainContext) * 1)(lower)
    primary.contents.lower_quality_chain_count = 1
    primary.contents.lower_quality_chains = lower_array
    crypt32 = _RecordingBuildCrypt(primary)
    api = _native_api(crypt32, object())

    candidates = api._build_candidates(
        "maps.googleapis.com", b"leaf", ctypes.c_void_p(91)
    )

    assert lower_references and primary_references and lower_array
    assert len(candidates) == 2
    assert all(candidate.policy_valid for candidate in candidates)
    assert crypt32.requested_oids == ["1.3.6.1.5.5.7.3.1"]
    assert crypt32.flags == [
        native_module._CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
        | native_module._CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS
        | native_module._CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE
        | native_module._CERT_CHAIN_DISABLE_AIA
        | native_module._CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
        | native_module._CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY
    ]
    assert crypt32.freed_chains == 1
    assert crypt32.freed_certificates == 1


class _RecordingHttpCrypt:
    def __init__(self, chain: object) -> None:
        self.chain = chain
        self.freed = 0

    def CertFreeCertificateChain(self, chain: object) -> None:
        assert _void_value(chain) == _void_value(self.chain)
        self.freed += 1


class _RecordingWinHttp:
    def __init__(self, chain: object) -> None:
        self.chain = chain
        self.options: list[tuple[int, int | None]] = []
        self.closed: list[int] = []
        self.open_request: tuple[object, ...] | None = None

    def WinHttpOpen(self, *arguments: object) -> int:
        assert arguments == ("TowerScout Launcher", 4, None, None, 0)
        return 11

    def WinHttpSetTimeouts(self, handle: object, *timeouts: int) -> int:
        assert _void_value(handle) == 11
        assert timeouts == (10_000, 10_000, 10_000, 10_000)
        return 1

    def WinHttpSetOption(
        self, handle: object, option: int, value_pointer: object, size: int
    ) -> int:
        value = None
        if value_pointer is not None:
            assert size == ctypes.sizeof(ctypes.c_uint32)
            value = ctypes.cast(
                value_pointer, ctypes.POINTER(ctypes.c_uint32)
            ).contents.value
        else:
            assert option == native_module._WINHTTP_OPTION_CLIENT_CERT_CONTEXT
            assert size == 0
        self.options.append((option, value))
        return 1

    def WinHttpConnect(
        self, session: object, hostname: str, port: int, reserved: int
    ) -> int:
        assert _void_value(session) == 11
        assert hostname == "maps.googleapis.com"
        assert (port, reserved) == (443, 0)
        return 22

    def WinHttpOpenRequest(self, *arguments: object) -> int:
        self.open_request = arguments
        return 33

    def WinHttpSendRequest(self, *arguments: object) -> int:
        assert _void_value(arguments[0]) == 33
        assert arguments[1:] == (None, 0, None, 0, 0, 0)
        return 1

    def WinHttpReceiveResponse(self, request: object, reserved: object) -> int:
        assert _void_value(request) == 33
        assert reserved is None
        return 1

    def WinHttpQueryOption(
        self,
        request: object,
        option: int,
        result_pointer: object,
        length_pointer: object,
    ) -> int:
        assert _void_value(request) == 33
        assert option == native_module._WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT
        length = ctypes.cast(length_pointer, ctypes.POINTER(ctypes.c_uint32)).contents
        assert length.value == ctypes.sizeof(ctypes.c_void_p)
        ctypes.cast(
            result_pointer,
            ctypes.POINTER(ctypes.POINTER(native_module._CertChainContext)),
        )[0] = self.chain
        return 1

    def WinHttpCloseHandle(self, handle: ctypes.c_void_p) -> int:
        self.closed.append(int(handle.value))
        return 1


def test_server_chain_probe_uses_fixed_tls_policy_and_reverse_cleanup() -> None:
    chain, references = _native_chain((b"leaf", b"intermediate"))
    crypt32 = _RecordingHttpCrypt(chain)
    winhttp = _RecordingWinHttp(chain)
    api = _native_api(crypt32, winhttp)

    captured = api._server_chain("maps.googleapis.com")

    assert references
    assert captured == (b"leaf", b"intermediate")
    assert winhttp.open_request is not None
    assert _void_value(winhttp.open_request[0]) == 22
    assert winhttp.open_request[1:] == (
        "HEAD",
        "/",
        None,
        None,
        None,
        native_module._WINHTTP_FLAG_SECURE,
    )
    assert winhttp.options == [
        (
            native_module._WINHTTP_OPTION_SECURE_PROTOCOLS,
            native_module._WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
            | native_module._WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
        ),
        (
            native_module._WINHTTP_OPTION_DISABLE_FEATURE,
            native_module._WINHTTP_DISABLE_COOKIES
            | native_module._WINHTTP_DISABLE_REDIRECTS,
        ),
        (
            native_module._WINHTTP_OPTION_AUTOLOGON_POLICY,
            native_module._WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM,
        ),
        (
            native_module._WINHTTP_OPTION_REDIRECT_POLICY,
            native_module._WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
        ),
        (native_module._WINHTTP_OPTION_CLIENT_CERT_CONTEXT, None),
    ]
    assert crypt32.freed == 1
    assert winhttp.closed == [33, 22, 11]


def test_production_entry_point_has_no_native_or_hostname_injection_seam() -> None:
    with pytest.raises(TypeError):
        capture_selected_windows_root(  # type: ignore[call-arg]
            MapProvider.GOOGLE,
            hostname="attacker.invalid",
        )
    with pytest.raises(TypeError):
        capture_selected_windows_root(  # type: ignore[call-arg]
            MapProvider.GOOGLE,
            api=_FakeNativeApi(evidence=_evidence(MapProvider.GOOGLE)),
        )
    with pytest.raises(TypeError):
        capture_selected_windows_root(  # type: ignore[call-arg]
            MapProvider.GOOGLE,
            environment={},
        )


def test_production_rejects_actual_ca_redirect_before_native_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructed = False

    def construct() -> object:
        nonlocal constructed
        constructed = True
        raise AssertionError("native adapter must not be constructed")

    monkeypatch.setenv("SSL_CERT_FILE", r"C:\private\injected.pem")
    monkeypatch.setattr(native_module, "_CtypesWindowsTrustApi", construct)

    with pytest.raises(TrustPolicyError) as failure:
        capture_selected_windows_root(MapProvider.GOOGLE)

    assert failure.value.code == "ambient_ca_redirect"
    assert constructed is False


def test_selected_material_remains_immutable_and_redacted() -> None:
    api = _FakeNativeApi(evidence=_evidence(MapProvider.GOOGLE))
    selected = _capture_selected_windows_root_with_api(
        MapProvider.GOOGLE, environment={}, api=api  # type: ignore[arg-type]
    )

    assert selected.fingerprint_sha256 not in repr(selected)
    assert selected.der_bytes.hex() not in repr(selected)
    with pytest.raises(FrozenInstanceError):
        selected.der_bytes = b"replacement"  # type: ignore[misc]
