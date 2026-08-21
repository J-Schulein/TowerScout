"""Fail-closed matching for package-bound Windows Authenticode evidence.

The public verifier is deliberately verification-only.  It consumes an
already-open :class:`HandleBoundFile`, never discovers an executable by path,
and never executes or mutates a runtime.  Native extraction is isolated behind
an injectable backend; all signature and publisher decisions are repeated here
against the exact package-bound runtime policy.  A successful result identifies
the compatible signer-policy entries only.  It is not proof of the executable's
product, leaf name, or version.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol

from .runtime_policy import (
    RuntimePolicy,
    RuntimePolicyError,
    RuntimeProductId,
    SignatureForm,
    SignerCertificatePolicy,
    load_package_bound_runtime_policy,
)
from .windows_security import (
    FileSnapshot,
    HandleBoundFile,
    StableFileIdentity,
    WindowsSecurityError,
)

_SHA256 = frozenset("0123456789abcdef")
_MAX_NATIVE_COUNT = 16
_EVIDENCE_DOMAIN = b"TowerScout.AuthenticodeEvidence.v1"
_PRODUCT_ID_ORDER = {
    product_id: index for index, product_id in enumerate(RuntimeProductId)
}


class AuthenticodeErrorCode(str, Enum):
    RUNTIME_IDENTITY_INVALID = "runtime_identity_invalid"
    RUNTIME_REPLACED = "runtime_replaced"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"


class AuthenticodeVerificationError(RuntimeError):
    """Sanitized public failure for the runtime-signature boundary."""

    _MESSAGES = {
        AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID: (
            "The runtime executable signature and publisher could not be authenticated."
        ),
        AuthenticodeErrorCode.RUNTIME_REPLACED: (
            "The runtime executable changed while it was being authenticated."
        ),
        AuthenticodeErrorCode.VERIFICATION_UNAVAILABLE: (
            "Windows runtime authentication is unavailable."
        ),
    }

    def __init__(self, code: AuthenticodeErrorCode) -> None:
        if type(code) is not AuthenticodeErrorCode:
            raise ValueError("Unknown Authenticode error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"AuthenticodeVerificationError(code={self.code.value!r})"


class NativeTrustStatus(str, Enum):
    TRUSTED = "trusted"
    REVOKED = "revoked"
    OFFLINE = "offline"
    UNKNOWN = "unknown"
    UNTRUSTED = "untrusted"


class TimestampForm(str, Enum):
    RFC3161 = "rfc3161"
    LEGACY_COUNTERSIGNATURE = "legacy_countersignature"
    UNKNOWN = "unknown"


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _SHA256 for character in value)
    )


def _is_text(value: object, *, maximum: int = 512) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and "\x00" not in value
        and all(0x20 <= ord(character) <= 0x7E for character in value)
    )


def _parse_utc(value: str) -> datetime:
    if (
        type(value) is not str
        or len(value) != 20
        or value[4] != "-"
        or value[7] != "-"
        or value[10] != "T"
        or value[13] != ":"
        or value[16] != ":"
        or value[19] != "Z"
    ):
        raise ValueError("UTC timestamp evidence is invalid.")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ValueError("UTC timestamp evidence is invalid.") from None
    return parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True, repr=False)
class SignerCertificateFacts:
    certificate_sha256: str = field(repr=False)
    subject_common_name: str
    subject_organization: str
    issuer_common_name: str
    serial_number: str = field(repr=False)
    not_before_utc: str
    not_after_utc: str
    public_key_algorithm: str
    public_key_bits: int
    code_signing_eku: bool

    def __post_init__(self) -> None:
        if (
            not _is_sha256(self.certificate_sha256)
            or not _is_text(self.subject_common_name)
            or not _is_text(self.subject_organization)
            or not _is_text(self.issuer_common_name)
            or type(self.serial_number) is not str
            or not 2 <= len(self.serial_number) <= 64
            or len(self.serial_number) % 2 != 0
            or any(character not in _SHA256 for character in self.serial_number)
            or not _is_text(self.public_key_algorithm, maximum=32)
            or type(self.public_key_bits) is not int
            or not 1024 <= self.public_key_bits <= 16384
            or type(self.code_signing_eku) is not bool
        ):
            raise ValueError("Signer certificate evidence is invalid.")
        _parse_utc(self.not_before_utc)
        if _parse_utc(self.not_after_utc) <= _parse_utc(self.not_before_utc):
            raise ValueError("Signer certificate evidence is invalid.")

    def __repr__(self) -> str:
        return "SignerCertificateFacts(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class TimestampFacts:
    form: TimestampForm
    token_sha256: str = field(repr=False)
    signing_time_utc: str
    digest_algorithm: str
    signature_algorithm: str
    primary_signature_valid: bool
    chain_status: NativeTrustStatus
    chain_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.form) is not TimestampForm
            or not _is_sha256(self.token_sha256)
            or not _is_sha256(self.chain_sha256)
            or not _is_text(self.digest_algorithm, maximum=32)
            or not _is_text(self.signature_algorithm, maximum=32)
            or type(self.primary_signature_valid) is not bool
            or type(self.chain_status) is not NativeTrustStatus
        ):
            raise ValueError("Timestamp evidence is invalid.")
        _parse_utc(self.signing_time_utc)

    def __repr__(self) -> str:
        return "TimestampFacts(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class NativeAuthenticodeFacts:
    signature_form: SignatureForm
    certificate_table_entry_count: int
    primary_signer_count: int
    secondary_signature_count: int
    nested_signature_count: int
    legacy_countersignature_count: int
    embedded_signature_sha256: str = field(repr=False)
    file_digest_algorithm: str
    signer_signature_algorithm: str
    wintrust_status: int = field(repr=False)
    signer_chain_status: NativeTrustStatus
    signer_chain_sha256: str = field(repr=False)
    signer: SignerCertificateFacts = field(repr=False)
    timestamps: tuple[TimestampFacts, ...] = field(repr=False)

    def __post_init__(self) -> None:
        counts = (
            self.certificate_table_entry_count,
            self.primary_signer_count,
            self.secondary_signature_count,
            self.nested_signature_count,
            self.legacy_countersignature_count,
        )
        if (
            type(self.signature_form) is not SignatureForm
            or any(
                type(value) is not int or not 0 <= value <= _MAX_NATIVE_COUNT
                for value in counts
            )
            or not _is_sha256(self.embedded_signature_sha256)
            or not _is_sha256(self.signer_chain_sha256)
            or type(self.wintrust_status) is not int
            or isinstance(self.wintrust_status, bool)
            or not -(2**31) <= self.wintrust_status < 2**31
            or type(self.signer_chain_status) is not NativeTrustStatus
            or type(self.signer) is not SignerCertificateFacts
            or type(self.timestamps) is not tuple
            or len(self.timestamps) > _MAX_NATIVE_COUNT
            or any(type(item) is not TimestampFacts for item in self.timestamps)
            or not _is_text(self.file_digest_algorithm, maximum=32)
            or not _is_text(self.signer_signature_algorithm, maximum=32)
        ):
            raise ValueError("Native Authenticode evidence is invalid.")

    def __repr__(self) -> str:
        return "NativeAuthenticodeFacts(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedAuthenticodeEvidence:
    signer_policy_product_ids: tuple[RuntimeProductId, ...]
    policy_sha256: str = field(repr=False)
    file_identity: StableFileIdentity = field(repr=False)
    file_sha256: str = field(repr=False)
    signer_certificate_sha256: str = field(repr=False)
    signer_chain_sha256: str = field(repr=False)
    embedded_signature_sha256: str = field(repr=False)
    timestamp_token_sha256: str | None = field(repr=False)
    timestamp_chain_sha256: str | None = field(repr=False)
    timestamp_time_utc: str | None
    evidence_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        product_ids = self.signer_policy_product_ids
        optional_hashes = (
            self.timestamp_token_sha256,
            self.timestamp_chain_sha256,
        )
        if (
            type(product_ids) is not tuple
            or not 1 <= len(product_ids) <= len(RuntimeProductId)
            or any(
                type(product_id) is not RuntimeProductId for product_id in product_ids
            )
            or len(set(product_ids)) != len(product_ids)
            or tuple(sorted(product_ids, key=_PRODUCT_ID_ORDER.__getitem__))
            != product_ids
            or not _is_sha256(self.policy_sha256)
            or type(self.file_identity) is not StableFileIdentity
            or not _is_sha256(self.file_sha256)
            or not _is_sha256(self.signer_certificate_sha256)
            or not _is_sha256(self.signer_chain_sha256)
            or not _is_sha256(self.embedded_signature_sha256)
            or any(
                value is not None and not _is_sha256(value) for value in optional_hashes
            )
            or (self.timestamp_token_sha256 is None)
            != (self.timestamp_chain_sha256 is None)
            or (self.timestamp_token_sha256 is None)
            != (self.timestamp_time_utc is None)
        ):
            raise ValueError("Verified Authenticode evidence is invalid.")
        if self.timestamp_time_utc is not None:
            _parse_utc(self.timestamp_time_utc)
        object.__setattr__(
            self,
            "evidence_sha256",
            _canonical_evidence_digest(
                (
                    len(product_ids).to_bytes(1, "big"),
                    *(product_id.value.encode("ascii") for product_id in product_ids),
                    self.policy_sha256.encode("ascii"),
                    self.file_identity.volume_serial.to_bytes(8, "big"),
                    self.file_identity.file_id,
                    self.file_sha256.encode("ascii"),
                    self.signer_certificate_sha256.encode("ascii"),
                    self.signer_chain_sha256.encode("ascii"),
                    self.embedded_signature_sha256.encode("ascii"),
                    (self.timestamp_token_sha256 or "").encode("ascii"),
                    (self.timestamp_chain_sha256 or "").encode("ascii"),
                    (self.timestamp_time_utc or "").encode("ascii"),
                )
            ),
        )

    def __repr__(self) -> str:
        return (
            "VerifiedAuthenticodeEvidence("
            f"signer_policy_count={len(self.signer_policy_product_ids)}, <redacted>)"
        )


class AuthenticodeBackend(Protocol):
    """Extract complete native evidence through an existing file handle."""

    @property
    def supported(self) -> bool: ...

    def inspect_open_file(
        self,
        *,
        handle: object,
        snapshot: FileSnapshot,
    ) -> NativeAuthenticodeFacts: ...


class VerificationClock(Protocol):
    def now_utc(self) -> datetime: ...


class SystemVerificationClock:
    __slots__ = ()

    def now_utc(self) -> datetime:
        return datetime.now(timezone.utc)


def _fail(code: AuthenticodeErrorCode) -> None:
    raise AuthenticodeVerificationError(code)


def _signer_matches(
    facts: SignerCertificateFacts,
    approved: SignerCertificatePolicy,
) -> bool:
    return not (
        facts.certificate_sha256 != approved.certificate_sha256
        or facts.subject_common_name != approved.subject_common_name
        or facts.subject_organization != approved.subject_organization
        or facts.issuer_common_name != approved.issuer_common_name
        or facts.serial_number != approved.serial_number
        or facts.not_before_utc != approved.not_before_utc
        or facts.not_after_utc != approved.not_after_utc
        or facts.public_key_algorithm != approved.public_key_algorithm
        or facts.public_key_bits < approved.minimum_public_key_bits
        or facts.code_signing_eku is not True
    )


def _compatible_signer_policy_product_ids(
    policy: RuntimePolicy,
    facts: SignerCertificateFacts,
) -> tuple[RuntimeProductId, ...]:
    product_ids = tuple(
        product.product_id
        for product in policy.products
        if any(_signer_matches(facts, approved) for approved in product.signers)
    )
    if not product_ids:
        _fail(AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID)
    return product_ids


def _validated_timestamp(
    facts: NativeAuthenticodeFacts,
    *,
    now: datetime,
    signer_not_before: datetime,
    signer_not_after: datetime,
) -> TimestampFacts | None:
    if len(facts.timestamps) > 1:
        _fail(AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID)
    if not facts.timestamps:
        if now > signer_not_after:
            _fail(AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID)
        return None
    timestamp = facts.timestamps[0]
    timestamp_time = _parse_utc(timestamp.signing_time_utc)
    if (
        timestamp.form is not TimestampForm.RFC3161
        or timestamp.digest_algorithm != "sha256"
        or timestamp.signature_algorithm != "rsa_pkcs1v15"
        or timestamp.primary_signature_valid is not True
        or timestamp.chain_status is not NativeTrustStatus.TRUSTED
        or timestamp_time < signer_not_before
        or timestamp_time > signer_not_after
        or timestamp_time > now
    ):
        _fail(AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID)
    return timestamp


def _match_authenticode(
    facts: NativeAuthenticodeFacts,
    *,
    policy: RuntimePolicy,
    now: datetime,
) -> tuple[tuple[RuntimeProductId, ...], TimestampFacts | None]:
    auth = policy.authenticode
    if (
        facts.signature_form is not SignatureForm.EMBEDDED_AUTHENTICODE
        or facts.signature_form is not auth.signature_form
        or facts.certificate_table_entry_count != 1
        or facts.primary_signer_count != 1
        or facts.secondary_signature_count != 0
        or facts.nested_signature_count != 0
        or facts.legacy_countersignature_count != 0
        or facts.file_digest_algorithm != auth.file_digest_algorithm
        or facts.signer_signature_algorithm != auth.signer_signature_algorithm
        or facts.wintrust_status != 0
        or facts.signer_chain_status is not NativeTrustStatus.TRUSTED
    ):
        _fail(AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID)
    product_ids = _compatible_signer_policy_product_ids(policy, facts.signer)
    signer_not_before = _parse_utc(facts.signer.not_before_utc)
    signer_not_after = _parse_utc(facts.signer.not_after_utc)
    if now < signer_not_before:
        _fail(AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID)
    return (
        product_ids,
        _validated_timestamp(
            facts,
            now=now,
            signer_not_before=signer_not_before,
            signer_not_after=signer_not_after,
        ),
    )


def _canonical_evidence_digest(fields: tuple[bytes, ...]) -> str:
    digest = hashlib.sha256()
    for value in (_EVIDENCE_DOMAIN, *fields):
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _build_evidence(
    *,
    policy: RuntimePolicy,
    signer_policy_product_ids: tuple[RuntimeProductId, ...],
    snapshot: FileSnapshot,
    facts: NativeAuthenticodeFacts,
    timestamp: TimestampFacts | None,
) -> VerifiedAuthenticodeEvidence:
    timestamp_token = timestamp.token_sha256 if timestamp is not None else None
    timestamp_chain = timestamp.chain_sha256 if timestamp is not None else None
    timestamp_time = timestamp.signing_time_utc if timestamp is not None else None
    return VerifiedAuthenticodeEvidence(
        signer_policy_product_ids=signer_policy_product_ids,
        policy_sha256=policy.content_sha256,
        file_identity=snapshot.identity,
        file_sha256=snapshot.sha256,
        signer_certificate_sha256=facts.signer.certificate_sha256,
        signer_chain_sha256=facts.signer_chain_sha256,
        embedded_signature_sha256=facts.embedded_signature_sha256,
        timestamp_token_sha256=timestamp_token,
        timestamp_chain_sha256=timestamp_chain,
        timestamp_time_utc=timestamp_time,
    )


def verify_package_bound_authenticode_signer(
    bound_file: HandleBoundFile,
    *,
    backend: AuthenticodeBackend | None = None,
    clock: VerificationClock | None = None,
) -> VerifiedAuthenticodeEvidence:
    """Authenticate one held signature and publisher against the packaged policy.

    The compatible product IDs in the result describe signer-policy overlap.
    They do not authenticate the held file's product, leaf name, or version.
    """

    if type(bound_file) is not HandleBoundFile:
        _fail(AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID)
    try:
        policy = load_package_bound_runtime_policy()
    except RuntimePolicyError:
        _fail(AuthenticodeErrorCode.VERIFICATION_UNAVAILABLE)
    if backend is None:
        try:
            from .authenticode_native import NativeWindowsAuthenticodeBackend

            selected_backend: AuthenticodeBackend = NativeWindowsAuthenticodeBackend()
        except Exception:
            _fail(AuthenticodeErrorCode.VERIFICATION_UNAVAILABLE)
    else:
        selected_backend = backend
    try:
        supported = selected_backend.supported is True
    except Exception:
        supported = False
    if not supported:
        _fail(AuthenticodeErrorCode.VERIFICATION_UNAVAILABLE)

    selected_clock = clock if clock is not None else SystemVerificationClock()
    try:
        now = selected_clock.now_utc()
        if (
            type(now) is not datetime
            or now.tzinfo is None
            or now.utcoffset() != timezone.utc.utcoffset(now)
        ):
            _fail(AuthenticodeErrorCode.VERIFICATION_UNAVAILABLE)
        now = now.astimezone(timezone.utc)
    except AuthenticodeVerificationError:
        raise
    except Exception:
        _fail(AuthenticodeErrorCode.VERIFICATION_UNAVAILABLE)

    try:
        facts = bound_file.inspect_same_handle(
            lambda handle, snapshot: selected_backend.inspect_open_file(
                handle=handle,
                snapshot=snapshot,
            )
        )
    except WindowsSecurityError as error:
        if error.category in {"file_identity_changed", "file_handle_closed"}:
            _fail(AuthenticodeErrorCode.RUNTIME_REPLACED)
        _fail(AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID)
    except Exception:
        _fail(AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID)
    if type(facts) is not NativeAuthenticodeFacts:
        _fail(AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID)
    try:
        product_ids, timestamp = _match_authenticode(
            facts,
            policy=policy,
            now=now,
        )
        return _build_evidence(
            policy=policy,
            signer_policy_product_ids=product_ids,
            snapshot=bound_file.snapshot,
            facts=facts,
            timestamp=timestamp,
        )
    except AuthenticodeVerificationError:
        raise
    except Exception:
        _fail(AuthenticodeErrorCode.RUNTIME_IDENTITY_INVALID)
    raise AssertionError("unreachable")
