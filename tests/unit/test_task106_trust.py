"""Trust refresh preserves old data and cannot reintroduce blocked CA keys."""
import hashlib
import base64
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "webapp"))
import ts_trust as trust


def certificate(key=None, name="Synthetic CA", ca=True):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert.public_bytes(Encoding.PEM)


@pytest.fixture(autouse=True)
def clear_cache():
    trust.validate_bundle.cache_clear()
    yield
    trust.validate_bundle.cache_clear()


def test_refresh_preserves_system_org_and_prior_bundle(tmp_path):
    _, system = certificate(name="System")
    _, org = certificate(name="Approved org")
    base, approved, prior, candidate = [tmp_path / name for name in ("base", "approved", "prior", "candidate")]
    base.write_bytes(system)
    approved.write_bytes(org)
    prior.write_bytes(b"old persisted bytes")
    trust.build_bundle(base, approved, candidate)
    assert system.strip() in candidate.read_bytes()
    assert org.strip() in candidate.read_bytes()
    assert prior.read_bytes() == b"old persisted bytes"
    with pytest.raises(FileExistsError):
        trust.build_bundle(base, approved, candidate)


def test_reissued_certificate_with_blocked_key_is_rejected(monkeypatch):
    key, original = certificate()
    _, reissued = certificate(key, "Different certificate subject")
    digest = hashlib.sha256(key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    monkeypatch.setattr(trust, "BLOCKED_KEYS", frozenset({digest}))
    for pem in (original, reissued):
        with pytest.raises(ValueError, match="distrusted"):
            trust.validate_bundle(pem)


@pytest.mark.parametrize("bad", [b"broken PEM", b"", b"x" * (trust.MAX_BUNDLE_BYTES + 1)], ids=["malformed", "empty", "oversized"])
def test_invalid_bundle_does_not_create_candidate(tmp_path, bad):
    _, system = certificate()
    base, approved, candidate = [tmp_path / name for name in ("base", "approved", "candidate")]
    base.write_bytes(system)
    approved.write_bytes(bad)
    with pytest.raises(ValueError):
        trust.build_bundle(base, approved, candidate)
    assert not candidate.exists()


def test_leaf_cannot_be_imported_as_trust_anchor():
    _, leaf = certificate(ca=False)
    with pytest.raises(ValueError, match="not a CA"):
        trust.validate_bundle(leaf, imported=True)


def test_non_certificate_material_cannot_be_copied_into_trust():
    _, pem = certificate()
    with pytest.raises(ValueError, match="non-certificate"):
        trust.validate_bundle(pem + b"-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----", imported=True)


def test_actual_incident_root_is_rejected_without_network():
    pem = (Path(__file__).resolve().parents[1] / "fixtures/task106-trust/distrusted-emsign-root.pem").read_bytes()
    with pytest.raises(ValueError, match="distrusted"):
        trust.validate_bundle(pem)


def unsupported_curve_certificate():
    _, pem = certificate()
    der = x509.load_pem_x509_certificate(pem).public_bytes(Encoding.DER)
    curve_oid = bytes.fromhex("06082a8648ce3d030107")
    assert der.count(curve_oid) == 1
    der = der.replace(curve_oid, bytes.fromhex("06082a8648ce3d030108"))
    return b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der) + b"-----END CERTIFICATE-----\n"


def test_unsupported_certificate_is_a_sanitized_provider_error(tmp_path, monkeypatch):
    import ts_provider_http as provider
    from ts_errors import NetworkError
    bundle = tmp_path / "unsupported.pem"
    bundle.write_bytes(unsupported_curve_certificate())
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(bundle))
    monkeypatch.delenv("TOWERSCOUT_ALLOW_INSECURE_TLS", raising=False)
    monkeypatch.setattr(provider.requests, "get", lambda *a, **k: pytest.fail("Unexpected network call"))
    with pytest.raises(NetworkError) as error:
        provider.provider_get("google", "https://maps.googleapis.com/")
    assert error.value.details["category"] == provider.TLS_BUNDLE_UNUSABLE
    assert str(bundle) not in str(error.value)


def test_provider_rejects_persisted_incident_bundle_before_request(tmp_path, monkeypatch):
    import ts_provider_http as provider
    from ts_errors import NetworkError
    pem = (Path(__file__).resolve().parents[1] / "fixtures/task106-trust/distrusted-emsign-root.pem").read_bytes()
    bundle = tmp_path / "persisted.pem"
    bundle.write_bytes(pem)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(bundle))
    monkeypatch.delenv("TOWERSCOUT_ALLOW_INSECURE_TLS", raising=False)
    def unexpected(*args, **kwargs):
        pytest.fail("Network request occurred before trust rejection")
    monkeypatch.setattr(provider.requests, "get", unexpected)
    with pytest.raises(NetworkError):
        provider.provider_get("google", "https://maps.googleapis.com/")
