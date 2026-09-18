from __future__ import annotations

import hashlib
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.target_contracts import (  # noqa: E402
    ABSENT_FILE_SHA256,
    CONTAINER_BUNDLE_DESTINATION,
)
from towerscout_launcher.windows_environment_replacement import (  # noqa: E402
    EnvironmentContentState,
    EnvironmentReplacementError,
    EnvironmentReplacementErrorCode,
    MAX_ENVIRONMENT_BYTES,
    plan_ca_environment_replacement,
)

_REQUESTS = f"REQUESTS_CA_BUNDLE={CONTAINER_BUNDLE_DESTINATION}".encode("ascii")
_SSL = f"SSL_CERT_FILE={CONTAINER_BUNDLE_DESTINATION}".encode("ascii")


def test_plan_changes_only_target_value_spans_and_preserves_layout() -> None:
    original = (
        b"\xef\xbb\xbf# retained\r\n"
        b" REQUESTS_CA_BUNDLE =old-request-value\r\n"
        b"UNICODE=caf\xc3\xa9\n"
        b"SSL_CERT_FILE=old-ssl-value"
    )
    expected = (
        b"\xef\xbb\xbf# retained\r\n"
        + b" REQUESTS_CA_BUNDLE ="
        + CONTAINER_BUNDLE_DESTINATION.encode("ascii")
        + b"\r\nUNICODE=caf\xc3\xa9\nSSL_CERT_FILE="
        + CONTAINER_BUNDLE_DESTINATION.encode("ascii")
    )

    plan = plan_ca_environment_replacement(original, original_present=True)

    assert plan.original_contents == original
    assert plan.candidate_contents == expected
    assert plan.original_sha256 == hashlib.sha256(original).hexdigest()
    assert plan.candidate_sha256 == hashlib.sha256(expected).hexdigest()
    rendered = repr(plan)
    assert "old-request-value" not in rendered
    assert "old-ssl-value" not in rendered
    with pytest.raises(FrozenInstanceError):
        setattr(plan, "candidate_contents", b"changed")


@pytest.mark.parametrize(
    ("original", "expected"),
    (
        (b"OTHER=one\n", b"OTHER=one\n" + _REQUESTS + b"\n" + _SSL + b"\n"),
        (b"OTHER=one", b"OTHER=one\n" + _REQUESTS + b"\n" + _SSL),
        (
            b"OTHER=one\r\n",
            b"OTHER=one\r\n" + _REQUESTS + b"\r\n" + _SSL + b"\r\n",
        ),
        (b"", _REQUESTS + b"\r\n" + _SSL + b"\r\n"),
        (
            b"\xef\xbb\xbf",
            b"\xef\xbb\xbf" + _REQUESTS + b"\r\n" + _SSL + b"\r\n",
        ),
    ),
)
def test_plan_appends_with_existing_newline_and_trailing_form(
    original: bytes,
    expected: bytes,
) -> None:
    plan = plan_ca_environment_replacement(original, original_present=True)

    assert plan.candidate_contents == expected


@pytest.mark.parametrize(
    "contents",
    (
        b"REQUESTS_CA_BUNDLE=one\nREQUESTS_CA_BUNDLE=two\n",
        b"requests_ca_bundle=wrong-case\n",
        b"REQUESTS_CA_BUNDLE\n",
        b"export REQUESTS_CA_BUNDLE=unsupported\n",
        b"SSL_CERT_FILE=one\nssl_cert_file=two\n",
    ),
)
def test_plan_rejects_duplicate_or_malformed_target_settings(contents: bytes) -> None:
    with pytest.raises(EnvironmentReplacementError) as failure:
        plan_ca_environment_replacement(contents, original_present=True)

    assert failure.value.code is EnvironmentReplacementErrorCode.CONTENT_INVALID
    assert failure.value.__context__ is None


@pytest.mark.parametrize(
    "contents",
    (
        b"\xff",
        b"VALUE=before\x00after\n",
        b"VALUE=one\rVALUE=two\n",
        b"\xef\xbb\xbf\xef\xbb\xbfVALUE=two\n",
        b"A" * (MAX_ENVIRONMENT_BYTES + 1),
    ),
    ids=("invalid-utf8", "nul", "bare-cr", "second-bom", "oversized"),
)
def test_plan_rejects_unsafe_or_oversized_content_without_disclosure(
    contents: bytes,
) -> None:
    with pytest.raises(EnvironmentReplacementError) as failure:
        plan_ca_environment_replacement(contents, original_present=True)

    assert failure.value.code is EnvironmentReplacementErrorCode.CONTENT_INVALID
    assert "before" not in str(failure.value)
    assert "before" not in repr(failure.value)
    assert failure.value.__context__ is None


def test_plan_rejects_candidate_growth_beyond_size_limit() -> None:
    original = b"OTHER=" + b"x" * (MAX_ENVIRONMENT_BYTES - len(b"OTHER="))

    with pytest.raises(EnvironmentReplacementError) as failure:
        plan_ca_environment_replacement(original, original_present=True)

    assert failure.value.code is EnvironmentReplacementErrorCode.CONTENT_INVALID


def test_plan_classifies_exact_existing_environment_states() -> None:
    original = b"OTHER=one\n"
    plan = plan_ca_environment_replacement(original, original_present=True)

    assert plan.classify(original) is EnvironmentContentState.ORIGINAL
    assert plan.classify(plan.candidate_contents) is EnvironmentContentState.CANDIDATE
    assert plan.classify(None) is EnvironmentContentState.ABSENT
    assert (
        plan.classify(b"OTHER=concurrent-edit\n") is EnvironmentContentState.THIRD_STATE
    )


def test_plan_classifies_exact_absent_environment_states() -> None:
    template = b"OTHER=template\n"
    plan = plan_ca_environment_replacement(template, original_present=False)

    assert plan.original_contents is None
    assert plan.original_sha256 == ABSENT_FILE_SHA256
    assert plan.classify(None) is EnvironmentContentState.ABSENT
    assert plan.classify(plan.candidate_contents) is EnvironmentContentState.CANDIDATE
    assert plan.classify(template) is EnvironmentContentState.THIRD_STATE


def test_noop_candidate_remains_classified_as_original() -> None:
    original = _REQUESTS + b"\n" + _SSL
    plan = plan_ca_environment_replacement(original, original_present=True)

    assert plan.candidate_contents == original
    assert plan.classify(original) is EnvironmentContentState.ORIGINAL


def test_plan_rejects_invalid_inputs_and_inconsistent_reconstruction() -> None:
    with pytest.raises(EnvironmentReplacementError) as failure:
        plan_ca_environment_replacement(b"OTHER=one\n", original_present=1)  # type: ignore[arg-type]
    assert failure.value.code is EnvironmentReplacementErrorCode.INPUT_INVALID

    plan = plan_ca_environment_replacement(b"OTHER=one\n", original_present=True)
    with pytest.raises(ValueError, match="replacement plan"):
        replace(plan, candidate_sha256="0" * 64)
    with pytest.raises(ValueError, match="replacement plan"):
        replace(
            plan,
            original_contents=b"x" * (MAX_ENVIRONMENT_BYTES + 1),
            original_sha256=hashlib.sha256(
                b"x" * (MAX_ENVIRONMENT_BYTES + 1)
            ).hexdigest(),
        )

    with pytest.raises(EnvironmentReplacementError) as classify_failure:
        plan.classify(bytearray(plan.candidate_contents))  # type: ignore[arg-type]
    assert classify_failure.value.code is EnvironmentReplacementErrorCode.INPUT_INVALID
