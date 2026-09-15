"""Pure content planning for a future handle-bound ``.env`` replacement.

This module validates and transforms bytes only. It does not open, create,
replace, remove, or recover files and cannot enable runtime mutation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn

from .target_contracts import ABSENT_FILE_SHA256, CONTAINER_BUNDLE_DESTINATION

MAX_ENVIRONMENT_BYTES = 262_144
_SCHEMA_VERSION = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CA_SETTINGS = (
    ("REQUESTS_CA_BUNDLE", CONTAINER_BUNDLE_DESTINATION),
    ("SSL_CERT_FILE", CONTAINER_BUNDLE_DESTINATION),
)
_CA_SETTING_BY_FOLDED_NAME = {
    name.casefold(): (name, value) for name, value in _CA_SETTINGS
}


class EnvironmentReplacementErrorCode(str, Enum):
    INPUT_INVALID = "environment_replace_input_invalid"
    CONTENT_INVALID = "environment_replace_content_invalid"


class EnvironmentReplacementError(RuntimeError):
    """Sanitized failure while planning package-environment replacement."""

    _MESSAGES = {
        EnvironmentReplacementErrorCode.INPUT_INVALID: (
            "The environment replacement request is invalid."
        ),
        EnvironmentReplacementErrorCode.CONTENT_INVALID: (
            "The package environment file cannot be updated safely."
        ),
    }

    def __init__(self, code: EnvironmentReplacementErrorCode) -> None:
        if type(code) is not EnvironmentReplacementErrorCode:
            raise ValueError("Unknown environment replacement error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"EnvironmentReplacementError(code={self.code.value!r})"


class EnvironmentContentState(str, Enum):
    ORIGINAL = "original"
    CANDIDATE = "candidate"
    ABSENT = "absent"
    THIRD_STATE = "third_state"


def _fail(code: EnvironmentReplacementErrorCode) -> NoReturn:
    raise EnvironmentReplacementError(code)


def _sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _decode_environment(contents: bytes) -> tuple[str, bool]:
    if type(contents) is not bytes:
        _fail(EnvironmentReplacementErrorCode.INPUT_INVALID)
    if len(contents) > MAX_ENVIRONMENT_BYTES:
        _fail(EnvironmentReplacementErrorCode.CONTENT_INVALID)
    has_bom = contents.startswith(b"\xef\xbb\xbf")
    try:
        text = contents.decode("utf-8-sig", errors="strict")
    except UnicodeError:
        text = None
    if text is None:
        _fail(EnvironmentReplacementErrorCode.CONTENT_INVALID)
    if (
        "\x00" in text
        or "\ufeff" in text
        or any(character in text for character in ("\x85", "\u2028", "\u2029"))
        or any(
            ord(character) < 0x20 and character not in {"\t", "\r", "\n"}
            for character in text
        )
        or "\r" in text.replace("\r\n", "")
    ):
        _fail(EnvironmentReplacementErrorCode.CONTENT_INVALID)
    return text, has_bom


def _line_parts(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    return line, ""


def _contains_target_name(value: str) -> bool:
    return any(
        token.casefold() in _CA_SETTING_BY_FOLDED_NAME
        for token in _ENVIRONMENT_NAME.findall(value)
    )


def _replace_target_line(line: str, replaced: set[str]) -> str:
    content, ending = _line_parts(line)
    if content.lstrip().startswith("#"):
        return line
    name, separator, _value = content.partition("=")
    key = name.strip()
    target = _CA_SETTING_BY_FOLDED_NAME.get(key.casefold())
    if target is None:
        if _contains_target_name(name):
            _fail(EnvironmentReplacementErrorCode.CONTENT_INVALID)
        return line
    canonical_name, replacement = target
    if separator != "=" or key != canonical_name or canonical_name in replaced:
        _fail(EnvironmentReplacementErrorCode.CONTENT_INVALID)
    replaced.add(canonical_name)
    return f"{name}={replacement}{ending}"


def _append_missing_settings(
    updated: str,
    replaced: set[str],
    *,
    newline: str,
    had_trailing_newline: bool,
) -> str:
    missing = tuple(item for item in _CA_SETTINGS if item[0] not in replaced)
    if not missing:
        return updated
    appended = newline.join(f"{name}={value}" for name, value in missing)
    if not updated:
        return appended + newline
    separator = "" if had_trailing_newline else newline
    suffix = newline if had_trailing_newline else ""
    return f"{updated}{separator}{appended}{suffix}"


def _candidate_contents(source_contents: bytes) -> bytes:
    text, has_bom = _decode_environment(source_contents)
    selected_newline = "\r\n" if "\r\n" in text or not text else "\n"
    had_trailing_newline = text.endswith(("\r\n", "\n"))
    replaced: set[str] = set()
    updated = "".join(
        _replace_target_line(line, replaced) for line in text.splitlines(keepends=True)
    )
    updated = _append_missing_settings(
        updated,
        replaced,
        newline=selected_newline,
        had_trailing_newline=had_trailing_newline,
    )

    encoded = updated.encode("utf-8", errors="strict")
    if has_bom:
        encoded = b"\xef\xbb\xbf" + encoded
    if not 1 <= len(encoded) <= MAX_ENVIRONMENT_BYTES:
        _fail(EnvironmentReplacementErrorCode.CONTENT_INVALID)
    return encoded


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentReplacementPlan:
    """Immutable original/candidate bytes and exact state classifier."""

    schema_version: int
    original_contents: bytes | None = field(repr=False)
    candidate_contents: bytes = field(repr=False)
    original_sha256: str = field(repr=False)
    candidate_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        expected_original = (
            ABSENT_FILE_SHA256
            if self.original_contents is None
            else _sha256(self.original_contents)
        )
        if (
            self.schema_version != _SCHEMA_VERSION
            or (
                self.original_contents is not None
                and (
                    type(self.original_contents) is not bytes
                    or len(self.original_contents) > MAX_ENVIRONMENT_BYTES
                )
            )
            or type(self.candidate_contents) is not bytes
            or not 1 <= len(self.candidate_contents) <= MAX_ENVIRONMENT_BYTES
            or type(self.original_sha256) is not str
            or not _SHA256.fullmatch(self.original_sha256)
            or self.original_sha256 != expected_original
            or type(self.candidate_sha256) is not str
            or not _SHA256.fullmatch(self.candidate_sha256)
            or self.candidate_sha256 != _sha256(self.candidate_contents)
        ):
            raise ValueError("Environment replacement plan is invalid.")

    def classify(self, observed_contents: bytes | None) -> EnvironmentContentState:
        if observed_contents is None:
            return EnvironmentContentState.ABSENT
        if type(observed_contents) is not bytes:
            _fail(EnvironmentReplacementErrorCode.INPUT_INVALID)
        if (
            self.original_contents is not None
            and observed_contents == self.original_contents
        ):
            return EnvironmentContentState.ORIGINAL
        if observed_contents == self.candidate_contents:
            return EnvironmentContentState.CANDIDATE
        return EnvironmentContentState.THIRD_STATE

    def __repr__(self) -> str:
        original = "absent" if self.original_contents is None else "present"
        return (
            "EnvironmentReplacementPlan("
            f"schema_version={self.schema_version}, original={original!r}, <redacted>)"
        )


def plan_ca_environment_replacement(
    source_contents: bytes,
    *,
    original_present: bool,
) -> EnvironmentReplacementPlan:
    """Build a pure CA-setting update from existing or template bytes."""

    if type(original_present) is not bool:
        _fail(EnvironmentReplacementErrorCode.INPUT_INVALID)
    candidate = _candidate_contents(source_contents)
    original = source_contents if original_present else None
    return EnvironmentReplacementPlan(
        schema_version=_SCHEMA_VERSION,
        original_contents=original,
        candidate_contents=candidate,
        original_sha256=(
            _sha256(source_contents) if original_present else ABSENT_FILE_SHA256
        ),
        candidate_sha256=_sha256(candidate),
    )


__all__ = [
    "EnvironmentContentState",
    "EnvironmentReplacementError",
    "EnvironmentReplacementErrorCode",
    "EnvironmentReplacementPlan",
    "MAX_ENVIRONMENT_BYTES",
    "plan_ca_environment_replacement",
]
