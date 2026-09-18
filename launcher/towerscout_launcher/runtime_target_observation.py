"""Fail-closed process plans for Gate-A target observation and recreation.

This module does not execute a child process.  It binds every future Compose
or engine observation to an immutable :class:`TargetResolutionPlan`, an
absolute authenticated executable, an explicit endpoint, a minimal child
environment, and the complete set of file/path identities that an execution
owner must retain.  Dynamic daemon selectors are deliberately limited to one
full container ID, one provider-canonical full image ID, or one of
TowerScout's eight derived named-volume names. Docker uses
``sha256:<64-hex>`` while Podman emits and accepts a bare 64-hex image ID.

The native executor and provider-specific output normalizers remain separate
review boundaries. Constructing these plans performs no Docker, Podman,
Compose, filesystem, or launcher mutation. Mutating plans are limited to exact
prior-profile recreation plus fixed certificate staging, atomic restoration,
and removal commands. Only the owned recovery backend may issue them while the
target's native authority is retained; the recovery adapter separately retains
certificate source authority across every staging command.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import NoReturn, Sequence

from .runtime_target_resolution import TargetResolutionPlan
from .target_contracts import (
    CONTAINER_BUNDLE_DESTINATION,
    CONTAINER_CERT_DESTINATION,
    EXPECTED_VOLUME_DESTINATIONS,
    ComposeInvocationKind,
    EndpointBindingKind,
    FileIdentity,
    MapProvider,
    RuntimeProduct,
)

OBSERVATION_CA_DESTINATION = CONTAINER_BUNDLE_DESTINATION
OBSERVATION_TIMEOUT_MS = 15_000
OBSERVATION_COMPOSE_STDOUT_LIMIT_BYTES = 1024 * 1024
OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES = 1024 * 1024
OBSERVATION_LIST_STDOUT_LIMIT_BYTES = 8 * 1024
OBSERVATION_STDERR_LIMIT_BYTES = 16 * 1024
RECREATION_TIMEOUT_MS = 120_000
RECREATION_STDERR_LIMIT_BYTES = 64 * 1024
RUNTIME_RESTART_TIMEOUT_MS = 120_000
RUNTIME_RESTART_STDERR_LIMIT_BYTES = 64 * 1024
CERTIFICATE_OPERATION_TIMEOUT_MS = 30_000
CERTIFICATE_OPERATION_STDOUT_LIMIT_BYTES = 8 * 1024
CERTIFICATE_OPERATION_STDERR_LIMIT_BYTES = 16 * 1024

_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_DOCKER_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_PODMAN_IMAGE_ID = re.compile(r"^[0-9a-f]{64}$")
_CERTIFICATE_TEMP_NAME = re.compile(r"^recovery-certificate-[0-9a-f]{32}\.tmp$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_ARGUMENTS = 128
_MAX_ARGUMENT_CHARACTERS = 32_767
_MAX_COMMAND_LINE_CHARACTERS = 32_767
_MAX_ENVIRONMENT_ITEMS = 32
_MAX_ENVIRONMENT_BLOCK_CHARACTERS = 32_767


class ObservationOperation(str, Enum):
    COMPOSE_MODEL_CURRENT = "compose_model_current"
    COMPOSE_MODEL_PLANNED = "compose_model_planned"
    CONTAINER_LIST = "container_list"
    CONTAINER_INSPECT = "container_inspect"
    IMAGE_INSPECT = "image_inspect"
    VOLUME_INSPECT = "volume_inspect"
    COMPOSE_RECREATE_PRIOR_PROFILE = "compose_recreate_prior_profile"
    COMPOSE_RESTART_PRIOR_PROFILE = "compose_restart_prior_profile"
    CERTIFICATE_OBSERVE = "certificate_observe"
    CERTIFICATE_STAGE_ORIGINAL = "certificate_stage_original"
    CERTIFICATE_APPLY_ORIGINAL = "certificate_apply_original"
    CERTIFICATE_REMOVE_CANDIDATE = "certificate_remove_candidate"
    CERTIFICATE_REMOVE_STAGED_ORIGINAL = "certificate_remove_staged_original"
    ROLLBACK_READINESS_PROBE = "rollback_readiness_probe"
    ROLLBACK_PROVIDER_PROBE = "rollback_provider_probe"


class CertificateTargetDestination(str, Enum):
    LOCAL_CA = "local_ca"
    CA_BUNDLE = "ca_bundle"


def _certificate_destination_path(destination: CertificateTargetDestination) -> str:
    return (
        CONTAINER_CERT_DESTINATION
        if destination is CertificateTargetDestination.LOCAL_CA
        else CONTAINER_BUNDLE_DESTINATION
    )


def _certificate_stage_path(name: str) -> str:
    return f"/app/webapp/config/certs/.{name}"


@dataclass(frozen=True, slots=True, repr=False)
class CertificateRuntimeSelector:
    """Finite engine selector for one exact certificate recovery operation."""

    container_id: str = field(repr=False)
    destination: CertificateTargetDestination
    restore_temp_name: str | None = field(default=None, repr=False)
    source_path: PureWindowsPath | None = field(default=None, repr=False)
    original_sha256: str | None = field(default=None, repr=False)
    original_size: int | None = None
    original_mode: int | None = None
    candidate_sha256: str | None = field(default=None, repr=False)
    candidate_size: int | None = None
    candidate_mode: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.container_id) is not str
            or _CONTAINER_ID.fullmatch(self.container_id) is None
            or type(self.destination) is not CertificateTargetDestination
            or (
                self.restore_temp_name is not None
                and (
                    type(self.restore_temp_name) is not str
                    or _CERTIFICATE_TEMP_NAME.fullmatch(self.restore_temp_name) is None
                )
            )
            or (
                self.source_path is not None
                and type(self.source_path) is not PureWindowsPath
            )
        ):
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        if self.source_path is not None:
            path = self.source_path
            if (
                not path.is_absolute()
                or self.restore_temp_name is None
                or path.name != self.restore_temp_name
                or path.parent.name.casefold() != "v1"
                or path.parent.parent.name.casefold() != "recovery"
                or path.parent.parent.parent.name.casefold() != "towerscout"
            ):
                _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        hashes = (self.original_sha256, self.candidate_sha256)
        sizes = (self.original_size, self.candidate_size)
        modes = (self.original_mode, self.candidate_mode)
        if (
            any(
                value is not None
                and (type(value) is not str or _SHA256.fullmatch(value) is None)
                for value in hashes
            )
            or any(
                value is not None and (type(value) is not int or value < 0)
                for value in sizes
            )
            or any(
                value is not None
                and (type(value) is not int or not 0 <= value <= 0o7777)
                for value in modes
            )
        ):
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)

    @property
    def destination_path(self) -> str:
        return _certificate_destination_path(self.destination)

    @property
    def stage_path(self) -> str | None:
        return (
            None
            if self.restore_temp_name is None
            else _certificate_stage_path(self.restore_temp_name)
        )

    def __repr__(self) -> str:
        return (
            "CertificateRuntimeSelector("
            f"destination={self.destination.value!r}, <redacted>)"
        )


class TargetObservationBindingErrorCode(str, Enum):
    TARGET_MISMATCH = "target_mismatch"
    OPERATION_REJECTED = "operation_rejected"
    SELECTOR_REJECTED = "selector_rejected"
    PLAN_REJECTED = "plan_rejected"


_PUBLIC_ERROR_MESSAGES = {
    TargetObservationBindingErrorCode.TARGET_MISMATCH: (
        "The target-observation authority is inconsistent."
    ),
    TargetObservationBindingErrorCode.OPERATION_REJECTED: (
        "The requested target-observation operation is not allowed."
    ),
    TargetObservationBindingErrorCode.SELECTOR_REJECTED: (
        "The requested target-observation selector is not allowed."
    ),
    TargetObservationBindingErrorCode.PLAN_REJECTED: (
        "The target-observation process plan is invalid."
    ),
}


class TargetObservationBindingError(ValueError):
    """A fixed-category error that never includes private plan material."""

    def __init__(self, code: TargetObservationBindingErrorCode) -> None:
        if type(code) is not TargetObservationBindingErrorCode:
            raise ValueError("Unknown target-observation binding error code.")
        self.code = code
        super().__init__(_PUBLIC_ERROR_MESSAGES[code])

    def __repr__(self) -> str:
        return f"TargetObservationBindingError(code={self.code.value!r})"


def _reject(code: TargetObservationBindingErrorCode) -> NoReturn:
    raise TargetObservationBindingError(code)


def _same_file_identity(left: FileIdentity, right: FileIdentity) -> bool:
    return (
        left.logical_name == right.logical_name
        and left.final_path == right.final_path
        and left.volume_serial == right.volume_serial
        and left.file_id == right.file_id
        and left.is_directory == right.is_directory
        and left.sha256 == right.sha256
        and left.size_bytes == right.size_bytes
    )


def _deduplicated_identities(
    identities: Sequence[FileIdentity],
) -> tuple[FileIdentity, ...]:
    output: list[FileIdentity] = []
    for identity in identities:
        if not any(_same_file_identity(identity, current) for current in output):
            output.append(identity)
    return tuple(output)


def _windows_environment(
    target: TargetResolutionPlan,
) -> tuple[tuple[str, str], ...]:
    environment = target.process_environment
    return (
        ("SYSTEMROOT", str(environment.system_root.final_path)),
        ("WINDIR", str(environment.system_root.final_path)),
        ("TEMP", str(environment.temp_directory.final_path)),
        ("TMP", str(environment.temp_directory.final_path)),
        ("USERPROFILE", str(environment.user_profile.final_path)),
        ("LOCALAPPDATA", str(environment.local_app_data.final_path)),
        ("APPDATA", str(environment.roaming_app_data.final_path)),
    )


def _all_authenticated_identities(
    target: TargetResolutionPlan,
) -> tuple[FileIdentity, ...]:
    endpoint_key = (
        () if target.endpoint.identity_key is None else (target.endpoint.identity_key,)
    )
    return _deduplicated_identities(
        (
            target.runtime.executable,
            *target.compose_provider.artifacts,
            *target.ordered_compose_files,
            target.environment_source,
            *target.security_artifacts.ordered_files,
            target.package_root,
            target.process_environment.system_root,
            target.process_environment.temp_directory,
            target.process_environment.user_profile,
            target.process_environment.local_app_data,
            target.process_environment.roaming_app_data,
            *endpoint_key,
            *target.endpoint.discovery_artifacts,
        )
    )


def _valid_argument(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= _MAX_ARGUMENT_CHARACTERS
        and "\x00" not in value
        and not any(ord(character) < 0x20 for character in value)
    )


def _utf16_code_units(value: str) -> int | None:
    try:
        return len(value.encode("utf-16-le", errors="strict")) // 2
    except UnicodeError:
        return None


def _command_line_upper_bound(
    executable: FileIdentity,
    arguments: tuple[str, ...],
) -> int:
    """Bound Windows quoting without constructing or exposing the command."""

    values = (str(executable.final_path), *arguments)
    code_units = tuple(_utf16_code_units(value) for value in values)
    if any(value is None for value in code_units):
        return _MAX_COMMAND_LINE_CHARACTERS + 1
    # Windows quoting can at most double each input code unit, add two quote
    # characters per argv item, one separator between items, and the final NUL.
    return sum(2 * value + 2 for value in code_units if value is not None) + len(values)


def _environment_block_characters(
    environment_items: tuple[tuple[str, str], ...],
) -> int:
    total = 1
    for name, value in environment_items:
        name_characters = _utf16_code_units(name)
        value_characters = _utf16_code_units(value)
        if name_characters is None or value_characters is None:
            return _MAX_ENVIRONMENT_BLOCK_CHARACTERS + 1
        total += name_characters + value_characters + 2
    # Each entry is NAME=VALUE\0 and the complete block has one final NUL.
    return total


def _require_executable(identity: FileIdentity, leaf: str) -> None:
    if (
        type(identity) is not FileIdentity
        or identity.is_directory
        or not identity.final_path.is_absolute()
        or identity.logical_name.casefold() != leaf
        or identity.final_path.name.casefold() != leaf
    ):
        _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)


def _endpoint_prefix(target: TargetResolutionPlan) -> tuple[str, ...]:
    if target.runtime.product is RuntimeProduct.DOCKER:
        return ("--host", target.endpoint.canonical_endpoint)
    key = target.endpoint.identity_key
    if key is None:
        _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)
    return (
        "--url",
        target.endpoint.canonical_endpoint,
        "--identity",
        str(key.final_path),
    )


_CERTIFICATE_OBSERVE_SCRIPT = (
    "import hashlib,json,os,stat,sys\n"
    "p=sys.argv[1]\n"
    "present=os.path.lexists(p)\n"
    "f=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)) if present else None\n"
    "s=os.fstat(f) if f is not None else None\n"
    "if s is not None and not stat.S_ISREG(s.st_mode): raise SystemExit(42)\n"
    "h=hashlib.sha256()\n"
    "if f is not None:\n"
    " while True:\n"
    "  chunk=os.read(f,1048576)\n"
    "  if not chunk: break\n"
    "  h.update(chunk)\n"
    "s2=os.fstat(f) if f is not None else None\n"
    "same=s is None or (s.st_dev,s.st_ino,s.st_size,s.st_mode)=="
    "(s2.st_dev,s2.st_ino,s2.st_size,s2.st_mode)\n"
    "if f is not None: os.close(f)\n"
    "if not same: raise SystemExit(42)\n"
    "value={'present':present}\n"
    "if present: value.update(sha256=h.hexdigest(),size=s.st_size,"
    "mode=stat.S_IMODE(s.st_mode))\n"
    "print(json.dumps(value,sort_keys=True,separators=(',',':')))\n"
)

_CERTIFICATE_APPLY_SCRIPT = (
    "import hashlib,os,stat,sys\n"
    "d,t,oh,oz,om,ch,cz,cm=sys.argv[1:]\n"
    "oz=int(oz); om=int(om,8); cz=int(cz); cm=int(cm,8)\n"
    "def snap(p,h,z,m):\n"
    " f=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))\n"
    " s=os.fstat(f); x=hashlib.sha256()\n"
    " while True:\n"
    "  b=os.read(f,1048576)\n"
    "  if not b: break\n"
    "  x.update(b)\n"
    " s2=os.fstat(f)\n"
    " ok=(stat.S_ISREG(s.st_mode) and s.st_size==z and "
    "stat.S_IMODE(s.st_mode)==m and x.hexdigest()==h and "
    "(s.st_dev,s.st_ino,s.st_size,s.st_mode)=="
    "(s2.st_dev,s2.st_ino,s2.st_size,s2.st_mode))\n"
    " return f,s,ok\n"
    "df,ds,dok=snap(d,ch,cz,cm)\n"
    "tf,ts,tok=snap(t,oh,oz,stat.S_IMODE(os.lstat(t).st_mode))\n"
    "os.fchmod(tf,om); ts2=os.fstat(tf)\n"
    "tok=tok and stat.S_IMODE(ts2.st_mode)==om\n"
    "dok=dok and os.path.samestat(ds,os.lstat(d))\n"
    "tok=tok and os.path.samestat(ts2,os.lstat(t))\n"
    "if not dok or not tok: raise SystemExit(43)\n"
    "os.replace(t,d); os.close(df); os.close(tf)\n"
)

_CERTIFICATE_REMOVE_SCRIPT = (
    "import hashlib,os,stat,sys\n"
    "p,h,z,m=sys.argv[1:]; z=int(z); m=int(m,8)\n"
    "f=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)); s=os.fstat(f)\n"
    "x=hashlib.sha256()\n"
    "while True:\n"
    " b=os.read(f,1048576)\n"
    " if not b: break\n"
    " x.update(b)\n"
    "s2=os.fstat(f)\n"
    "ok=(stat.S_ISREG(s.st_mode) and s.st_size==z and "
    "stat.S_IMODE(s.st_mode)==m and x.hexdigest()==h and "
    "(s.st_dev,s.st_ino,s.st_size,s.st_mode)=="
    "(s2.st_dev,s2.st_ino,s2.st_size,s2.st_mode) and "
    "os.path.samestat(s2,os.lstat(p)))\n"
    "if not ok: raise SystemExit(44)\n"
    "os.unlink(p); os.close(f)\n"
)

_ROLLBACK_READINESS_PROBE_SCRIPT = (
    "import json,sys,urllib.request\n"
    "req=urllib.request.Request('http://127.0.0.1:5000/api/readiness',"
    "headers={'Accept':'application/json'},method='GET')\n"
    "with urllib.request.urlopen(req,timeout=5) as response:\n"
    " data=response.read(8193)\n"
    " if response.status!=200 or len(data)>8192: raise SystemExit(45)\n"
    "value=json.loads(data.decode('utf-8','strict'))\n"
    "state=value.get('state') if type(value) is dict else None\n"
    "if state not in {'setup_required','degraded','ready'}: raise SystemExit(45)\n"
    "print(state)\n"
)

_ROLLBACK_PROVIDER_PROBE_SCRIPT = (
    "import socket,ssl,sys\n"
    "host=sys.argv[1]\n"
    "outcome='provider_recheck_indeterminate'\n"
    "try:\n"
    " context=ssl.create_default_context()\n"
    " with socket.create_connection((host,443),timeout=5) as connection:\n"
    "  with context.wrap_socket(connection,server_hostname=host): pass\n"
    " outcome='success'\n"
    "except ssl.SSLCertVerificationError:\n"
    " outcome='repairable_tls_failure'\n"
    "except (OSError,ssl.SSLError,TimeoutError):\n"
    " pass\n"
    "print(outcome)\n"
)

# Command arguments cannot contain control characters.  The reviewed program
# is therefore passed as one literal to a fixed outer ``exec`` expression.
_CERTIFICATE_OBSERVE_SCRIPT = f"exec({_CERTIFICATE_OBSERVE_SCRIPT!r})"
_CERTIFICATE_APPLY_SCRIPT = f"exec({_CERTIFICATE_APPLY_SCRIPT!r})"
_CERTIFICATE_REMOVE_SCRIPT = f"exec({_CERTIFICATE_REMOVE_SCRIPT!r})"
_ROLLBACK_READINESS_PROBE_SCRIPT = f"exec({_ROLLBACK_READINESS_PROBE_SCRIPT!r})"
_ROLLBACK_PROVIDER_PROBE_SCRIPT = f"exec({_ROLLBACK_PROVIDER_PROBE_SCRIPT!r})"


def _certificate_selector_valid(
    operation: ObservationOperation,
    selector: CertificateRuntimeSelector,
) -> bool:
    optional = (
        selector.restore_temp_name,
        selector.source_path,
        selector.original_sha256,
        selector.original_size,
        selector.original_mode,
        selector.candidate_sha256,
        selector.candidate_size,
        selector.candidate_mode,
    )
    if operation is ObservationOperation.CERTIFICATE_OBSERVE:
        return selector.source_path is None and all(
            value is None for value in optional[2:]
        )
    if operation is ObservationOperation.CERTIFICATE_STAGE_ORIGINAL:
        return (
            selector.restore_temp_name is not None
            and selector.source_path is not None
            and all(value is None for value in optional[2:])
        )
    if operation is ObservationOperation.CERTIFICATE_APPLY_ORIGINAL:
        return (
            selector.restore_temp_name is not None
            and selector.source_path is None
            and all(value is not None for value in optional[2:])
        )
    if operation is ObservationOperation.CERTIFICATE_REMOVE_CANDIDATE:
        return (
            selector.restore_temp_name is None
            and selector.source_path is None
            and all(value is None for value in optional[2:5])
            and all(value is not None for value in optional[5:])
        )
    if operation is ObservationOperation.CERTIFICATE_REMOVE_STAGED_ORIGINAL:
        return (
            selector.restore_temp_name is not None
            and selector.source_path is None
            and all(value is not None for value in optional[2:5])
            and all(value is None for value in optional[5:])
        )
    return False


@dataclass(frozen=True, slots=True, repr=False)
class _ExpectedProcess:
    executable: FileIdentity
    arguments: tuple[str, ...]
    environment_items: tuple[tuple[str, str], ...]
    authenticated_files: tuple[FileIdentity, ...]
    timeout_ms: int
    stdout_limit_bytes: int
    stderr_limit_bytes: int


def _compose_expected(
    target: TargetResolutionPlan,
    *,
    operation: ObservationOperation,
) -> _ExpectedProcess:
    if operation not in {
        ObservationOperation.COMPOSE_MODEL_CURRENT,
        ObservationOperation.COMPOSE_MODEL_PLANNED,
        ObservationOperation.COMPOSE_RECREATE_PRIOR_PROFILE,
        ObservationOperation.COMPOSE_RESTART_PRIOR_PROFILE,
    }:
        _reject(TargetObservationBindingErrorCode.OPERATION_REJECTED)
    planned = operation is ObservationOperation.COMPOSE_MODEL_PLANNED
    recreate = operation is ObservationOperation.COMPOSE_RECREATE_PRIOR_PROFILE
    restart = operation is ObservationOperation.COMPOSE_RESTART_PRIOR_PROFILE
    environment = _windows_environment(target)
    if target.runtime.product is RuntimeProduct.DOCKER:
        provider = target.compose_provider
        if (
            provider.invocation_kind
            is not ComposeInvocationKind.DOCKER_COMPOSE_EXECUTABLE
            or provider.endpoint_binding is not EndpointBindingKind.DOCKER_HOST_ARGUMENT
            or not provider.artifacts
        ):
            _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)
        executable = provider.artifacts[0]
        _require_executable(executable, "docker-compose.exe")
        prefix = (
            "--host",
            target.endpoint.canonical_endpoint,
            "--project-name",
            target.compose_project,
            "--project-directory",
            str(target.package_root.final_path),
            *tuple(
                value
                for identity in target.ordered_compose_files
                for value in ("--file", str(identity.final_path))
            ),
            "--env-file",
            str(target.environment_source.final_path),
        )
        docker_action = (
            ("up", "-d", "--no-deps", "towerscout")
            if recreate
            else (
                ("up", "-d", "--no-deps", "--force-recreate", "towerscout")
                if restart
                else ("config", "--format", "json")
            )
        )
        arguments = (*prefix, *docker_action)
    else:
        provider = target.compose_provider
        key = target.endpoint.identity_key
        if (
            provider.invocation_kind is not ComposeInvocationKind.PODMAN_PYTHON_MODULE
            or provider.endpoint_binding
            is not EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT
            or len(provider.artifacts) < 2
            or key is None
        ):
            _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)
        executable = provider.artifacts[0]
        _require_executable(executable, "python.exe")
        _require_executable(target.runtime.executable, "podman.exe")
        prefix = (
            "-I",
            "-B",
            "-m",
            "podman_compose",
            "--podman-path",
            str(target.runtime.executable.final_path),
            "-p",
            target.compose_project,
            *tuple(
                value
                for identity in target.ordered_compose_files
                for value in ("-f", str(identity.final_path))
            ),
            "--env-file",
            str(target.environment_source.final_path),
        )
        podman_action = (
            ("up", "-d", "--no-deps", "towerscout")
            if recreate
            else (
                ("up", "-d", "--no-deps", "--force-recreate", "towerscout")
                if restart
                else ("config",)
            )
        )
        arguments = (*prefix, *podman_action)
        environment = (
            *environment,
            ("COMPOSE_PROJECT_DIR", str(target.package_root.final_path)),
            ("CONTAINER_HOST", target.endpoint.canonical_endpoint),
            ("CONTAINER_SSHKEY", str(key.final_path)),
        )
    if planned:
        environment = (
            *environment,
            ("REQUESTS_CA_BUNDLE", OBSERVATION_CA_DESTINATION),
            ("SSL_CERT_FILE", OBSERVATION_CA_DESTINATION),
        )
    return _ExpectedProcess(
        executable=executable,
        arguments=arguments,
        environment_items=environment,
        authenticated_files=_all_authenticated_identities(target),
        timeout_ms=(
            RECREATION_TIMEOUT_MS
            if recreate
            else RUNTIME_RESTART_TIMEOUT_MS if restart else OBSERVATION_TIMEOUT_MS
        ),
        stdout_limit_bytes=OBSERVATION_COMPOSE_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=(
            (
                RECREATION_STDERR_LIMIT_BYTES
                if recreate
                else RUNTIME_RESTART_STDERR_LIMIT_BYTES
            )
            if (recreate or restart)
            else OBSERVATION_STDERR_LIMIT_BYTES
        ),
    )


def _valid_selector(
    operation: ObservationOperation,
    target: TargetResolutionPlan,
    selector: str | CertificateRuntimeSelector | None,
) -> bool:
    if operation in {
        ObservationOperation.COMPOSE_MODEL_CURRENT,
        ObservationOperation.COMPOSE_MODEL_PLANNED,
        ObservationOperation.COMPOSE_RECREATE_PRIOR_PROFILE,
        ObservationOperation.COMPOSE_RESTART_PRIOR_PROFILE,
        ObservationOperation.CONTAINER_LIST,
    }:
        return selector is None
    if operation is ObservationOperation.CONTAINER_INSPECT:
        return type(selector) is str and _CONTAINER_ID.fullmatch(selector) is not None
    if operation is ObservationOperation.IMAGE_INSPECT:
        pattern = (
            _DOCKER_IMAGE_ID
            if target.runtime.product is RuntimeProduct.DOCKER
            else _PODMAN_IMAGE_ID
        )
        return type(selector) is str and (
            pattern.fullmatch(selector) is not None
            or selector == target.configured_image_reference
        )
    if operation is ObservationOperation.VOLUME_INSPECT:
        expected = {
            f"{target.compose_project}_{logical_name}"
            for logical_name, _destination in EXPECTED_VOLUME_DESTINATIONS
        }
        return type(selector) is str and selector in expected
    if operation in {
        ObservationOperation.CERTIFICATE_OBSERVE,
        ObservationOperation.CERTIFICATE_STAGE_ORIGINAL,
        ObservationOperation.CERTIFICATE_APPLY_ORIGINAL,
        ObservationOperation.CERTIFICATE_REMOVE_CANDIDATE,
        ObservationOperation.CERTIFICATE_REMOVE_STAGED_ORIGINAL,
    }:
        return type(selector) is CertificateRuntimeSelector and (
            _certificate_selector_valid(operation, selector)
        )
    if operation in {
        ObservationOperation.ROLLBACK_READINESS_PROBE,
        ObservationOperation.ROLLBACK_PROVIDER_PROBE,
    }:
        return type(selector) is str and _CONTAINER_ID.fullmatch(selector) is not None
    return False


def _engine_expected(
    target: TargetResolutionPlan,
    operation: ObservationOperation,
    selector: str | CertificateRuntimeSelector | None,
) -> _ExpectedProcess:
    _require_executable(
        target.runtime.executable,
        (
            "docker.exe"
            if target.runtime.product is RuntimeProduct.DOCKER
            else "podman.exe"
        ),
    )
    prefix = _endpoint_prefix(target)
    project_label = (
        "com.docker.compose.project"
        if target.runtime.product is RuntimeProduct.DOCKER
        else "io.podman.compose.project"
    )
    service_label = (
        "com.docker.compose.service"
        if target.runtime.product is RuntimeProduct.DOCKER
        else "io.podman.compose.service"
    )
    suffix: tuple[str, ...]
    if operation is ObservationOperation.CONTAINER_LIST:
        suffix = (
            "container",
            "ls",
            "--all",
            "--filter",
            f"label={project_label}={target.compose_project}",
            "--filter",
            f"label={service_label}=towerscout",
            "--no-trunc",
            "--quiet",
        )
        stdout_limit = OBSERVATION_LIST_STDOUT_LIMIT_BYTES
    elif operation is ObservationOperation.CONTAINER_INSPECT:
        suffix = ("container", "inspect", selector if type(selector) is str else "")
        stdout_limit = OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES
    elif operation is ObservationOperation.IMAGE_INSPECT:
        suffix = ("image", "inspect", selector if type(selector) is str else "")
        stdout_limit = OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES
    elif operation is ObservationOperation.VOLUME_INSPECT:
        suffix = ("volume", "inspect", selector if type(selector) is str else "")
        stdout_limit = OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES
    elif operation is ObservationOperation.CERTIFICATE_OBSERVE:
        if type(selector) is not CertificateRuntimeSelector:
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        path = selector.stage_path or selector.destination_path
        suffix = (
            "container",
            "exec",
            selector.container_id,
            "python",
            "-c",
            _CERTIFICATE_OBSERVE_SCRIPT,
            path,
        )
        stdout_limit = CERTIFICATE_OPERATION_STDOUT_LIMIT_BYTES
    elif operation is ObservationOperation.CERTIFICATE_STAGE_ORIGINAL:
        if (
            type(selector) is not CertificateRuntimeSelector
            or selector.source_path is None
            or selector.stage_path is None
        ):
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        suffix = (
            "container",
            "cp",
            str(selector.source_path),
            f"{selector.container_id}:{selector.stage_path}",
        )
        stdout_limit = CERTIFICATE_OPERATION_STDOUT_LIMIT_BYTES
    elif operation is ObservationOperation.CERTIFICATE_APPLY_ORIGINAL:
        if (
            type(selector) is not CertificateRuntimeSelector
            or selector.stage_path is None
        ):
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        suffix = (
            "container",
            "exec",
            selector.container_id,
            "python",
            "-c",
            _CERTIFICATE_APPLY_SCRIPT,
            selector.destination_path,
            selector.stage_path,
            selector.original_sha256 or "",
            str(selector.original_size),
            format(selector.original_mode or 0, "o"),
            selector.candidate_sha256 or "",
            str(selector.candidate_size),
            format(selector.candidate_mode or 0, "o"),
        )
        stdout_limit = CERTIFICATE_OPERATION_STDOUT_LIMIT_BYTES
    elif operation is ObservationOperation.CERTIFICATE_REMOVE_CANDIDATE:
        if type(selector) is not CertificateRuntimeSelector:
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        suffix = (
            "container",
            "exec",
            selector.container_id,
            "python",
            "-c",
            _CERTIFICATE_REMOVE_SCRIPT,
            selector.destination_path,
            selector.candidate_sha256 or "",
            str(selector.candidate_size),
            format(selector.candidate_mode or 0, "o"),
        )
        stdout_limit = CERTIFICATE_OPERATION_STDOUT_LIMIT_BYTES
    elif operation is ObservationOperation.CERTIFICATE_REMOVE_STAGED_ORIGINAL:
        if (
            type(selector) is not CertificateRuntimeSelector
            or selector.stage_path is None
        ):
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        suffix = (
            "container",
            "exec",
            selector.container_id,
            "python",
            "-c",
            _CERTIFICATE_REMOVE_SCRIPT,
            selector.stage_path,
            selector.original_sha256 or "",
            str(selector.original_size),
            format(selector.original_mode or 0, "o"),
        )
        stdout_limit = CERTIFICATE_OPERATION_STDOUT_LIMIT_BYTES
    elif operation is ObservationOperation.ROLLBACK_READINESS_PROBE:
        if type(selector) is not str:
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        suffix = (
            "container",
            "exec",
            selector,
            "python",
            "-c",
            _ROLLBACK_READINESS_PROBE_SCRIPT,
        )
        stdout_limit = 128
    elif operation is ObservationOperation.ROLLBACK_PROVIDER_PROBE:
        if type(selector) is not str:
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        provider_host = (
            "maps.googleapis.com"
            if target.provider is MapProvider.GOOGLE
            else "atlas.microsoft.com"
        )
        suffix = (
            "container",
            "exec",
            selector,
            "python",
            "-c",
            _ROLLBACK_PROVIDER_PROBE_SCRIPT,
            provider_host,
        )
        stdout_limit = 128
    else:
        _reject(TargetObservationBindingErrorCode.OPERATION_REJECTED)
    return _ExpectedProcess(
        executable=target.runtime.executable,
        arguments=(*prefix, *suffix),
        environment_items=_windows_environment(target),
        authenticated_files=_all_authenticated_identities(target),
        timeout_ms=(
            CERTIFICATE_OPERATION_TIMEOUT_MS
            if operation
            in {
                ObservationOperation.CERTIFICATE_OBSERVE,
                ObservationOperation.CERTIFICATE_STAGE_ORIGINAL,
                ObservationOperation.CERTIFICATE_APPLY_ORIGINAL,
                ObservationOperation.CERTIFICATE_REMOVE_CANDIDATE,
                ObservationOperation.CERTIFICATE_REMOVE_STAGED_ORIGINAL,
                ObservationOperation.ROLLBACK_READINESS_PROBE,
                ObservationOperation.ROLLBACK_PROVIDER_PROBE,
            }
            else OBSERVATION_TIMEOUT_MS
        ),
        stdout_limit_bytes=stdout_limit,
        stderr_limit_bytes=(
            CERTIFICATE_OPERATION_STDERR_LIMIT_BYTES
            if operation
            in {
                ObservationOperation.CERTIFICATE_OBSERVE,
                ObservationOperation.CERTIFICATE_STAGE_ORIGINAL,
                ObservationOperation.CERTIFICATE_APPLY_ORIGINAL,
                ObservationOperation.CERTIFICATE_REMOVE_CANDIDATE,
                ObservationOperation.CERTIFICATE_REMOVE_STAGED_ORIGINAL,
                ObservationOperation.ROLLBACK_READINESS_PROBE,
                ObservationOperation.ROLLBACK_PROVIDER_PROBE,
            }
            else OBSERVATION_STDERR_LIMIT_BYTES
        ),
    )


def _expected_process(
    target: TargetResolutionPlan,
    operation: ObservationOperation,
    selector: str | CertificateRuntimeSelector | None,
) -> _ExpectedProcess:
    if not _valid_selector(operation, target, selector):
        _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
    if operation is ObservationOperation.COMPOSE_MODEL_CURRENT:
        return _compose_expected(target, operation=operation)
    if operation is ObservationOperation.COMPOSE_MODEL_PLANNED:
        return _compose_expected(target, operation=operation)
    if operation is ObservationOperation.COMPOSE_RECREATE_PRIOR_PROFILE:
        return _compose_expected(target, operation=operation)
    if operation is ObservationOperation.COMPOSE_RESTART_PRIOR_PROFILE:
        return _compose_expected(target, operation=operation)
    return _engine_expected(target, operation, selector)


@dataclass(frozen=True, slots=True, repr=False)
class TargetObservationProcessPlan:
    """One exact, inert, shell-free target-observation process plan."""

    operation: ObservationOperation
    target: TargetResolutionPlan = field(repr=False)
    executable: FileIdentity = field(repr=False)
    arguments: tuple[str, ...] = field(repr=False)
    environment_items: tuple[tuple[str, str], ...] = field(repr=False)
    authenticated_files: tuple[FileIdentity, ...] = field(repr=False)
    selector: str | CertificateRuntimeSelector | None = field(default=None, repr=False)
    timeout_ms: int = OBSERVATION_TIMEOUT_MS
    stdout_limit_bytes: int = OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES
    stderr_limit_bytes: int = OBSERVATION_STDERR_LIMIT_BYTES
    stdin_closed: bool = True
    shell: bool = False

    def __post_init__(self) -> None:
        structurally_valid = (
            type(self.operation) is ObservationOperation
            and type(self.target) is TargetResolutionPlan
            and type(self.executable) is FileIdentity
            and type(self.arguments) is tuple
            and 1 <= len(self.arguments) <= _MAX_ARGUMENTS
            and all(_valid_argument(value) for value in self.arguments)
            and _command_line_upper_bound(self.executable, self.arguments)
            <= _MAX_COMMAND_LINE_CHARACTERS
            and type(self.environment_items) is tuple
            and 1 <= len(self.environment_items) <= _MAX_ENVIRONMENT_ITEMS
            and all(
                type(item) is tuple
                and len(item) == 2
                and type(item[0]) is str
                and type(item[1]) is str
                and bool(item[0])
                and bool(item[1])
                and "\x00" not in item[0]
                and "\x00" not in item[1]
                for item in self.environment_items
            )
            and _environment_block_characters(self.environment_items)
            <= _MAX_ENVIRONMENT_BLOCK_CHARACTERS
            and type(self.authenticated_files) is tuple
            and all(type(item) is FileIdentity for item in self.authenticated_files)
            and (
                self.selector is None
                or type(self.selector) is str
                or type(self.selector) is CertificateRuntimeSelector
            )
            and type(self.timeout_ms) is int
            and type(self.stdout_limit_bytes) is int
            and type(self.stderr_limit_bytes) is int
            and self.stdin_closed is True
            and self.shell is False
        )
        if not structurally_valid:
            _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)
        try:
            expected = _expected_process(self.target, self.operation, self.selector)
        except TargetObservationBindingError as error:
            if error.code is TargetObservationBindingErrorCode.SELECTOR_REJECTED:
                raise
            _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)
        keys = tuple(name for name, _value in self.environment_items)
        if (
            not _same_file_identity(self.executable, expected.executable)
            or self.arguments != expected.arguments
            or self.environment_items != expected.environment_items
            or len(set(keys)) != len(keys)
            or self.authenticated_files != expected.authenticated_files
            or len({id(item) for item in self.authenticated_files})
            != len(self.authenticated_files)
            or self.timeout_ms != expected.timeout_ms
            or self.stdout_limit_bytes != expected.stdout_limit_bytes
            or self.stderr_limit_bytes != expected.stderr_limit_bytes
        ):
            _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)

    @property
    def authority_sha256(self) -> str:
        return self.target.authority_sha256

    @property
    def command(self) -> tuple[str, ...]:
        return (str(self.executable.final_path), *self.arguments)

    @property
    def environment(self) -> dict[str, str]:
        return dict(self.environment_items)

    @property
    def working_directory(self) -> PureWindowsPath:
        return self.target.package_root.final_path

    def __repr__(self) -> str:
        return (
            "TargetObservationProcessPlan("
            f"operation={self.operation.value!r}, runtime="
            f"{self.target.runtime.product.value!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TargetObservationProcessRequest:
    """Native-process request that can only wrap one validated observation plan."""

    plan: TargetObservationProcessPlan = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.plan) is not TargetObservationProcessPlan:
            _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)

    @classmethod
    def from_plan(
        cls, plan: TargetObservationProcessPlan
    ) -> "TargetObservationProcessRequest":
        return cls(plan)

    @property
    def executable_path(self) -> PureWindowsPath:
        return self.plan.executable.final_path

    @property
    def arguments(self) -> tuple[str, ...]:
        return self.plan.arguments

    @property
    def environment(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            sorted(self.plan.environment_items, key=lambda item: item[0].casefold())
        )

    @property
    def working_directory(self) -> PureWindowsPath:
        return self.plan.working_directory

    @property
    def timeout_ms(self) -> int:
        return self.plan.timeout_ms

    @property
    def stdout_limit_bytes(self) -> int:
        return self.plan.stdout_limit_bytes

    @property
    def stderr_limit_bytes(self) -> int:
        return self.plan.stderr_limit_bytes

    @property
    def stdin_closed(self) -> bool:
        return self.plan.stdin_closed

    @property
    def shell(self) -> bool:
        return self.plan.shell

    def __repr__(self) -> str:
        return (
            "TargetObservationProcessRequest("
            f"operation={self.plan.operation.value!r}, "
            f"arguments={len(self.plan.arguments)}, path='<redacted>')"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TargetObservationExecutionBinding:
    """Construct only the reviewed observation commands for one target plan."""

    target: TargetResolutionPlan = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.target) is not TargetResolutionPlan:
            _reject(TargetObservationBindingErrorCode.TARGET_MISMATCH)
        try:
            _compose_expected(
                self.target,
                operation=ObservationOperation.COMPOSE_MODEL_CURRENT,
            )
            _engine_expected(
                self.target,
                ObservationOperation.CONTAINER_LIST,
                None,
            )
        except TargetObservationBindingError:
            _reject(TargetObservationBindingErrorCode.TARGET_MISMATCH)

    def _build(
        self,
        operation: ObservationOperation,
        selector: str | CertificateRuntimeSelector | None = None,
    ) -> TargetObservationProcessPlan:
        if not _valid_selector(operation, self.target, selector):
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        expected = _expected_process(self.target, operation, selector)
        return TargetObservationProcessPlan(
            operation=operation,
            target=self.target,
            executable=expected.executable,
            arguments=expected.arguments,
            environment_items=expected.environment_items,
            authenticated_files=expected.authenticated_files,
            selector=selector,
            timeout_ms=expected.timeout_ms,
            stdout_limit_bytes=expected.stdout_limit_bytes,
            stderr_limit_bytes=expected.stderr_limit_bytes,
        )

    def compose_model(self, *, planned: bool) -> TargetObservationProcessPlan:
        if type(planned) is not bool:
            _reject(TargetObservationBindingErrorCode.OPERATION_REJECTED)
        return self._build(
            (
                ObservationOperation.COMPOSE_MODEL_PLANNED
                if planned
                else ObservationOperation.COMPOSE_MODEL_CURRENT
            )
        )

    def recreate_prior_profile(self) -> TargetObservationProcessPlan:
        """Build the one scoped recovery mutation without a volume-delete flag."""

        return self._build(ObservationOperation.COMPOSE_RECREATE_PRIOR_PROFILE)

    def restart_prior_profile(self) -> TargetObservationProcessPlan:
        """Recreate only the exact service without requesting volume deletion."""

        return self._build(ObservationOperation.COMPOSE_RESTART_PRIOR_PROFILE)

    def container_list(self) -> TargetObservationProcessPlan:
        return self._build(ObservationOperation.CONTAINER_LIST)

    def container_inspect(self, container_id: str) -> TargetObservationProcessPlan:
        return self._build(ObservationOperation.CONTAINER_INSPECT, container_id)

    def image_inspect(self, image_id: str) -> TargetObservationProcessPlan:
        return self._build(ObservationOperation.IMAGE_INSPECT, image_id)

    def configured_image_inspect(self) -> TargetObservationProcessPlan:
        """Inspect only the digest-pinned image recorded by the exact plan."""

        return self._build(
            ObservationOperation.IMAGE_INSPECT,
            self.target.configured_image_reference,
        )

    def volume_inspect(self, logical_name: str) -> TargetObservationProcessPlan:
        expected_logical = {item for item, _destination in EXPECTED_VOLUME_DESTINATIONS}
        if type(logical_name) is not str or logical_name not in expected_logical:
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        return self._build(
            ObservationOperation.VOLUME_INSPECT,
            f"{self.target.compose_project}_{logical_name}",
        )

    def volume_inspects(self) -> tuple[TargetObservationProcessPlan, ...]:
        return tuple(
            self.volume_inspect(logical_name)
            for logical_name, _destination in EXPECTED_VOLUME_DESTINATIONS
        )

    def certificate_observe(
        self,
        *,
        container_id: str,
        destination: CertificateTargetDestination,
        restore_temp_name: str | None = None,
    ) -> TargetObservationProcessPlan:
        return self._build(
            ObservationOperation.CERTIFICATE_OBSERVE,
            CertificateRuntimeSelector(
                container_id,
                destination,
                restore_temp_name=restore_temp_name,
            ),
        )

    def certificate_stage_original(
        self,
        *,
        container_id: str,
        destination: CertificateTargetDestination,
        restore_temp_name: str,
        source_path: PureWindowsPath,
    ) -> TargetObservationProcessPlan:
        return self._build(
            ObservationOperation.CERTIFICATE_STAGE_ORIGINAL,
            CertificateRuntimeSelector(
                container_id,
                destination,
                restore_temp_name=restore_temp_name,
                source_path=source_path,
            ),
        )

    def certificate_apply_original(
        self,
        *,
        container_id: str,
        destination: CertificateTargetDestination,
        restore_temp_name: str,
        original_sha256: str,
        original_size: int,
        original_mode: int,
        candidate_sha256: str,
        candidate_size: int,
        candidate_mode: int,
    ) -> TargetObservationProcessPlan:
        return self._build(
            ObservationOperation.CERTIFICATE_APPLY_ORIGINAL,
            CertificateRuntimeSelector(
                container_id,
                destination,
                restore_temp_name=restore_temp_name,
                original_sha256=original_sha256,
                original_size=original_size,
                original_mode=original_mode,
                candidate_sha256=candidate_sha256,
                candidate_size=candidate_size,
                candidate_mode=candidate_mode,
            ),
        )

    def certificate_remove_candidate(
        self,
        *,
        container_id: str,
        destination: CertificateTargetDestination,
        candidate_sha256: str,
        candidate_size: int,
        candidate_mode: int,
    ) -> TargetObservationProcessPlan:
        return self._build(
            ObservationOperation.CERTIFICATE_REMOVE_CANDIDATE,
            CertificateRuntimeSelector(
                container_id,
                destination,
                candidate_sha256=candidate_sha256,
                candidate_size=candidate_size,
                candidate_mode=candidate_mode,
            ),
        )

    def certificate_remove_staged_original(
        self,
        *,
        container_id: str,
        destination: CertificateTargetDestination,
        restore_temp_name: str,
        original_sha256: str,
        original_size: int,
        original_mode: int,
    ) -> TargetObservationProcessPlan:
        return self._build(
            ObservationOperation.CERTIFICATE_REMOVE_STAGED_ORIGINAL,
            CertificateRuntimeSelector(
                container_id,
                destination,
                restore_temp_name=restore_temp_name,
                original_sha256=original_sha256,
                original_size=original_size,
                original_mode=original_mode,
            ),
        )

    def rollback_readiness_probe(
        self,
        *,
        container_id: str,
    ) -> TargetObservationProcessPlan:
        return self._build(
            ObservationOperation.ROLLBACK_READINESS_PROBE,
            container_id,
        )

    def rollback_provider_probe(
        self,
        *,
        container_id: str,
    ) -> TargetObservationProcessPlan:
        return self._build(
            ObservationOperation.ROLLBACK_PROVIDER_PROBE,
            container_id,
        )

    def __repr__(self) -> str:
        return (
            "TargetObservationExecutionBinding("
            f"runtime={self.target.runtime.product.value!r}, <redacted>)"
        )


__all__ = [
    "CERTIFICATE_OPERATION_STDERR_LIMIT_BYTES",
    "CERTIFICATE_OPERATION_STDOUT_LIMIT_BYTES",
    "CERTIFICATE_OPERATION_TIMEOUT_MS",
    "CertificateRuntimeSelector",
    "CertificateTargetDestination",
    "OBSERVATION_CA_DESTINATION",
    "OBSERVATION_COMPOSE_STDOUT_LIMIT_BYTES",
    "OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES",
    "OBSERVATION_LIST_STDOUT_LIMIT_BYTES",
    "OBSERVATION_STDERR_LIMIT_BYTES",
    "OBSERVATION_TIMEOUT_MS",
    "ObservationOperation",
    "TargetObservationBindingError",
    "TargetObservationBindingErrorCode",
    "TargetObservationExecutionBinding",
    "TargetObservationProcessPlan",
    "TargetObservationProcessRequest",
]
