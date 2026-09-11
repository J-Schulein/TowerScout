"""Retained native Docker target inputs for the production plan source owner.

This module composes the already authenticated Docker runtime/endpoint pair
with the separately authenticated Docker Compose executable.  It remains
source-only: no launcher confirmation, repair, or mutation path imports it.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import NoReturn

from .runtime_command_version import (
    BoundCommandRuntimeEvidence,
    RuntimeCommandVerificationError,
    open_package_bound_command_runtime_evidence,
)
from .runtime_docker_endpoint import (
    BoundDockerRuntimeEndpointInputs,
    DockerEndpointError,
    capture_native_windows_docker_runtime_endpoint_inputs,
)
from .runtime_policy import RuntimeProductId
from .target_contracts import (
    ComposeInvocationKind,
    ComposeProviderIdentity,
    EndpointBindingKind,
    EndpointIdentity,
    FileIdentity,
    RuntimeIdentity,
    RuntimeProduct,
)


class DockerInputErrorCode(str, Enum):
    COMPOSE_INVALID = "compose_invalid"
    INPUTS_CHANGED = "inputs_changed"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"


class DockerInputError(RuntimeError):
    _MESSAGES = {
        DockerInputErrorCode.COMPOSE_INVALID: (
            "The authenticated Docker Compose provider is invalid."
        ),
        DockerInputErrorCode.INPUTS_CHANGED: (
            "The authenticated Docker target inputs changed during verification."
        ),
        DockerInputErrorCode.VERIFICATION_UNAVAILABLE: (
            "Docker target input verification is unavailable."
        ),
    }

    def __init__(self, code: DockerInputErrorCode) -> None:
        if type(code) is not DockerInputErrorCode:
            raise ValueError("Unknown Docker target input error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"DockerInputError(code={self.code.value!r})"


def _fail(code: DockerInputErrorCode) -> NoReturn:
    raise DockerInputError(code)


@dataclass(frozen=True, slots=True, repr=False)
class DockerTargetSourceInputs:
    """Exact Docker fields emitted by the retained native source owners."""

    runtime: RuntimeIdentity = field(repr=False)
    endpoint: EndpointIdentity = field(repr=False)
    compose_provider: ComposeProviderIdentity = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.runtime) is not RuntimeIdentity
            or self.runtime.product is not RuntimeProduct.DOCKER
            or type(self.endpoint) is not EndpointIdentity
            or self.endpoint.product is not RuntimeProduct.DOCKER
            or type(self.compose_provider) is not ComposeProviderIdentity
            or self.compose_provider.invocation_kind
            is not ComposeInvocationKind.DOCKER_COMPOSE_EXECUTABLE
            or self.compose_provider.endpoint_binding
            is not EndpointBindingKind.DOCKER_HOST_ARGUMENT
        ):
            raise ValueError("Docker target source inputs are invalid.")

    def __repr__(self) -> str:
        return "DockerTargetSourceInputs(<redacted>)"


def _compose_identity(
    compose: BoundCommandRuntimeEvidence,
) -> ComposeProviderIdentity:
    try:
        snapshot = compose._capture_file_snapshot()  # noqa: SLF001
        evidence = compose.evidence
        path = PureWindowsPath(snapshot.final_path)
        if (
            evidence.product_id is not RuntimeProductId.DOCKER_COMPOSE
            or not path.is_absolute()
            or path.name.casefold() != "docker-compose.exe"
        ):
            _fail(DockerInputErrorCode.COMPOSE_INVALID)
        artifact = FileIdentity(
            logical_name="docker-compose.exe",
            final_path=path,
            volume_serial=snapshot.identity.volume_serial,
            file_id=snapshot.identity.file_id,
            sha256=snapshot.sha256,
            size_bytes=snapshot.size,
        )
        return ComposeProviderIdentity(
            provider_id=RuntimeProductId.DOCKER_COMPOSE.value,
            invocation_kind=ComposeInvocationKind.DOCKER_COMPOSE_EXECUTABLE,
            endpoint_binding=EndpointBindingKind.DOCKER_HOST_ARGUMENT,
            artifacts=(artifact,),
            integrity_sha256=evidence.evidence_sha256,
        )
    except DockerInputError:
        raise
    except RuntimeCommandVerificationError:
        raise DockerInputError(DockerInputErrorCode.COMPOSE_INVALID) from None
    except (TypeError, ValueError, UnicodeError):
        _fail(DockerInputErrorCode.COMPOSE_INVALID)


class BoundDockerTargetSourceInputs:
    """Retain and coherently revalidate all native Docker source inputs."""

    __slots__ = (
        "_active_owner",
        "_compose",
        "_lifetime_lock",
        "_runtime_endpoint",
    )

    def __init__(
        self,
        *,
        runtime_endpoint: BoundDockerRuntimeEndpointInputs,
        compose: BoundCommandRuntimeEvidence,
    ) -> None:
        if (
            type(runtime_endpoint) is not BoundDockerRuntimeEndpointInputs
            or runtime_endpoint.closed
            or type(compose) is not BoundCommandRuntimeEvidence
            or compose.closed
            or compose.evidence.product_id is not RuntimeProductId.DOCKER_COMPOSE
        ):
            raise ValueError("Bound Docker target source inputs are invalid.")
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None
        self._runtime_endpoint: BoundDockerRuntimeEndpointInputs | None = (
            runtime_endpoint
        )
        self._compose: BoundCommandRuntimeEvidence | None = compose

    @property
    def supported(self) -> bool:
        with self._lifetime_lock:
            runtime_endpoint = self._runtime_endpoint
            compose = self._compose
            return bool(
                runtime_endpoint is not None
                and runtime_endpoint.supported
                and compose is not None
                and not compose.closed
            )

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            runtime_endpoint = self._runtime_endpoint
            compose = self._compose
            return bool(
                (runtime_endpoint is None or runtime_endpoint.closed)
                and (compose is None or compose.closed)
            )

    def capture(self) -> DockerTargetSourceInputs:
        self._lifetime_lock.acquire()
        if self._active_owner is not None:
            self._lifetime_lock.release()
            _fail(DockerInputErrorCode.INPUTS_CHANGED)
        runtime_endpoint = self._runtime_endpoint
        compose = self._compose
        if (
            runtime_endpoint is None
            or runtime_endpoint.closed
            or compose is None
            or compose.closed
        ):
            self._lifetime_lock.release()
            _fail(DockerInputErrorCode.INPUTS_CHANGED)
        self._active_owner = threading.get_ident()
        try:
            first_runtime_endpoint = runtime_endpoint.capture()
            first_compose = _compose_identity(compose)
            second_runtime_endpoint = runtime_endpoint.capture()
            second_compose = _compose_identity(compose)
            if (
                first_runtime_endpoint != second_runtime_endpoint
                or first_compose != second_compose
                or second_runtime_endpoint.runtime.publisher_policy_sha256
                != compose.evidence.policy_sha256
                or second_runtime_endpoint.runtime.executable.final_path.parent
                != second_compose.artifacts[0].final_path.parent
            ):
                _fail(DockerInputErrorCode.INPUTS_CHANGED)
            return DockerTargetSourceInputs(
                runtime=second_runtime_endpoint.runtime,
                endpoint=second_runtime_endpoint.endpoint,
                compose_provider=second_compose,
            )
        except DockerInputError:
            raise
        except (DockerEndpointError, RuntimeCommandVerificationError):
            raise DockerInputError(DockerInputErrorCode.INPUTS_CHANGED) from None
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            _fail(DockerInputErrorCode.VERIFICATION_UNAVAILABLE)
        finally:
            self._active_owner = None
            self._lifetime_lock.release()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(DockerInputErrorCode.INPUTS_CHANGED)
            runtime_endpoint = self._runtime_endpoint
            compose = self._compose
            failed = False
            interruption: BaseException | None = None
            if compose is not None:
                try:
                    compose.close()
                except BaseException as error:
                    if isinstance(error, Exception):
                        failed = True
                    else:
                        interruption = error
                if compose.closed:
                    self._compose = None
                else:
                    failed = True
            if runtime_endpoint is not None:
                try:
                    runtime_endpoint.close()
                except BaseException as error:
                    if isinstance(error, Exception):
                        failed = True
                    elif interruption is None:
                        interruption = error
                if runtime_endpoint.closed:
                    self._runtime_endpoint = None
                else:
                    failed = True
            if interruption is not None:
                raise interruption
            if failed:
                _fail(DockerInputErrorCode.INPUTS_CHANGED)

    def __enter__(self) -> "BoundDockerTargetSourceInputs":
        if self.closed:
            _fail(DockerInputErrorCode.INPUTS_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"BoundDockerTargetSourceInputs(state={state!r}, <redacted>)"


def capture_native_windows_docker_target_source_inputs() -> (
    BoundDockerTargetSourceInputs
):
    """Capture the fixed native Docker runtime, endpoint, and Compose owner."""

    runtime_endpoint: BoundDockerRuntimeEndpointInputs | None = None
    compose: BoundCommandRuntimeEvidence | None = None
    transferred = False
    try:
        runtime_endpoint = capture_native_windows_docker_runtime_endpoint_inputs()
        compose = open_package_bound_command_runtime_evidence(
            RuntimeProductId.DOCKER_COMPOSE
        )
        owner = BoundDockerTargetSourceInputs(
            runtime_endpoint=runtime_endpoint,
            compose=compose,
        )
        owner.capture()
        transferred = True
        return owner
    except DockerInputError:
        raise
    except DockerEndpointError:
        raise DockerInputError(DockerInputErrorCode.INPUTS_CHANGED) from None
    except RuntimeCommandVerificationError:
        raise DockerInputError(DockerInputErrorCode.COMPOSE_INVALID) from None
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        _fail(DockerInputErrorCode.VERIFICATION_UNAVAILABLE)
    finally:
        if not transferred:
            if compose is not None:
                try:
                    compose.close()
                except BaseException:
                    pass
            if runtime_endpoint is not None:
                try:
                    runtime_endpoint.close()
                except BaseException:
                    pass


__all__ = [
    "BoundDockerTargetSourceInputs",
    "DockerInputError",
    "DockerInputErrorCode",
    "DockerTargetSourceInputs",
    "capture_native_windows_docker_target_source_inputs",
]
