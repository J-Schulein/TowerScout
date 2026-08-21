from __future__ import annotations

import hashlib
import re
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.models import PackageIdentity  # noqa: E402
from towerscout_launcher.target_contracts import (  # noqa: E402
    ABSENT_FILE_SHA256,
    EXPECTED_VOLUME_DESTINATIONS,
    AccelerationPlan,
    CertificateIdentity,
    ComposeInvocationKind,
    ComposePlan,
    ComposeProviderIdentity,
    ContainerIdentity,
    EffectiveProfile,
    EndpointBindingKind,
    EndpointIdentity,
    EndpointKind,
    FileIdentity,
    GpuMode,
    ImageIdentity,
    MapProvider,
    ResolvedRepairTarget,
    RuntimeIdentity,
    RuntimeProduct,
    VolumeIdentity,
    WindowsProcessEnvironment,
    encode_target_token,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _directory(logical_name: str, path: str, marker: int) -> FileIdentity:
    return FileIdentity(
        logical_name=logical_name,
        final_path=PureWindowsPath(path),
        volume_serial=1000 + marker,
        file_id=marker.to_bytes(16, "big"),
        is_directory=True,
    )


def _file(logical_name: str, path: str, marker: int) -> FileIdentity:
    return FileIdentity(
        logical_name=logical_name,
        final_path=PureWindowsPath(path),
        volume_serial=2000 + marker,
        file_id=marker.to_bytes(16, "big"),
        sha256=_digest(f"file-{marker}"),
        size_bytes=100 + marker,
    )


def _target() -> ResolvedRepairTarget:
    private_root = r"C:\Users\PATH-SECRET\TowerScout"
    package_root = _directory("package_root", private_root, 1)
    process_environment = WindowsProcessEnvironment(
        system_root=_directory("system_root", r"C:\Windows", 50),
        temp_directory=_directory(
            "temp_directory", r"C:\Users\PATH-SECRET\AppData\Local\Temp", 51
        ),
        user_profile=_directory("user_profile", r"C:\Users\PATH-SECRET", 52),
        local_app_data=_directory(
            "local_app_data", r"C:\Users\PATH-SECRET\AppData\Local", 53
        ),
        roaming_app_data=_directory(
            "roaming_app_data", r"C:\Users\PATH-SECRET\AppData\Roaming", 54
        ),
    )
    runtime_file = _file(
        "docker.exe",
        r"C:\Program Files\Docker\RUNTIME-PATH-SECRET\docker.exe",
        2,
    )
    runtime = RuntimeIdentity(
        product=RuntimeProduct.DOCKER,
        executable=runtime_file,
        version="28.3.2",
        publisher_policy_sha256=_digest("PUBLISHER-SECRET"),
    )
    docker_config = _file(
        "docker-context-metadata",
        r"C:\Users\PATH-SECRET\.docker\contexts\meta.json",
        3,
    )
    endpoint = EndpointIdentity(
        product=RuntimeProduct.DOCKER,
        kind=EndpointKind.DOCKER_NAMED_PIPE,
        canonical_endpoint="npipe:////./pipe/ENDPOINT-SECRET",
        private_metadata_sha256=_digest("DAEMON-SECRET" + docker_config.sha256),
        discovery_artifacts=(docker_config,),
    )
    compose_executable = _file(
        "docker-compose.exe",
        r"C:\Program Files\Docker\COMPOSE-PATH-SECRET\docker-compose.exe",
        4,
    )
    compose_provider = ComposeProviderIdentity(
        provider_id="docker-compose-v2",
        invocation_kind=ComposeInvocationKind.DOCKER_COMPOSE_EXECUTABLE,
        endpoint_binding=EndpointBindingKind.DOCKER_HOST_ARGUMENT,
        artifacts=(compose_executable,),
        integrity_sha256=_digest("docker-compose-policy-v1"),
    )
    compose_file = _file(
        "compose.yaml",
        private_root + r"\compose.yaml",
        5,
    )
    environment_secret = "PROVIDER_KEY=ENVIRONMENT-SECRET"
    environment_file = replace(
        _file(".env", private_root + r"\.env", 6),
        sha256=_digest(environment_secret),
    )
    compose = ComposePlan(
        ordered_files=(compose_file,),
        environment_sha256=_digest(environment_secret),
        planned_environment_sha256=_digest(environment_secret + "-planned"),
        pre_model_sha256=_digest("pre-model"),
        post_model_sha256=_digest("post-model"),
        environment_source=environment_file,
        environment_file=environment_file,
    )
    image = ImageIdentity(
        configured_reference="private.registry.invalid/IMAGE-SECRET@sha256:" + "a" * 64,
        pinned_digest="sha256:" + "a" * 64,
        repository_digest=("private.registry.invalid/towerscout@sha256:" + "a" * 64),
        daemon_image_id="sha256:" + "b" * 64,
        private_inspect_sha256=_digest("image-inspect"),
    )
    container = ContainerIdentity(
        container_id="CONTAINER-ID-SECRET",
        container_name="CONTAINER-NAME-SECRET",
        daemon_image_id="sha256:" + "b" * 64,
        private_inspect_sha256=_digest(
            "labels" + environment_secret + "127.0.0.1:5000" + "all-eight-mounts"
        ),
    )
    volumes = tuple(
        VolumeIdentity(
            logical_name=logical_name,
            runtime_name=f"towerscout-test_{logical_name}",
            destination=destination,
            private_inspect_sha256=_digest(
                f"{logical_name}-VOLUME-STORE-SECRET-options-labels-opaque"
            ),
        )
        for logical_name, destination in EXPECTED_VOLUME_DESTINATIONS
    )
    certificate = CertificateIdentity(
        provider=MapProvider.GOOGLE,
        windows_root_fingerprint_sha256="c" * 64,
        candidate_content_sha256="d" * 64,
    )
    return ResolvedRepairTarget(
        package_root=package_root,
        process_environment=process_environment,
        release_identity="v0.1.3-rc.test",
        runtime=runtime,
        endpoint=endpoint,
        compose_provider=compose_provider,
        compose=compose,
        compose_project="towerscout-test",
        service="towerscout",
        acceleration=AccelerationPlan(GpuMode.OFF, EffectiveProfile.CPU),
        provider=MapProvider.GOOGLE,
        port=5000,
        image=image,
        container=container,
        volumes=volumes,
        certificate=certificate,
    )


def test_target_token_encoding_is_versioned_bounded_and_boundary_safe() -> None:
    left = encode_target_token(("ab", "c"))
    right = encode_target_token(("a", "bc"))

    assert left != right
    assert left.digest_sha256 != right.digest_sha256
    assert re.fullmatch(r"TSRT1-[0-9a-f]{32}", left.display)
    assert len(left.display.removeprefix("TSRT1-")) * 4 >= 128
    assert left.digest_sha256 not in repr(left)


def test_each_hidden_target_identity_change_changes_the_full_token() -> None:
    target = _target()
    first_volume = target.volumes[0]
    mutations = (
        replace(
            target,
            endpoint=replace(
                target.endpoint,
                canonical_endpoint="npipe:////./pipe/changed-endpoint",
            ),
        ),
        replace(
            target,
            runtime=replace(
                target.runtime,
                executable=replace(
                    target.runtime.executable,
                    sha256=_digest("changed-runtime"),
                ),
            ),
        ),
        replace(
            target,
            process_environment=replace(
                target.process_environment,
                temp_directory=replace(
                    target.process_environment.temp_directory,
                    final_path=PureWindowsPath(r"C:\Users\OTHER\AppData\Local\Temp"),
                ),
            ),
        ),
        replace(
            target,
            endpoint=replace(
                target.endpoint,
                discovery_artifacts=(
                    replace(
                        target.endpoint.discovery_artifacts[0],
                        final_path=PureWindowsPath(
                            r"C:\Users\OTHER\.docker\contexts\meta.json"
                        ),
                    ),
                ),
            ),
        ),
        replace(
            target,
            compose=replace(
                target.compose,
                environment_file=replace(
                    target.compose.environment_file,
                    sha256=_digest("changed-environment"),
                ),
                environment_source=replace(
                    target.compose.environment_source,
                    sha256=_digest("changed-environment"),
                ),
                environment_sha256=_digest("changed-environment"),
            ),
        ),
        replace(
            target,
            compose=replace(
                target.compose,
                post_model_sha256=_digest("changed-post-model"),
            ),
        ),
        replace(
            target,
            volumes=(
                replace(
                    first_volume,
                    private_inspect_sha256=_digest("changed-volume"),
                ),
                *target.volumes[1:],
            ),
        ),
        replace(
            target,
            certificate=replace(
                target.certificate,
                candidate_content_sha256=_digest("changed-candidate"),
            ),
        ),
    )

    assert len({item.target_token.digest_sha256 for item in mutations}) == len(
        mutations
    )
    assert all(item.target_token != target.target_token for item in mutations)


def test_internal_target_and_nested_plans_are_immutable_and_slot_based() -> None:
    target = _target()

    with pytest.raises(FrozenInstanceError):
        target.port = 5001  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        target.endpoint.rootless = True  # type: ignore[misc]

    assert not hasattr(target, "__dict__")
    assert not hasattr(target.endpoint, "__dict__")
    assert isinstance(target.volumes, tuple)


def test_target_repr_and_public_summary_never_expose_private_identity() -> None:
    target = _target()
    summary = target.to_public_summary()
    public_output = "\n".join((repr(target), repr(summary), str(summary)))

    private_values = (
        "PATH-SECRET",
        "RUNTIME-PATH-SECRET",
        "COMPOSE-PATH-SECRET",
        "ENDPOINT-SECRET",
        "DAEMON-SECRET",
        "PUBLISHER-SECRET",
        "ENVIRONMENT-SECRET",
        "IMAGE-SECRET",
        "CONTAINER-ID-SECRET",
        "CONTAINER-NAME-SECRET",
        "VOLUME-STORE-SECRET",
        target.runtime.publisher_policy_sha256,
        target.endpoint.private_metadata_sha256,
        target.compose.environment_sha256,
        target.certificate.windows_root_fingerprint_sha256,
        target.certificate.candidate_content_sha256,
        target.endpoint.canonical_endpoint,
        str(target.package_root.final_path),
        target.image.configured_reference,
    )
    for private_value in private_values:
        assert private_value not in public_output

    assert target.target_token.display in public_output
    assert "local Windows named pipe" in public_output
    assert "towerscout-test/towerscout" in public_output
    assert "Google Maps" in public_output
    assert "/app/webapp/config/certs/local-ca.pem" in public_output
    assert "/app/webapp/config/certs/towerscout-ca-bundle.pem" in public_output


@pytest.mark.parametrize(
    ("field_name", "unsafe_value"),
    (
        ("target_token", "TSRT1-short"),
        ("runtime_version", "28.3.2\nC:\\private"),
        ("compose_project", "../../private"),
        ("service", "other-service"),
        ("config_volume_label", "unsafe volume label"),
        ("container_token", "not-hex"),
    ),
)
def test_public_summary_rejects_unbounded_or_unsafe_fields(
    field_name: str, unsafe_value: object
) -> None:
    summary = _target().to_public_summary()

    with pytest.raises(ValueError):
        replace(summary, **{field_name: unsafe_value})


def test_public_summary_rejects_endpoint_for_another_runtime() -> None:
    summary = _target().to_public_summary()

    with pytest.raises(ValueError, match="endpoint kind"):
        replace(summary, endpoint_kind=EndpointKind.PODMAN_ROOTLESS_WSL)


def test_public_summary_rejects_gpu_profile_for_another_runtime() -> None:
    summary = _target().to_public_summary()

    with pytest.raises(ValueError, match="acceleration profile"):
        replace(summary, effective_profile=EffectiveProfile.PODMAN_GPU)


def test_target_rejects_compose_binding_for_another_runtime() -> None:
    target = _target()
    podman_binding = replace(
        target.compose_provider,
        endpoint_binding=EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT,
    )

    with pytest.raises(ValueError, match="Compose execution"):
        replace(target, compose_provider=podman_binding)


def test_target_rejects_gpu_profile_for_another_runtime_or_unbound_overlay() -> None:
    target = _target()

    with pytest.raises(ValueError, match="acceleration profile"):
        replace(
            target,
            acceleration=AccelerationPlan(
                GpuMode.ON,
                EffectiveProfile.PODMAN_GPU,
                "compose.gpu.podman.yaml",
            ),
        )

    with pytest.raises(ValueError, match="Compose inputs"):
        replace(
            target,
            acceleration=AccelerationPlan(
                GpuMode.ON,
                EffectiveProfile.DOCKER_GPU,
                "compose.gpu.yaml",
            ),
        )


def test_target_rejects_wrong_or_extra_compose_overlay_files() -> None:
    target = _target()
    base = target.compose.ordered_files[0]
    podman_overlay = _file(
        "compose.gpu.podman.yaml",
        r"C:\Users\PATH-SECRET\TowerScout\compose.gpu.podman.yaml",
        12,
    )
    compose_with_podman_overlay = replace(
        target.compose,
        ordered_files=(base, podman_overlay),
    )

    with pytest.raises(ValueError, match="Compose inputs"):
        replace(
            target,
            compose=compose_with_podman_overlay,
            acceleration=AccelerationPlan(
                GpuMode.ON,
                EffectiveProfile.DOCKER_GPU,
                "compose.gpu.podman.yaml",
            ),
        )
    with pytest.raises(ValueError, match="Compose inputs"):
        replace(target, compose=compose_with_podman_overlay)


def test_target_rejects_unpinned_or_inconsistent_image_digests() -> None:
    target = _target()

    with pytest.raises(ValueError, match="not pinned"):
        replace(
            target.image,
            configured_reference="private.registry.invalid/towerscout:latest",
        )
    with pytest.raises(ValueError, match="does not match"):
        replace(
            target.image,
            repository_digest="private.registry.invalid/towerscout@sha256:" + "e" * 64,
        )
    with pytest.raises(ValueError, match="Container and inspected image"):
        replace(
            target,
            container=replace(target.container, daemon_image_id="sha256:" + "e" * 64),
        )


def test_target_rejects_compose_inputs_or_environment_source_outside_package() -> None:
    target = _target()

    with pytest.raises(ValueError, match="Compose inputs are outside"):
        replace(
            target,
            compose=replace(
                target.compose,
                ordered_files=(
                    replace(
                        target.compose.ordered_files[0],
                        final_path=PureWindowsPath(r"C:\Attacker\compose.yaml"),
                    ),
                ),
            ),
        )
    with pytest.raises(ValueError, match="environment source is outside"):
        replace(
            target,
            compose=replace(
                target.compose,
                environment_file=None,
                environment_sha256=ABSENT_FILE_SHA256,
                environment_source=_file(
                    ".env.example", r"C:\Attacker\.env.example", 43
                ),
            ),
        )


def test_target_rejects_duplicate_runtime_volume_names() -> None:
    target = _target()
    duplicate = replace(
        target.volumes[1],
        runtime_name=target.volumes[0].runtime_name,
    )

    with pytest.raises(ValueError, match="must be distinct"):
        replace(target, volumes=(target.volumes[0], duplicate, *target.volumes[2:]))


def test_security_bearing_collections_reject_tuple_subclasses() -> None:
    class HostileTuple(tuple):
        pass

    target = _target()

    with pytest.raises(ValueError, match="Endpoint artifacts are invalid"):
        replace(
            target.endpoint,
            discovery_artifacts=HostileTuple(target.endpoint.discovery_artifacts),
        )
    with pytest.raises(ValueError, match="Compose provider artifacts are invalid"):
        replace(
            target.compose_provider,
            artifacts=HostileTuple(target.compose_provider.artifacts),
        )
    with pytest.raises(ValueError, match="Compose input identities are invalid"):
        replace(
            target.compose,
            ordered_files=HostileTuple(target.compose.ordered_files),
        )
    with pytest.raises(ValueError, match="Runtime volume identities are invalid"):
        replace(target, volumes=HostileTuple(target.volumes))


@pytest.mark.parametrize(
    "final_path",
    (
        PureWindowsPath("relative/path.exe"),
        PureWindowsPath(r"C:relative\path.exe"),
        PureWindowsPath(r"\root-relative\path.exe"),
        PurePosixPath("/host/absolute/path.exe"),
    ),
)
def test_file_identity_rejects_non_absolute_or_non_windows_paths(
    final_path: PureWindowsPath | PurePosixPath,
) -> None:
    with pytest.raises(ValueError, match="absolute"):
        FileIdentity(
            logical_name="runtime.exe",
            final_path=final_path,  # type: ignore[arg-type]
            volume_serial=2099,
            file_id=(99).to_bytes(16, "big"),
            sha256=_digest("file-99"),
            size_bytes=199,
        )


def test_file_identity_rejects_wrong_path_type_before_rendering_it() -> None:
    class HostilePath:
        def __str__(self) -> str:
            raise AssertionError("wrong-type path must not be rendered")

    with pytest.raises(ValueError, match="absolute"):
        FileIdentity(
            logical_name="runtime.exe",
            final_path=HostilePath(),  # type: ignore[arg-type]
            volume_serial=2099,
            file_id=(99).to_bytes(16, "big"),
            sha256=_digest("file-99"),
            size_bytes=199,
        )


@pytest.mark.parametrize(
    "path",
    (
        r"C:\Program Files\Docker\bin\docker.exe",
        r"\\?\C:\Program Files\Docker\bin\docker.exe",
    ),
)
def test_file_identity_uses_windows_path_semantics_on_every_host(path: str) -> None:
    identity = _file("docker.exe", path, 98)

    assert type(identity.final_path) is PureWindowsPath
    assert identity.final_path.is_absolute()
    assert identity.final_path.name.casefold() == "docker.exe"
    assert identity.final_path.parent.name.casefold() == "bin"
    assert identity.final_path.parent / identity.final_path.name == identity.final_path


def test_endpoint_identity_rejects_remote_or_root_podman_targets() -> None:
    target = _target()
    identity_key = _file(
        "podman_identity_key",
        r"C:\Users\PATH-SECRET\.local\share\containers\podman\machine\key",
        40,
    )

    with pytest.raises(ValueError, match="local named pipe"):
        replace(target.endpoint, canonical_endpoint="tcp://remote.invalid:2375")

    for endpoint in (
        "ssh://user@remote.invalid:51313/run/user/1000/podman/podman.sock",
        "ssh://root@127.0.0.1:51313/run/podman/podman.sock",
    ):
        with pytest.raises(ValueError, match="local rootless SSH socket"):
            EndpointIdentity(
                product=RuntimeProduct.PODMAN,
                kind=EndpointKind.PODMAN_ROOTLESS_WSL,
                canonical_endpoint=endpoint,
                private_metadata_sha256=_digest("podman-endpoint"),
                identity_key=identity_key,
                rootless=True,
            )


def test_endpoint_identity_accepts_bound_rootless_loopback_podman_socket() -> None:
    identity_key = _file(
        "podman_identity_key",
        r"C:\Users\PATH-SECRET\.local\share\containers\podman\machine\key",
        41,
    )
    endpoint = EndpointIdentity(
        product=RuntimeProduct.PODMAN,
        kind=EndpointKind.PODMAN_ROOTLESS_WSL,
        canonical_endpoint=(
            "ssh://user@127.0.0.1:51313/run/user/1000/podman/podman.sock"
        ),
        private_metadata_sha256=_digest("podman-endpoint-and-key"),
        identity_key=identity_key,
        rootless=True,
    )

    assert repr(endpoint) == "EndpointIdentity(<redacted>)"

    with pytest.raises(ValueError, match="identity material"):
        replace(
            endpoint,
            identity_key=replace(identity_key, logical_name="connection_metadata"),
        )


def test_invalid_podman_endpoint_does_not_retain_private_parse_cause() -> None:
    identity_key = _file(
        "podman_identity_key",
        r"C:\Users\PATH-SECRET\.local\share\containers\podman\machine\key",
        44,
    )

    with pytest.raises(ValueError) as failure:
        EndpointIdentity(
            product=RuntimeProduct.PODMAN,
            kind=EndpointKind.PODMAN_ROOTLESS_WSL,
            canonical_endpoint=(
                "ssh://user@127.0.0.1:PORT-SECRET/run/user/1000/podman/podman.sock"
            ),
            private_metadata_sha256=_digest("podman-endpoint"),
            identity_key=identity_key,
            rootless=True,
        )

    assert failure.value.__cause__ is None
    assert "PORT-SECRET" not in repr(failure.value)


def test_absent_environment_file_is_bound_into_the_target_token() -> None:
    target = _target()
    absent = replace(
        target,
        compose=replace(
            target.compose,
            environment_file=None,
            environment_sha256=ABSENT_FILE_SHA256,
            environment_source=_file(
                ".env.example",
                str(target.package_root.final_path / ".env.example"),
                42,
            ),
        ),
    )

    assert absent.target_token != target.target_token


def test_role_specific_file_identities_reject_directories() -> None:
    target = _target()
    directory = target.package_root

    with pytest.raises(ValueError, match="executable identity"):
        replace(target.runtime, executable=directory)
    with pytest.raises(ValueError, match="artifacts must be files"):
        replace(target.compose_provider, artifacts=(directory,))
    with pytest.raises(ValueError, match="content-bearing files"):
        replace(
            target.compose,
            ordered_files=(replace(directory, logical_name="compose.yaml"),),
        )


def test_existing_package_identity_api_remains_compatible() -> None:
    package = PackageIdentity(
        root=Path("."),
        release_version="template",
        track="unknown",
        image="unknown",
        image_digest="",
        pytorch_flavor="cpu",
        engine_hint="docker",
        gpu_mode="off",
        port=5000,
        compose_project="towerscout",
        is_release_package=False,
    )

    assert package.__dict__["engine_hint"] == "docker"
    assert package.package_label == "TowerScout source prototype (cpu)"
