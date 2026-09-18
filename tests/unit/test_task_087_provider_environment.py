"""Task-087 provider environment replacement security coverage."""

import base64
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = REPO_ROOT / "launcher"
PROVIDER_ENVIRONMENT_LIB = (
    REPO_ROOT / "scripts" / "lib" / "TowerScoutProviderEnvironment.ps1"
)
PROVIDER_LIB = REPO_ROOT / "scripts" / "lib" / "TowerScoutPodmanComposeProvider.ps1"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.windows_path_trust import (  # noqa: E402
    NativeWindowsPathTrustApi,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    StableFileIdentity,
    derive_environment_mutex_name,
)


def _powershell_executable():
    return shutil.which("powershell.exe") or shutil.which("pwsh")


def _run_powershell(command: str):
    powershell = _powershell_executable()
    if powershell is None:
        pytest.skip("PowerShell executable not found")
    return subprocess.run(
        [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_podman_compose_provider(path: Path, version: str = "1.5.0"):
    path.write_text(
        "@echo off\r\n"
        'if not "%PYTHONDONTWRITEBYTECODE%"=="1" exit /b 9\r\n'
        'if "%1"=="version" (\r\n'
        f"  echo podman-compose version {version}\r\n"
        "  exit /b 0\r\n"
        ")\r\n"
        "echo podman-compose %*\r\n"
        "exit /b 0\r\n",
        encoding="utf-8",
    )


def test_provider_environment_source_uses_protected_native_contract_without_backup():
    environment = PROVIDER_ENVIRONMENT_LIB.read_text(encoding="utf-8")
    provider = PROVIDER_LIB.read_text(encoding="utf-8")
    combined = environment + provider

    assert "SHGetKnownFolderPath" in environment
    assert "Environment]::GetFolderPath" not in environment
    assert "ReplaceFileW" in environment
    assert "MoveFileExW" in environment
    assert "OpenDirectoryLease" in environment
    assert "IdentityFromHandle" in environment
    assert "Global\\TowerScoutEnv-v1-" in environment
    assert "DataProtectionScope]::CurrentUser" in environment
    assert ".env.backup." not in combined
    assert "BackupPath" not in combined
    assert "PODMAN_COMPOSE_PROVIDER=$resolvedPath" not in provider


@pytest.mark.skipif(os.name != "nt", reason="Windows mutex identity is Windows-only")
def test_provider_environment_uses_launcher_package_mutex_identity(tmp_path: Path):
    api = NativeWindowsPathTrustApi()
    handle = api.open_directory(str(tmp_path), follow_reparse=False)
    try:
        facts = api.query_directory(handle)
        expected = derive_environment_mutex_name(
            StableFileIdentity(facts.volume_serial, facts.file_id)
        )
    finally:
        api.close_handle(handle)

    command = f"""
    $ErrorActionPreference = "Stop"
    . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"
    $binding = Get-TowerScoutProviderEnvironmentBinding -RootPath "{tmp_path}"
    Write-Output $binding.MutexName
    """
    result = _run_powershell(command)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == expected


@pytest.mark.skipif(
    os.name != "nt", reason="PowerShell launcher helpers are Windows-only"
)
def test_podman_compose_provider_env_apply_is_atomic_without_plaintext_backup():
    temp_root = (
        REPO_ROOT
        / ".agent_work"
        / "pytest-temp"
        / f"task084-provider-apply-{uuid.uuid4().hex}"
    )
    temp_root.mkdir(parents=True)
    provider = temp_root / "podman-compose.cmd"
    _write_podman_compose_provider(provider)
    env_file = temp_root / ".env"
    env_file.write_text(
        "TOWERSCOUT_PORT=5005\n"
        "PODMAN_COMPOSE_PROVIDER=old-provider\n"
        "TOWERSCOUT_GPU_MODE=off\n",
        encoding="utf-8",
    )

    try:
        command = f"""
        $ErrorActionPreference = "Stop"
        . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"

        $preview = Set-TowerScoutPodmanComposeProviderEnv -ProviderPath "{provider}" -RootPath "{temp_root}"
        if ($preview.Applied) {{
            throw "Preview mode should not apply .env changes."
        }}
        $before = Get-Content -LiteralPath "{env_file}" -Raw
        if ($before -notmatch "PODMAN_COMPOSE_PROVIDER=old-provider") {{
            throw "Preview mode changed .env."
        }}

        $applied = Set-TowerScoutPodmanComposeProviderEnv -ProviderPath "{provider}" -RootPath "{temp_root}" -Apply
        if (-not $applied.Applied) {{
            throw "Apply mode did not report a verified update."
        }}
        $after = Get-Content -LiteralPath "{env_file}" -Raw
        if ($after -notmatch [regex]::Escape("PODMAN_COMPOSE_PROVIDER={provider}")) {{
            throw "Apply mode did not set the provider path."
        }}
        if ($after -notmatch "TOWERSCOUT_PORT=5005" -or $after -notmatch "TOWERSCOUT_GPU_MODE=off") {{
            throw "Apply mode changed unrelated settings."
        }}
        if (Get-ChildItem -LiteralPath "{temp_root}" -Filter ".env.backup.*") {{
            throw "Apply mode retained a plaintext whole-file backup."
        }}
        if (Get-ChildItem -LiteralPath "{temp_root}" -Filter ".towerscout-provider-env-*.tmp") {{
            throw "Apply mode retained a package-root temporary file."
        }}
        $binding = Get-TowerScoutProviderEnvironmentBinding -RootPath "{temp_root}"
        $recoveryRoot = Initialize-TowerScoutProviderRecoveryRoot
        if (@(Get-TowerScoutProviderJournalChain -RootPath $recoveryRoot -Digest $binding.Digest).Count -ne 0) {{
            throw "Apply mode retained a provider mini-journal."
        }}
        "ok"
        """
        result = _run_powershell(command)

        assert result.returncode == 0, result.stdout + result.stderr
        assert "ok" in result.stdout
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


@pytest.mark.skipif(
    os.name != "nt", reason="PowerShell launcher helpers are Windows-only"
)
def test_podman_compose_provider_env_plan_preserves_utf8_bom_crlf_and_unrelated_bytes():
    temp_root = (
        REPO_ROOT
        / ".agent_work"
        / "pytest-temp"
        / f"task087-provider-plan-{uuid.uuid4().hex}"
    )
    temp_root.mkdir(parents=True)
    provider = temp_root / "podman-compose.cmd"
    _write_podman_compose_provider(provider)
    source = (
        b"\xef\xbb\xbfSECRET=\xc3\xb6paque\r\n"
        b"  PODMAN_COMPOSE_PROVIDER=old-provider\r\n"
        b"TAIL=last"
    )
    expected = (
        b"\xef\xbb\xbfSECRET=\xc3\xb6paque\r\n"
        + f"  PODMAN_COMPOSE_PROVIDER={provider}\r\n".encode()
        + b"TAIL=last"
    )
    source_b64 = base64.b64encode(source).decode("ascii")
    expected_b64 = base64.b64encode(expected).decode("ascii")

    try:
        command = f"""
        $ErrorActionPreference = "Stop"
        . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"
        $source = [Convert]::FromBase64String("{source_b64}")
        $plan = ConvertTo-TowerScoutProviderEnvironmentPlan `
            -SourceContents $source `
            -ProviderPath "{provider}" `
            -OriginalPresent $true
        if ([Convert]::ToBase64String($plan.CandidateContents) -ne "{expected_b64}") {{
            throw "The candidate did not preserve exact unrelated bytes."
        }}
        if ([Convert]::ToBase64String($plan.OriginalContents) -ne "{source_b64}") {{
            throw "The plan did not retain the exact in-memory original."
        }}
        if ($plan.OriginalSha256 -eq $plan.CandidateSha256) {{
            throw "The original and candidate hashes unexpectedly matched."
        }}
        "ok"
        """
        result = _run_powershell(command)

        assert result.returncode == 0, result.stdout + result.stderr
        assert "ok" in result.stdout
        assert "SECRET" not in result.stdout
        assert str(provider) not in result.stdout
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


@pytest.mark.skipif(
    os.name != "nt", reason="PowerShell launcher helpers are Windows-only"
)
def test_podman_compose_provider_env_apply_creates_absent_file_from_exact_template():
    temp_root = (
        REPO_ROOT
        / ".agent_work"
        / "pytest-temp"
        / f"task087-provider-absent-{uuid.uuid4().hex}"
    )
    temp_root.mkdir(parents=True)
    provider = temp_root / "podman-compose.cmd"
    _write_podman_compose_provider(provider)
    template = b"\xef\xbb\xbfSECRET=\xc3\xb6paque\r\nTAIL=last\r\n"
    expected = template + f"PODMAN_COMPOSE_PROVIDER={provider}\r\n".encode()
    template_path = temp_root / ".env.example"
    template_path.write_bytes(template)

    try:
        command = f"""
        $ErrorActionPreference = "Stop"
        . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"
        $preview = Set-TowerScoutPodmanComposeProviderEnv -ProviderPath "{provider}" -RootPath "{temp_root}"
        if ($preview.Applied -or (Test-Path -LiteralPath "{temp_root}\\.env")) {{
            throw "Preview mode created an absent environment file."
        }}
        $applied = Set-TowerScoutPodmanComposeProviderEnv -ProviderPath "{provider}" -RootPath "{temp_root}" -Apply
        if (-not $applied.Applied) {{ throw "Apply mode did not report success." }}
        [void] (Assert-TowerScoutProviderRestrictedPath -Path "{temp_root}\\.env")
        $binding = Get-TowerScoutProviderEnvironmentBinding -RootPath "{temp_root}"
        $recoveryRoot = Initialize-TowerScoutProviderRecoveryRoot
        if (@(Get-TowerScoutProviderJournalChain -RootPath $recoveryRoot -Digest $binding.Digest).Count -ne 0) {{
            throw "Absent-file apply retained a provider mini-journal."
        }}
        if (Get-ChildItem -LiteralPath "{temp_root}" -Filter ".towerscout-provider-env-*.tmp") {{
            throw "Absent-file apply retained a temporary file."
        }}
        "ok"
        """
        result = _run_powershell(command)

        assert result.returncode == 0, result.stdout + result.stderr
        assert "ok" in result.stdout
        assert (temp_root / ".env").read_bytes() == expected
        assert template_path.read_bytes() == template
        assert not list(temp_root.glob(".env.backup.*"))
        assert str(provider) not in result.stdout
        assert "SECRET" not in result.stdout
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


@pytest.mark.skipif(
    os.name != "nt", reason="PowerShell launcher helpers are Windows-only"
)
@pytest.mark.parametrize(
    "post_exit_state", ("original", "candidate", "candidate_attributes", "third")
)
def test_podman_compose_provider_env_fresh_process_reconciles_verified_journal(
    post_exit_state: str,
):
    temp_root = (
        REPO_ROOT
        / ".agent_work"
        / "pytest-temp"
        / f"task087-provider-restart-{uuid.uuid4().hex}"
    )
    temp_root.mkdir(parents=True)
    provider = temp_root / "podman-compose.cmd"
    _write_podman_compose_provider(provider)
    env_file = temp_root / ".env"
    env_file.write_bytes(b"SECRET=opaque\r\nPODMAN_COMPOSE_PROVIDER=old\r\n")
    post_stage_action = {
        "original": "",
        "candidate": "[TowerScout.ProviderEnvironmentNative]::ReplaceWithoutBackup($tempPath, $envPath)",
        "candidate_attributes": (
            "[TowerScout.ProviderEnvironmentNative]::ReplaceWithoutBackup($tempPath, $envPath); "
            "$attributes = [System.IO.File]::GetAttributes($envPath); "
            "[System.IO.File]::SetAttributes($envPath, $attributes -bor "
            "[System.IO.FileAttributes]::Hidden)"
        ),
        "third": (
            "[System.IO.File]::WriteAllBytes($envPath, "
            '[System.Text.Encoding]::UTF8.GetBytes("UNRELATED=third`r`n"))'
        ),
    }[post_exit_state]

    seed = f"""
    $ErrorActionPreference = "Stop"
    . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"
    $binding = Get-TowerScoutProviderEnvironmentBinding -RootPath "{temp_root}"
    $mutex = Enter-TowerScoutProviderEnvironmentMutex -Name $binding.MutexName
    try {{
        $recoveryRoot = Initialize-TowerScoutProviderRecoveryRoot
        $envPath = Join-Path $binding.RootPath ".env"
        $original = Get-TowerScoutProviderEnvironmentObservation -Path $envPath
        $plan = ConvertTo-TowerScoutProviderEnvironmentPlan `
            -SourceContents $original.Contents `
            -ProviderPath "{provider}" `
            -OriginalPresent $true
        $tempName = ".towerscout-provider-env-$([guid]::NewGuid().ToString('N')).tmp"
        [void] (Add-TowerScoutProviderJournalGeneration `
            -RootPath $recoveryRoot `
            -Digest $binding.Digest `
            -State "planned" `
            -Values @{{
            root_identity = $binding.RootIdentity
            original_present = $true
            original_sha256 = $original.Sha256
            original_identity = $original.Identity
            original_security_sha256 = $original.SecuritySha256
            original_file_attributes = $original.FileAttributes
            candidate_sha256 = $plan.CandidateSha256
            candidate_size = $plan.CandidateContents.Length
            temp_name = $tempName
        }})
        $tempPath = Join-Path $binding.RootPath $tempName
        $stream = New-TowerScoutProviderRestrictedFile -Path $tempPath
        try {{
            $tempIdentity = Assert-TowerScoutProviderRestrictedPath -Path $tempPath
            [void] (Add-TowerScoutProviderJournalGeneration `
                -RootPath $recoveryRoot `
                -Digest $binding.Digest `
                -State "created" `
                -Values @{{ temp_identity = $tempIdentity }})
            $stream.Write($plan.CandidateContents, 0, $plan.CandidateContents.Length)
            $stream.Flush($true)
        }}
        finally {{ $stream.Dispose() }}
        [void] (Add-TowerScoutProviderJournalGeneration `
            -RootPath $recoveryRoot `
            -Digest $binding.Digest `
            -State "verified" `
            -Values @{{
            temp_identity = $tempIdentity
            candidate_sha256 = $plan.CandidateSha256
            candidate_size = $plan.CandidateContents.Length
        }})
        {post_stage_action}
        "seeded"
    }}
    finally {{
        try {{ $mutex.ReleaseMutex() }} catch [System.ApplicationException] {{ }}
        $mutex.Dispose()
    }}
    """
    reconcile = f"""
    $ErrorActionPreference = "Stop"
    . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"
    $result = Set-TowerScoutPodmanComposeProviderEnv -ProviderPath "{provider}" -RootPath "{temp_root}" -Apply
    if (-not $result.Applied) {{ throw "Fresh-process reconciliation did not complete." }}
    $binding = Get-TowerScoutProviderEnvironmentBinding -RootPath "{temp_root}"
    $recoveryRoot = Initialize-TowerScoutProviderRecoveryRoot
    if (@(Get-TowerScoutProviderJournalChain -RootPath $recoveryRoot -Digest $binding.Digest).Count -ne 0) {{
        throw "Fresh-process reconciliation retained a journal."
    }}
    if (Get-ChildItem -LiteralPath "{temp_root}" -Filter ".towerscout-provider-env-*.tmp") {{
        throw "Fresh-process reconciliation retained a temp."
    }}
    "ok"
    """
    cleanup = f"""
    $ErrorActionPreference = "SilentlyContinue"
    . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"
    $binding = Get-TowerScoutProviderEnvironmentBinding -RootPath "{temp_root}"
    $recoveryRoot = Initialize-TowerScoutProviderRecoveryRoot
    Remove-TowerScoutProviderJournalChain -RootPath $recoveryRoot -Digest $binding.Digest
    Get-ChildItem -LiteralPath "{temp_root}" -Filter ".towerscout-provider-env-*.tmp" | Remove-Item -Force
    """

    try:
        seeded = _run_powershell(seed)
        assert seeded.returncode == 0, seeded.stdout + seeded.stderr
        assert "seeded" in seeded.stdout

        resumed = _run_powershell(reconcile)
        if post_exit_state in {"third", "candidate_attributes"}:
            assert resumed.returncode != 0
            if post_exit_state == "third":
                assert env_file.read_bytes() == b"UNRELATED=third\r\n"
            else:
                assert (
                    f"PODMAN_COMPOSE_PROVIDER={provider}".encode()
                    in env_file.read_bytes()
                )
            assert "changed unexpectedly" in resumed.stderr
            assert str(provider) not in resumed.stdout
            assert "SECRET" not in resumed.stdout
        else:
            assert resumed.returncode == 0, resumed.stdout + resumed.stderr
            assert "ok" in resumed.stdout
            assert (
                f"PODMAN_COMPOSE_PROVIDER={provider}".encode() in env_file.read_bytes()
            )
            assert b"SECRET=opaque" in env_file.read_bytes()
            assert str(provider) not in resumed.stdout
            assert "SECRET" not in resumed.stdout
    finally:
        _run_powershell(cleanup)
        shutil.rmtree(temp_root, ignore_errors=True)


@pytest.mark.skipif(
    os.name != "nt", reason="PowerShell launcher helpers are Windows-only"
)
@pytest.mark.parametrize("orphan_contents", (b"", b"unexpected"))
def test_podman_compose_provider_env_fresh_process_classifies_planned_orphan(
    orphan_contents: bytes,
):
    temp_root = (
        REPO_ROOT
        / ".agent_work"
        / "pytest-temp"
        / f"task087-provider-planned-{uuid.uuid4().hex}"
    )
    temp_root.mkdir(parents=True)
    provider = temp_root / "podman-compose.cmd"
    _write_podman_compose_provider(provider)
    env_file = temp_root / ".env"
    original = b"PODMAN_COMPOSE_PROVIDER=old\nUNCHANGED=value\n"
    env_file.write_bytes(original)
    orphan_b64 = base64.b64encode(orphan_contents).decode("ascii")

    seed = f"""
    $ErrorActionPreference = "Stop"
    . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"
    $binding = Get-TowerScoutProviderEnvironmentBinding -RootPath "{temp_root}"
    $mutex = Enter-TowerScoutProviderEnvironmentMutex -Name $binding.MutexName
    try {{
        $recoveryRoot = Initialize-TowerScoutProviderRecoveryRoot
        $envPath = Join-Path $binding.RootPath ".env"
        $original = Get-TowerScoutProviderEnvironmentObservation -Path $envPath
        $plan = ConvertTo-TowerScoutProviderEnvironmentPlan `
            -SourceContents $original.Contents `
            -ProviderPath "{provider}" `
            -OriginalPresent $true
        $tempName = ".towerscout-provider-env-$([guid]::NewGuid().ToString('N')).tmp"
        [void] (Add-TowerScoutProviderJournalGeneration `
            -RootPath $recoveryRoot `
            -Digest $binding.Digest `
            -State "planned" `
            -Values @{{
            root_identity = $binding.RootIdentity
            original_present = $true
            original_sha256 = $original.Sha256
            original_identity = $original.Identity
            original_security_sha256 = $original.SecuritySha256
            original_file_attributes = $original.FileAttributes
            candidate_sha256 = $plan.CandidateSha256
            candidate_size = $plan.CandidateContents.Length
            temp_name = $tempName
        }})
        $stream = New-TowerScoutProviderRestrictedFile -Path (Join-Path $binding.RootPath $tempName)
        $orphanContents = [Convert]::FromBase64String("{orphan_b64}")
        if ($orphanContents.Length -gt 0) {{
            $stream.Write($orphanContents, 0, $orphanContents.Length)
        }}
        $stream.Flush($true)
        $stream.Dispose()
        "seeded"
    }}
    finally {{
        try {{ $mutex.ReleaseMutex() }} catch [System.ApplicationException] {{ }}
        $mutex.Dispose()
    }}
    """
    reconcile = f"""
    $ErrorActionPreference = "Stop"
    . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"
    $result = Set-TowerScoutPodmanComposeProviderEnv -ProviderPath "{provider}" -RootPath "{temp_root}" -Apply
    if (-not $result.Applied) {{ throw "Planned orphan reconciliation did not complete." }}
    $binding = Get-TowerScoutProviderEnvironmentBinding -RootPath "{temp_root}"
    $recoveryRoot = Initialize-TowerScoutProviderRecoveryRoot
    if (@(Get-TowerScoutProviderJournalChain -RootPath $recoveryRoot -Digest $binding.Digest).Count -ne 0) {{
        throw "Planned orphan reconciliation retained a journal."
    }}
    if (Get-ChildItem -LiteralPath "{temp_root}" -Filter ".towerscout-provider-env-*.tmp") {{
        throw "Planned orphan reconciliation retained a temp."
    }}
    "ok"
    """
    cleanup = f"""
    $ErrorActionPreference = "SilentlyContinue"
    . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"
    $binding = Get-TowerScoutProviderEnvironmentBinding -RootPath "{temp_root}"
    $recoveryRoot = Initialize-TowerScoutProviderRecoveryRoot
    Remove-TowerScoutProviderJournalChain -RootPath $recoveryRoot -Digest $binding.Digest
    Get-ChildItem -LiteralPath "{temp_root}" -Filter ".towerscout-provider-env-*.tmp" | Remove-Item -Force
    """

    try:
        seeded = _run_powershell(seed)
        assert seeded.returncode == 0, seeded.stdout + seeded.stderr
        resumed = _run_powershell(reconcile)
        if orphan_contents:
            assert resumed.returncode != 0
            assert "ambiguous" in resumed.stderr
            assert env_file.read_bytes() == original
            assert list(temp_root.glob(".towerscout-provider-env-*.tmp"))
        else:
            assert resumed.returncode == 0, resumed.stdout + resumed.stderr
            assert "ok" in resumed.stdout
            assert (
                f"PODMAN_COMPOSE_PROVIDER={provider}".encode() in env_file.read_bytes()
            )
            assert b"UNCHANGED=value" in env_file.read_bytes()
    finally:
        _run_powershell(cleanup)
        shutil.rmtree(temp_root, ignore_errors=True)


@pytest.mark.skipif(
    os.name != "nt", reason="PowerShell launcher helpers are Windows-only"
)
@pytest.mark.parametrize(
    "source",
    (
        b"PODMAN_COMPOSE_PROVIDER=one\nPODMAN_COMPOSE_PROVIDER=two\n",
        b"podman_compose_provider=wrong-case\n",
        b"PODMAN_COMPOSE_PROVIDER without equals\n",
        b"PODMAN_COMPOSE_PROVIDER=one\x00hidden\n",
    ),
)
def test_podman_compose_provider_env_plan_rejects_ambiguous_content(source: bytes):
    temp_root = (
        REPO_ROOT
        / ".agent_work"
        / "pytest-temp"
        / f"task087-provider-invalid-{uuid.uuid4().hex}"
    )
    temp_root.mkdir(parents=True)
    provider = temp_root / "podman-compose.cmd"
    _write_podman_compose_provider(provider)
    source_b64 = base64.b64encode(source).decode("ascii")

    try:
        command = f"""
        $ErrorActionPreference = "Stop"
        . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"
        try {{
            ConvertTo-TowerScoutProviderEnvironmentPlan `
                -SourceContents ([Convert]::FromBase64String("{source_b64}")) `
                -ProviderPath "{provider}" `
                -OriginalPresent $true | Out-Null
            throw "Unsafe environment content was accepted."
        }}
        catch {{
            if ($_.Exception.Message -eq "Unsafe environment content was accepted.") {{
                throw
            }}
            if ($_.Exception.Message -notmatch "cannot be updated safely") {{
                throw
            }}
        }}
        "ok"
        """
        result = _run_powershell(command)

        assert result.returncode == 0, result.stdout + result.stderr
        assert "ok" in result.stdout
        assert str(provider) not in result.stdout
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


@pytest.mark.skipif(
    os.name != "nt", reason="PowerShell launcher helpers are Windows-only"
)
def test_podman_compose_provider_env_plan_rejects_control_character_in_provider():
    command = f"""
    $ErrorActionPreference = "Stop"
    . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"
    try {{
        ConvertTo-TowerScoutProviderEnvironmentPlan `
            -SourceContents ([System.Text.Encoding]::UTF8.GetBytes("UNCHANGED=value`n")) `
            -ProviderPath "safe`nINJECTED=value" `
            -OriginalPresent $true | Out-Null
        throw "Unsafe provider path was accepted."
    }}
    catch {{
        if ($_.Exception.Message -eq "Unsafe provider path was accepted.") {{ throw }}
        if ($_.Exception.Message -notmatch "cannot be updated safely") {{ throw }}
    }}
    "ok"
    """
    result = _run_powershell(command)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "ok" in result.stdout
    assert "INJECTED" not in result.stdout


@pytest.mark.skipif(
    os.name != "nt", reason="PowerShell launcher helpers are Windows-only"
)
@pytest.mark.parametrize(
    "artifact_name",
    (
        "journal-0123456789abcdef0123456789abcdef.pointer",
        ".journal-pointer-0123456789abcdef0123456789abcdef.tmp",
        "pointer-transition-0123456789abcdef0123456789abcdef-00000000000000000001.generation",
        "recovery-backup-0123456789abcdef0123456789abcdef.blob",
    ),
)
def test_provider_environment_blocks_each_repair_recovery_artifact(
    tmp_path: Path, artifact_name: str
):
    (tmp_path / artifact_name).write_bytes(b"opaque")
    command = f"""
    $ErrorActionPreference = "Stop"
    . "{REPO_ROOT}\\scripts\\lib\\TowerScoutProviderEnvironment.ps1"
    if (-not (Test-TowerScoutRepairRecoveryArtifactsPending -RootPath "{tmp_path}")) {{
        throw "Repair recovery artifact was not detected."
    }}
    "ok"
    """
    result = _run_powershell(command)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


@pytest.mark.skipif(
    os.name != "nt", reason="Windows hard-link security is Windows-only"
)
def test_podman_compose_provider_env_apply_rejects_hard_linked_destination():
    temp_root = (
        REPO_ROOT
        / ".agent_work"
        / "pytest-temp"
        / f"task087-provider-hardlink-{uuid.uuid4().hex}"
    )
    temp_root.mkdir(parents=True)
    provider = temp_root / "podman-compose.cmd"
    _write_podman_compose_provider(provider)
    env_file = temp_root / ".env"
    original = b"PODMAN_COMPOSE_PROVIDER=old\nSECRET=opaque\n"
    env_file.write_bytes(original)
    hard_link = temp_root / "unrelated.env"
    os.link(env_file, hard_link)

    try:
        command = f"""
        $ErrorActionPreference = "Stop"
        . "{REPO_ROOT}\\scripts\\lib\\TowerScoutPodmanComposeProvider.ps1"
        try {{
            Set-TowerScoutPodmanComposeProviderEnv -ProviderPath "{provider}" -RootPath "{temp_root}" -Apply | Out-Null
            throw "Hard-linked environment file was accepted."
        }}
        catch {{
            if ($_.Exception.Message -eq "Hard-linked environment file was accepted.") {{ throw }}
            if ($_.Exception.Message -notmatch "cannot be updated safely") {{ throw }}
        }}
        "ok"
        """
        result = _run_powershell(command)

        assert result.returncode == 0, result.stdout + result.stderr
        assert "ok" in result.stdout
        assert env_file.read_bytes() == original
        assert hard_link.read_bytes() == original
        assert not list(temp_root.glob(".towerscout-provider-env-*.tmp"))
        assert not list(temp_root.glob(".env.backup.*"))
        assert "SECRET" not in result.stdout
        assert str(provider) not in result.stdout
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)
