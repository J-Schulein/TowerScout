import base64
import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER_LIB = REPO_ROOT / "scripts" / "lib" / "TowerScoutHostHelper.ps1"
HELPER_SCRIPT = REPO_ROOT / "scripts" / "host-helper.ps1"


def _powershell_executable():
    return shutil.which("powershell.exe") or shutil.which("pwsh")


def _run_powershell_script(script: str) -> subprocess.CompletedProcess[str]:
    powershell = _powershell_executable()
    if powershell is None:
        pytest.skip("PowerShell executable not found")

    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_host_helper_provider_tls_repair_plan_is_docker_only_and_allowlisted():
    script = HELPER_LIB.read_text(encoding="utf-8")

    assert (
        '$script:TowerScoutHostHelperProviderTlsRepairConfirmation = '
        '"repair_tls_and_restart"'
    ) in script
    assert "function New-TowerScoutProviderTlsRepairOperationPlan" in script
    assert 'if ($providerValue -notin @("google", "azure"))' in script
    assert '$engine -ne "docker"' in script
    assert '"unsupported_runtime"' in script
    assert '"rejected_confirmation"' in script
    assert '"rejected_unknown_provider"' in script
    assert '$publicProvider = "unknown"' in script
    assert '"scripts\\repair-provider-tls.cmd"' in script
    assert (
        'Arguments = @("-Provider", $providerValue, "-Engine", "docker", '
        '"-Gpu", $gpu, "-Apply")'
    ) in script
    assert '"scripts\\stop.cmd"' in script
    assert '"start.bat"' in script
    assert '"-NoBrowser"' in script
    assert "function New-TowerScoutHostHelperOperationLock" in script
    assert "nonce_fingerprint" in script
    assert '"operation-*.json"' in script
    assert "operation_files_cleared" in script
    assert "provider_tls_repair = $false" in script
    assert '"Access-Control-Allow-Methods: GET, POST, OPTIONS"' in script


def test_host_helper_provider_tls_repair_operation_api_is_bounded_and_non_mutating():
    script = HELPER_LIB.read_text(encoding="utf-8")

    assert "$script:TowerScoutHostHelperMaxBodyBytes = 4096" in script
    assert (
        '$script:TowerScoutHostHelperOperationAuthorizationPattern = '
        '"^[A-Za-z0-9_-]{32,128}$"'
    ) in script
    assert "function Read-TowerScoutProviderTlsRepairRequestBody" in script
    assert "function New-TowerScoutProviderTlsRepairOperationPlanResponse" in script
    assert "function Get-TowerScoutHostHelperOperationStatus" in script
    assert "function ConvertTo-TowerScoutHostHelperScriptExitState" in script
    assert 'if ($method -eq "POST")' in script
    assert '"The helper POST request did not include a content length."' in script
    assert '"The helper request body was too large."' in script
    assert "$contentTypeBase -ne \"application/json\"" in script
    assert "[System.Text.Encoding]::UTF8.GetByteCount($bodyText)" in script
    assert '"json_body_too_large"' in script
    assert '"Content-Length:' in script
    assert '"Content-Type:' in script
    assert '"/operations/provider-tls-repair"' in script
    assert '$operationStatusPathPattern = "^/operations/([a-f0-9]{32})$"' in script
    assert "execution_enabled = $ExecutionEnabled" in script
    assert '"operation_authorization"' in script
    assert '"rejected_operation_authorization"' in script
    assert '"rejected_unexpected_field"' in script
    assert '"operation_exists"' in script
    assert '"tls_repair_completed"' in script
    assert '"readiness_timeout"' in script
    assert '"operation_timeout"' in script
    assert "-ExecutionEnabled:$true" not in script


@pytest.mark.skipif(os.name != "nt", reason="PowerShell host helper is Windows-only")
def test_host_helper_operation_request_api_direct_invocation_is_non_mutating():
    helper_path = str(HELPER_LIB).replace("'", "''")
    script = textwrap.dedent(
        f"""
        $ProgressPreference = 'SilentlyContinue'
        . '{helper_path}'
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ("towerscout-task087-api-{{0}}" -f (New-TowerScoutHostHelperSessionId))
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        try {{
            $profile = New-TowerScoutHostHelperRuntimeProfile -Engine "docker" -Gpu "off" -AppPort 5000 -PackageRoot $root -PackageFlavor "api-probe"
            $authorization = New-TowerScoutHostHelperToken
            $request = [pscustomobject]@{{
                Headers = @{{ "content-type" = "application/json" }}
                BodyText = (@{{ provider = "google"; confirmation = $script:TowerScoutHostHelperProviderTlsRepairConfirmation; operation_authorization = $authorization }} | ConvertTo-Json -Compress)
            }}
            $planned = New-TowerScoutProviderTlsRepairOperationPlanResponse -Profile $profile -Request $request
            $status = Get-TowerScoutHostHelperOperationStatus -Profile $profile -OperationId ([string] $planned.Body.operation_id)
            $same = New-TowerScoutProviderTlsRepairOperationPlanResponse -Profile $profile -Request $request
            $otherRequest = [pscustomobject]@{{
                Headers = @{{ "content-type" = "application/json" }}
                BodyText = (@{{ provider = "google"; confirmation = $script:TowerScoutHostHelperProviderTlsRepairConfirmation; operation_authorization = (New-TowerScoutHostHelperToken) }} | ConvertTo-Json -Compress)
            }}
            $busy = New-TowerScoutProviderTlsRepairOperationPlanResponse -Profile $profile -Request $otherRequest
            $unexpectedRequest = [pscustomobject]@{{
                Headers = @{{ "content-type" = "application/json" }}
                BodyText = (@{{ provider = "google"; confirmation = $script:TowerScoutHostHelperProviderTlsRepairConfirmation; operation_authorization = (New-TowerScoutHostHelperToken); restart_mode = "restart_now" }} | ConvertTo-Json -Compress)
            }}
            $unexpected = New-TowerScoutProviderTlsRepairOperationPlanResponse -Profile $profile -Request $unexpectedRequest
            $badAuthorizationRequest = [pscustomobject]@{{
                Headers = @{{ "content-type" = "application/json" }}
                BodyText = (@{{ provider = "google"; confirmation = $script:TowerScoutHostHelperProviderTlsRepairConfirmation; operation_authorization = "short" }} | ConvertTo-Json -Compress)
            }}
            $badAuthorization = New-TowerScoutProviderTlsRepairOperationPlanResponse -Profile $profile -Request $badAuthorizationRequest
            [pscustomobject]@{{
                planned_status = $planned.StatusCode
                planned_state = [string] $planned.Body.state
                execution_enabled = [bool] $planned.Body.execution_enabled
                status_poll = $status.StatusCode
                same_authorization = $same.StatusCode
                same_existing = [bool] $same.Body.existing_operation
                different_authorization = $busy.StatusCode
                different_state = [string] $busy.Body.state
                unexpected_field = $unexpected.StatusCode
                unexpected_state = [string] $unexpected.Body.state
                bad_authorization = $badAuthorization.StatusCode
                bad_authorization_state = [string] $badAuthorization.Body.state
            }} | ConvertTo-Json -Compress
        }}
        finally {{
            if (Test-Path -LiteralPath $root) {{
                Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
            }}
        }}
        """
    )

    result = _run_powershell_script(script)

    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(next(line for line in result.stdout.splitlines() if line))
    assert payload == {
        "planned_status": 202,
        "planned_state": "planned",
        "execution_enabled": False,
        "status_poll": 200,
        "same_authorization": 202,
        "same_existing": True,
        "different_authorization": 409,
        "different_state": "operation_busy",
        "unexpected_field": 400,
        "unexpected_state": "rejected_unexpected_field",
        "bad_authorization": 400,
        "bad_authorization_state": "rejected_operation_authorization",
    }


@pytest.mark.skipif(os.name != "nt", reason="PowerShell host helper is Windows-only")
def test_host_helper_self_test_covers_provider_tls_operation_contract():
    powershell = _powershell_executable()
    if powershell is None:
        pytest.skip("PowerShell executable not found")

    result = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(HELPER_SCRIPT),
            "-SelfTest",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    scenarios = {
        scenario["name"]: scenario for scenario in payload["operation_scenarios"]
    }

    assert scenarios["provider_tls_repair_docker_plan"]["state"] == "planned"
    assert scenarios["provider_tls_repair_docker_plan"]["provider"] == "google"
    assert scenarios["provider_tls_repair_docker_plan"]["runtime"] == "docker"
    assert (
        scenarios["provider_tls_repair_podman_blocked"]["state"]
        == "unsupported_runtime"
    )
    assert (
        scenarios["provider_tls_repair_confirmation_required"]["state"]
        == "rejected_confirmation"
    )
    assert (
        scenarios["provider_tls_repair_provider_allowlist"]["state"]
        == "rejected_unknown_provider"
    )
    assert scenarios["provider_tls_repair_provider_allowlist"]["provider"] == "unknown"
    assert (
        scenarios["provider_tls_repair_single_operation_lock"]["state"]
        == "operation_busy"
    )
    assert "repair-provider-tls" not in result.stdout
    assert "scripts\\" not in result.stdout
    assert "start.bat" not in result.stdout
    assert "google;start-process" not in result.stdout.lower()
    assert "google;process-start" not in result.stdout.lower()
    assert "Start-Process" not in result.stdout
