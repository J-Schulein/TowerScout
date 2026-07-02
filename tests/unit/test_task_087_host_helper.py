import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER_LIB = REPO_ROOT / "scripts" / "lib" / "TowerScoutHostHelper.ps1"
HELPER_SCRIPT = REPO_ROOT / "scripts" / "host-helper.ps1"


def _powershell_executable():
    return shutil.which("powershell.exe") or shutil.which("pwsh")


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
    assert '"Access-Control-Allow-Methods: GET, OPTIONS"' in script


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
    assert "Start-Process" not in result.stdout
