param(
    [ValidateSet("auto", "docker", "podman")]
    [string] $Engine = "auto"
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\lib\TowerScoutCompose.ps1"
. "$PSScriptRoot\lib\TowerScoutHostHelper.ps1"

try {
    $helperCleanup = Clear-TowerScoutHostHelperSession -RootPath (Get-TowerScoutRepoRoot)
    if ($helperCleanup.cleared -gt 0) {
        Write-Host "Invalidated TowerScout host helper session metadata."
    }
}
catch {
    Write-Host "Could not invalidate TowerScout host helper session metadata: $($_.Exception.Message)"
}

Invoke-TowerScoutCompose -Engine $Engine -ComposeArguments @("down", "--remove-orphans")
exit $script:TowerScoutComposeExitCode
