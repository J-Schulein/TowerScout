param(
    [ValidateSet("docker", "podman")]
    [string] $Engine = "docker",

    [ValidateSet("off", "auto", "on")]
    [string] $Gpu = "off",

    [int] $AppPort = $(if ($env:TOWERSCOUT_PORT) { [int] $env:TOWERSCOUT_PORT } else { 5000 }),

    [int] $HelperPort = 0,

    [int] $MaxRequests = 0,

    [string] $PackageFlavor = "source",

    [switch] $SelfTest
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\lib\TowerScoutHostHelper.ps1"

if ($SelfTest) {
    Invoke-TowerScoutHostHelperSelfTest | ConvertTo-Json -Depth 8
    exit 0
}

$token = New-TowerScoutHostHelperToken
$profile = New-TowerScoutHostHelperRuntimeProfile `
    -Engine $Engine `
    -Gpu $Gpu `
    -AppPort $AppPort `
    -PackageFlavor $PackageFlavor `
    -HelperPort $HelperPort

Write-Host "TowerScout host helper proof is starting on loopback only."
Write-Host "Helper token generated and retained in process memory only."
Write-Host "This Gate 1 entry point is not yet wired into product UI or restart orchestration."
Start-TowerScoutHostHelper -Profile $profile -Token $token -HelperPort $HelperPort -MaxRequests $MaxRequests
