param(
    [string] $ProviderId = "podman-compose-pypi-1.5.0",

    [string] $InstallDir = "",

    [string] $Python = "python",

    [switch] $Apply,

    [switch] $Force
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\lib\TowerScoutPodmanComposeProvider.ps1"

function Test-TowerScoutInstallerChildPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Parent,

        [Parameter(Mandatory = $true)]
        [string] $Child
    )

    $parentFull = [System.IO.Path]::GetFullPath($Parent)
    $childFull = [System.IO.Path]::GetFullPath($Child)
    $trimChars = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $parentPrefix = $parentFull.TrimEnd($trimChars) + [System.IO.Path]::DirectorySeparatorChar

    return $childFull.StartsWith($parentPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

$repoRoot = Get-TowerScoutProviderRepoRoot
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $repoRoot "tools\podman-compose-provider\$ProviderId"
}
$managedInstallRoot = Join-Path $repoRoot "tools\podman-compose-provider"
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)

$catalog = Get-TowerScoutPodmanComposeProviderCatalog
$provider = @($catalog.providers | Where-Object { [string] $_.id -eq $ProviderId } | Select-Object -First 1)
if ($provider.Count -eq 0) {
    throw "Unknown Podman Compose provider id '$ProviderId'."
}
$provider = $provider[0]

$sourceUrl = [string] $provider.source_url
$expectedSha256 = ([string] $provider.package_sha256).Trim().ToLowerInvariant()
if ([string]::IsNullOrWhiteSpace($sourceUrl) -or [string]::IsNullOrWhiteSpace($expectedSha256)) {
    throw "Provider '$ProviderId' does not have a download URL and SHA-256 in the approved catalog."
}

if ((Test-Path -LiteralPath $InstallDir) -and -not $Force) {
    throw "Install directory already exists: $InstallDir. Use -Force to replace it."
}

if (Test-Path -LiteralPath $InstallDir) {
    if (-not (Test-TowerScoutInstallerChildPath -Parent $managedInstallRoot -Child $InstallDir)) {
        throw "-Force replacement is only allowed inside the managed provider cache: $managedInstallRoot"
    }
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$downloadPath = Join-Path $InstallDir ([System.IO.Path]::GetFileName($sourceUrl))
Write-Host "Downloading approved provider package:"
Write-Host $sourceUrl
Invoke-WebRequest -UseBasicParsing -Uri $sourceUrl -OutFile $downloadPath

$actualSha256 = (Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
    throw "Downloaded provider package SHA-256 mismatch. Expected $expectedSha256 but got $actualSha256."
}
Write-Host "Provider package SHA-256 verified."

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($downloadPath)
try {
    $scriptEntry = $null
    foreach ($entry in $zip.Entries) {
        if ($entry.FullName -eq "podman_compose.py") {
            $scriptEntry = $entry
            break
        }
    }
    if ($null -eq $scriptEntry) {
        throw "Downloaded provider package did not contain podman_compose.py."
    }
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile(
        $scriptEntry,
        (Join-Path $InstallDir "podman_compose.py"),
        $true
    )
}
finally {
    $zip.Dispose()
}

$wrapperPath = Join-Path $InstallDir "podman-compose.cmd"
@"
@echo off
"$Python" "%~dp0podman_compose.py" %*
"@ | Set-Content -LiteralPath $wrapperPath -Encoding ASCII

$check = Test-TowerScoutApprovedPodmanComposeProvider -ProviderPath $wrapperPath -Provider $provider
if (-not $check.Accepted) {
    throw "Installed provider did not pass the approved-provider check: $($check.Reason)"
}

Set-TowerScoutPodmanComposeProviderEnv -ProviderPath $wrapperPath -RootPath $repoRoot -Apply:$Apply | Out-Null
