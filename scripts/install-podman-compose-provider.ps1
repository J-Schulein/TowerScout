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

function Invoke-TowerScoutInstallerCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FileName,

        [string[]] $Arguments = @(),

        [Parameter(Mandatory = $true)]
        [string] $FailureMessage
    )

    Write-Host "Running approved installer command."
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    try {
        try {
            $output = & $FileName @Arguments 2>&1
            $exitCode = $LASTEXITCODE
            if ($null -eq $exitCode) {
                $exitCode = 0
            }
        }
        catch {
            $message = $_.Exception.Message
            if ([string]::IsNullOrWhiteSpace($message)) {
                $message = "command failed"
            }
            throw "$FailureMessage`n$message"
        }

        if ($exitCode -ne 0) {
            $outputText = ([string]::Join([Environment]::NewLine, @($output))).Trim()
            if (-not [string]::IsNullOrWhiteSpace($outputText)) {
                throw "$FailureMessage`n$outputText"
            }
            throw $FailureMessage
        }
        return @($output)
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

function Get-TowerScoutInstallerVenvPython {
    param(
        [Parameter(Mandatory = $true)]
        [string] $VenvDir
    )

    foreach ($relativePath in @("Scripts\python.exe", "bin\python")) {
        $candidate = Join-Path $VenvDir $relativePath
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    throw "The provider virtual environment was created, but no Python executable was found under $VenvDir."
}

function Assert-TowerScoutInstallerPythonVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Python,

        [string] $Requirement = ">=3.9"
    )

    if ($Requirement -ne ">=3.9") {
        throw "Unsupported provider Python requirement '$Requirement'. The installer currently enforces >=3.9."
    }

    $versionCheck = "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)"
    Invoke-TowerScoutInstallerCommand `
        -FileName $Python `
        -Arguments @("-c", $versionCheck) `
        -FailureMessage "Podman Compose provider '$ProviderId' requires Python $Requirement. Install Python 3.9 or newer and retry." | Out-Null
}

function Get-TowerScoutInstallerPythonRuntime {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Python
    )

    $runtimeProbe = 'import json, platform, sys, sysconfig; free_threaded = bool(sysconfig.get_config_var(''Py_GIL_DISABLED'')); python_tag = ''cp%d%d%s'' % (sys.version_info.major, sys.version_info.minor, ''t'' if free_threaded else ''''); machine = platform.machine().lower(); platform_tag = ''win_amd64'' if sys.platform == ''win32'' and machine in (''amd64'', ''x86_64'') else ''unsupported''; print(json.dumps({''python_tag'': python_tag, ''platform_tag'': platform_tag}))'
    $output = Invoke-TowerScoutInstallerCommand `
        -FileName $Python `
        -Arguments @("-c", $runtimeProbe) `
        -FailureMessage "Failed to determine the provider Python runtime tag."
    $runtime = ([string]::Join("", @($output))).Trim() | ConvertFrom-Json
    if ([string] $runtime.platform_tag -eq "unsupported") {
        throw "The approved Podman Compose provider installer currently supports 64-bit Windows Python only."
    }

    return $runtime
}

function Resolve-TowerScoutInstallerDependencyArtifact {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Dependency,

        [Parameter(Mandatory = $true)]
        [string] $PythonTag,

        [Parameter(Mandatory = $true)]
        [string] $PlatformTag
    )

    $matches = @($Dependency.artifacts | Where-Object {
        $artifactPythonTag = (Get-TowerScoutProviderObjectValue -InputObject $_ -Name "python_tag").Trim().ToLowerInvariant()
        $artifactPlatformTag = (Get-TowerScoutProviderObjectValue -InputObject $_ -Name "platform_tag").Trim().ToLowerInvariant()
        ($artifactPythonTag -eq $PythonTag.ToLowerInvariant() -or $artifactPythonTag -eq "py3") -and
        ($artifactPlatformTag -eq $PlatformTag.ToLowerInvariant() -or $artifactPlatformTag -eq "any")
    })
    if ($matches.Count -ne 1) {
        throw "Expected exactly one approved $($Dependency.name) artifact for $PythonTag/$PlatformTag; found $($matches.Count)."
    }

    return $matches[0]
}

function Invoke-TowerScoutInstallerVerifiedDownload {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Artifact,

        [Parameter(Mandatory = $true)]
        [string] $DestinationRoot,

        [Parameter(Mandatory = $true)]
        [string] $DisplayName
    )

    $filename = (Get-TowerScoutProviderObjectValue -InputObject $Artifact -Name "filename").Trim()
    $sourceUrl = (Get-TowerScoutProviderObjectValue -InputObject $Artifact -Name "source_url").Trim()
    $expectedSha256 = (Get-TowerScoutProviderObjectValue -InputObject $Artifact -Name "sha256").Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($filename) -or
        $sourceUrl -notmatch '^https://files\.pythonhosted\.org/' -or
        $expectedSha256 -notmatch '^[a-f0-9]{64}$') {
        throw "Approved artifact metadata is incomplete or invalid for $DisplayName."
    }

    $sourceUri = [Uri] $sourceUrl
    if ([System.IO.Path]::GetFileName($sourceUri.AbsolutePath) -ne $filename) {
        throw "Approved artifact filename does not match its source URL for $DisplayName."
    }

    $downloadPath = Join-Path $DestinationRoot $filename
    Write-Host "Downloading approved $DisplayName artifact."
    Invoke-WebRequest -UseBasicParsing -Uri $sourceUrl -OutFile $downloadPath
    $actualSha256 = (Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $expectedSha256) {
        throw "Downloaded $DisplayName artifact SHA-256 did not match the approved catalog."
    }
    Write-Host "Approved $DisplayName artifact SHA-256 verified."

    return $downloadPath
}

function Assert-TowerScoutInstallerPackageVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Python,

        [Parameter(Mandatory = $true)]
        [string] $Distribution,

        [Parameter(Mandatory = $true)]
        [string] $Version
    )

    $versionProbe = "import importlib.metadata as metadata, sys; sys.exit(0 if metadata.version('$Distribution') == '$Version' else 1)"
    Invoke-TowerScoutInstallerCommand `
        -FileName $Python `
        -Arguments @("-c", $versionProbe) `
        -FailureMessage "Installed package version verification failed for $Distribution." | Out-Null
}

$repoRoot = Get-TowerScoutProviderRepoRoot
$managedInstallRoot = Join-Path $repoRoot "tools\podman-compose-provider"

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

$requiresPython = (Get-TowerScoutProviderObjectValue -InputObject $provider -Name "requires_python").Trim()
if ([string]::IsNullOrWhiteSpace($requiresPython)) {
    $requiresPython = ">=3.9"
}
Assert-TowerScoutInstallerPythonVersion -Python $Python -Requirement $requiresPython
$pythonRuntime = Get-TowerScoutInstallerPythonRuntime -Python $Python

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $managedInstallRoot $ProviderId
}
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)

if ((Test-Path -LiteralPath $InstallDir) -and -not $Force) {
    throw "Install directory already exists: $InstallDir. Use -Force to replace it."
}

if (Test-Path -LiteralPath $InstallDir) {
    if (-not (Test-TowerScoutInstallerChildPath -Parent $managedInstallRoot -Child $InstallDir)) {
        throw "-Force replacement is only allowed inside the managed provider cache: $managedInstallRoot"
    }
}
$downloadRoot = Join-Path ([System.IO.Path]::GetTempPath()) "towerscout-podman-provider-$([Guid]::NewGuid().ToString('N'))"
$backupDir = ""
$installCreated = $false
try {
    New-Item -ItemType Directory -Force -Path $downloadRoot | Out-Null
    $providerArtifact = [pscustomobject]@{
        filename = [System.IO.Path]::GetFileName(([Uri] $sourceUrl).AbsolutePath)
        source_url = $sourceUrl
        sha256 = $expectedSha256
    }
    $providerWheel = Invoke-TowerScoutInstallerVerifiedDownload `
        -Artifact $providerArtifact `
        -DestinationRoot $downloadRoot `
        -DisplayName "provider"

    $dependencyWheels = @()
    foreach ($dependency in @($provider.dependencies)) {
        $artifact = Resolve-TowerScoutInstallerDependencyArtifact `
            -Dependency $dependency `
            -PythonTag ([string] $pythonRuntime.python_tag) `
            -PlatformTag ([string] $pythonRuntime.platform_tag)
        $dependencyWheels += Invoke-TowerScoutInstallerVerifiedDownload `
            -Artifact $artifact `
            -DestinationRoot $downloadRoot `
            -DisplayName ([string] $dependency.name)
    }

    if (Test-Path -LiteralPath $InstallDir) {
        $backupDir = "$InstallDir.backup.$([Guid]::NewGuid().ToString('N'))"
        Move-Item -LiteralPath $InstallDir -Destination $backupDir
    }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $installCreated = $true

    $venvDir = Join-Path $InstallDir ".venv"
    Invoke-TowerScoutInstallerCommand `
        -FileName $Python `
        -Arguments @("-m", "venv", $venvDir) `
        -FailureMessage "Failed to create the provider virtual environment." | Out-Null

    $venvPython = Get-TowerScoutInstallerVenvPython -VenvDir $venvDir
    $pipInstallArguments = @(
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-warn-script-location",
        "--no-index",
        "--no-deps",
        $providerWheel
    ) + $dependencyWheels
    Invoke-TowerScoutInstallerCommand `
        -FileName $venvPython `
        -Arguments $pipInstallArguments `
        -FailureMessage "Failed to install the approved Podman Compose provider wheelhouse." | Out-Null
    Invoke-TowerScoutInstallerCommand `
        -FileName $venvPython `
        -Arguments @("-m", "pip", "check", "--disable-pip-version-check") `
        -FailureMessage "The approved Podman Compose provider environment failed pip check." | Out-Null

    Assert-TowerScoutInstallerPackageVersion `
        -Python $venvPython `
        -Distribution "podman-compose" `
        -Version ([string] $provider.version)
    foreach ($dependency in @($provider.dependencies)) {
        Assert-TowerScoutInstallerPackageVersion `
            -Python $venvPython `
            -Distribution ([string] $dependency.name) `
            -Version ([string] $dependency.version)
    }

    $venvProviderPath = Join-Path $venvDir "Scripts\podman-compose.exe"
    if (-not (Test-Path -LiteralPath $venvProviderPath -PathType Leaf)) {
        throw "Provider installation completed, but the expected virtual-environment executable was not found."
    }

    $wrapperPath = Join-Path $InstallDir "podman-compose.cmd"
    @"
@echo off
set "TOWERSCOUT_PODMAN_COMPOSE_PROVIDER_HOME=%~dp0"
"%~dp0.venv\Scripts\podman-compose.exe" %*
"@ | Set-Content -LiteralPath $wrapperPath -Encoding ASCII

    $check = Test-TowerScoutApprovedPodmanComposeProvider -ProviderPath $venvProviderPath -Provider $provider
    if (-not $check.Accepted) {
        throw "Installed provider did not pass the approved-provider check: $($check.Reason)"
    }

    Set-TowerScoutPodmanComposeProviderEnv -ProviderPath $venvProviderPath -RootPath $repoRoot -Apply:$Apply | Out-Null
    if (-not [string]::IsNullOrWhiteSpace($backupDir) -and (Test-Path -LiteralPath $backupDir)) {
        try {
            Remove-Item -LiteralPath $backupDir -Recurse -Force
            $backupDir = ""
        }
        catch {
            Write-Warning "The replacement provider is active, but the previous managed provider backup could not be removed."
        }
    }
}
catch {
    if ($installCreated -and (Test-Path -LiteralPath $InstallDir)) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force
    }
    if (-not [string]::IsNullOrWhiteSpace($backupDir) -and (Test-Path -LiteralPath $backupDir)) {
        Move-Item -LiteralPath $backupDir -Destination $InstallDir
    }
    throw
}
finally {
    if (Test-Path -LiteralPath $downloadRoot) {
        Remove-Item -LiteralPath $downloadRoot -Recurse -Force
    }
}
