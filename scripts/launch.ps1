param(
    [ValidateSet("auto", "docker", "podman")]
    [string] $Engine = "auto",

    [int] $Port = $(if ($env:TOWERSCOUT_PORT) { [int] $env:TOWERSCOUT_PORT } else { 5000 }),

    [int] $TimeoutSeconds = 180,

    [ValidateSet("off", "auto", "on")]
    [string] $Gpu = "off",

    [int] $SessionMaxHours = $(if ($env:TOWERSCOUT_SESSION_MAX_HOURS) { [int] $env:TOWERSCOUT_SESSION_MAX_HOURS } else { 12 }),

    [string] $PodmanMachineName = "",

    [switch] $Build,

    [switch] $NoBrowser
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\lib\TowerScoutCompose.ps1"
. "$PSScriptRoot\lib\TowerScoutHostHelper.ps1"

$repoRoot = Get-TowerScoutRepoRoot
$appUrl = "http://localhost:$Port"
$readinessUrl = "$appUrl/api/readiness"

function Get-TowerScoutPropertyValue {
    param(
        [object] $InputObject,

        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    if ($null -eq $InputObject) {
        return $null
    }
    if ($InputObject.PSObject.Properties.Name -notcontains $Name) {
        return $null
    }
    return $InputObject.PSObject.Properties[$Name].Value
}

function Test-TowerScoutHostHelperReviewEnabled {
    $value = ([string] $env:TOWERSCOUT_HOST_HELPER_REVIEW_ENABLED).Trim().ToLowerInvariant()
    return $value -in @("1", "true", "yes", "on")
}

function Clear-TowerScoutHostHelperBridgeEnvironment {
    $env:TOWERSCOUT_HOST_HELPER_ENABLED = "0"
    Remove-Item Env:TOWERSCOUT_HOST_HELPER_PORT -ErrorAction SilentlyContinue
    Remove-Item Env:TOWERSCOUT_HOST_HELPER_SESSION_ID -ErrorAction SilentlyContinue
    Remove-Item Env:TOWERSCOUT_HOST_HELPER_SESSION_KEY -ErrorAction SilentlyContinue
}

function Get-TowerScoutHostHelperSessionMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [string] $SessionId,

        [Parameter(Mandatory = $true)]
        [string] $RootPath
    )

    $stateDirectory = Get-TowerScoutHostHelperStateDirectory -RootPath $RootPath
    $sessionPath = Join-Path $stateDirectory ("session-{0}.json" -f $SessionId)
    if (-not (Test-Path -LiteralPath $sessionPath -PathType Leaf)) {
        return $null
    }
    try {
        return (Get-Content -LiteralPath $sessionPath -Raw | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Test-TowerScoutHostHelperSessionMetadataMatchesProfile {
    param(
        [object] $Metadata,

        [Parameter(Mandatory = $true)]
        [ValidateSet("docker", "podman")]
        [string] $EngineName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("off", "auto", "on")]
        [string] $GpuMode,

        [Parameter(Mandatory = $true)]
        [int] $AppPort,

        [Parameter(Mandatory = $true)]
        [string] $RootPath,

        [Parameter(Mandatory = $true)]
        [string] $PackageFlavor
    )

    if ($null -eq $Metadata) {
        return $false
    }

    [int] $metadataAppPort = 0
    [int] $metadataHelperPort = 0
    $expectedRootIdentity = Get-TowerScoutHostHelperPackageRootIdentity -PackageRoot $RootPath
    return (
        (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "state") -eq "active" -and
        (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "helper_version") -eq $script:TowerScoutHostHelperVersion -and
        (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "engine") -eq $EngineName -and
        (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "gpu") -eq $GpuMode -and
        [int]::TryParse(
            ([string] (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "app_port")),
            [ref] $metadataAppPort
        ) -and
        $metadataAppPort -eq $AppPort -and
        [int]::TryParse(
            ([string] (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "helper_port")),
            [ref] $metadataHelperPort
        ) -and
        $metadataHelperPort -ge 1 -and
        $metadataHelperPort -le 65535 -and
        (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "package_flavor") -eq $PackageFlavor -and
        (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "package_root_identity") -eq $expectedRootIdentity
    )
}

function Test-TowerScoutHostHelperSessionLiveness {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Metadata,

        [Parameter(Mandatory = $true)]
        [string] $SessionId,

        [Parameter(Mandatory = $true)]
        [string] $RootPath,

        [Parameter(Mandatory = $true)]
        [int] $AppPort
    )

    [int] $processId = 0
    [int] $helperPort = 0
    [datetime] $expectedStartUtc = [datetime]::MinValue
    [datetime] $leaseExpiresUtc = [datetime]::MinValue
    [datetime] $heartbeatUtc = [datetime]::MinValue
    if (
        -not [int]::TryParse(
            ([string] (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "process_id")),
            [ref] $processId
        ) -or
        -not [int]::TryParse(
            ([string] (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "helper_port")),
            [ref] $helperPort
        ) -or
        -not [datetime]::TryParse(
            ([string] (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "process_start_time_utc")),
            [ref] $expectedStartUtc
        ) -or
        -not [datetime]::TryParse(
            ([string] (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "lease_expires_at_utc")),
            [ref] $leaseExpiresUtc
        ) -or
        -not [datetime]::TryParse(
            ([string] (Get-TowerScoutPropertyValue -InputObject $Metadata -Name "last_heartbeat_utc")),
            [ref] $heartbeatUtc
        )
    ) {
        return $false
    }
    $nowUtc = (Get-Date).ToUniversalTime()
    if (
        $leaseExpiresUtc.ToUniversalTime() -le $nowUtc -or
        $heartbeatUtc.ToUniversalTime() -lt $nowUtc.AddSeconds(-10)
    ) {
        return $false
    }
    try {
        $process = Get-Process -Id $processId -ErrorAction Stop
        if (
            [Math]::Abs(
                ($process.StartTime.ToUniversalTime() - $expectedStartUtc.ToUniversalTime()).TotalSeconds
            ) -gt 2
        ) {
            return $false
        }
    }
    catch {
        return $false
    }

    $tokenFileName = [string] (
        Get-TowerScoutPropertyValue -InputObject $Metadata -Name "token_file"
    )
    if ($tokenFileName -ne ("token-{0}.secret" -f $SessionId)) {
        return $false
    }
    $tokenPath = Join-Path `
        (Get-TowerScoutHostHelperStateDirectory -RootPath $RootPath) `
        $tokenFileName
    if (-not (Test-Path -LiteralPath $tokenPath -PathType Leaf)) {
        return $false
    }
    try {
        $token = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
        $request = [System.Net.HttpWebRequest]::Create(
            "http://127.0.0.1:$helperPort/runtime-profile"
        )
        $request.Method = "GET"
        $request.Timeout = 2000
        $request.Headers.Add("X-TowerScout-Helper-Token", $token)
        $request.Headers.Add("Origin", "http://localhost:$AppPort")
        $response = $request.GetResponse()
        try {
            $reader = New-Object System.IO.StreamReader(
                $response.GetResponseStream()
            )
            try {
                $profile = $reader.ReadToEnd() | ConvertFrom-Json
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $response.Dispose()
        }
        return (
            (Get-TowerScoutPropertyValue -InputObject $profile -Name "state") -eq "ready"
        )
    }
    catch {
        return $false
    }
}

function Stop-TowerScoutHostHelperReviewSession {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RootPath
    )

    Clear-TowerScoutHostHelperSession -RootPath $RootPath | Out-Null
    Clear-TowerScoutHostHelperBridgeEnvironment
}

function Initialize-TowerScoutHostHelperReviewSession {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("docker", "podman")]
        [string] $EngineName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("off", "auto", "on")]
        [string] $GpuMode,

        [Parameter(Mandatory = $true)]
        [int] $AppPort,

        [Parameter(Mandatory = $true)]
        [string] $RootPath,

        [Parameter(Mandatory = $true)]
        [string] $PackageFlavor
    )

    if (-not (Test-TowerScoutHostHelperReviewEnabled)) {
        Stop-TowerScoutHostHelperReviewSession -RootPath $RootPath
        return ""
    }

    $existingSessionId = ([string] $env:TOWERSCOUT_HOST_HELPER_SESSION_ID).Trim().ToLowerInvariant()
    $existingSessionKey = ([string] $env:TOWERSCOUT_HOST_HELPER_SESSION_KEY).Trim()
    if (
        $existingSessionId -match "^[a-f0-9]{32}$" -and
        $existingSessionKey -match "^[A-Za-z0-9_-]{43}$"
    ) {
        $existingMetadata = Get-TowerScoutHostHelperSessionMetadata `
            -SessionId $existingSessionId `
            -RootPath $RootPath
        [int] $existingHelperPort = 0
        if (
            (Test-TowerScoutHostHelperSessionMetadataMatchesProfile `
                -Metadata $existingMetadata `
                -EngineName $EngineName `
                -GpuMode $GpuMode `
                -AppPort $AppPort `
                -RootPath $RootPath `
                -PackageFlavor $PackageFlavor) -and
            [int]::TryParse(
                ([string] (Get-TowerScoutPropertyValue -InputObject $existingMetadata -Name "helper_port")),
                [ref] $existingHelperPort
            ) -and
            (Test-TowerScoutHostHelperSessionLiveness `
                -Metadata $existingMetadata `
                -SessionId $existingSessionId `
                -RootPath $RootPath `
                -AppPort $AppPort)
        ) {
            $env:TOWERSCOUT_HOST_HELPER_ENABLED = "1"
            $env:TOWERSCOUT_HOST_HELPER_PORT = "$existingHelperPort"
            Write-Host "Reusing the active TowerScout host helper review session."
            return $existingSessionId
        }
    }

    Stop-TowerScoutHostHelperReviewSession -RootPath $RootPath

    $sessionId = New-TowerScoutHostHelperSessionId
    $sessionKey = New-TowerScoutHostHelperToken
    $env:TOWERSCOUT_HOST_HELPER_SESSION_ID = $sessionId
    $env:TOWERSCOUT_HOST_HELPER_SESSION_KEY = $sessionKey
    $env:TOWERSCOUT_HOST_HELPER_ENABLED = "1"

    $visibleHelper = Join-Path $PSScriptRoot "host-helper-visible.cmd"
    & $visibleHelper `
        -Engine $EngineName `
        -Gpu $GpuMode `
        -AppPort $AppPort `
        -PackageFlavor $PackageFlavor `
        -HelperSessionId $sessionId
    if ($LASTEXITCODE -ne 0) {
        Clear-TowerScoutHostHelperSession -RootPath $RootPath -SessionId $sessionId | Out-Null
        Clear-TowerScoutHostHelperBridgeEnvironment
        throw "The TowerScout host helper review session could not be started."
    }

    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        $metadata = Get-TowerScoutHostHelperSessionMetadata `
            -SessionId $sessionId `
            -RootPath $RootPath
        [int] $helperPort = 0
        if (
            $null -ne $metadata -and
            [int]::TryParse(
                ([string] (Get-TowerScoutPropertyValue -InputObject $metadata -Name "helper_port")),
                [ref] $helperPort
            ) -and
            $helperPort -ge 1 -and
            $helperPort -le 65535
        ) {
            $env:TOWERSCOUT_HOST_HELPER_PORT = "$helperPort"
            Write-Host "TowerScout host helper review session is ready."
            return $sessionId
        }
        Start-Sleep -Milliseconds 200
    }

    Clear-TowerScoutHostHelperSession -RootPath $RootPath -SessionId $sessionId | Out-Null
    Clear-TowerScoutHostHelperBridgeEnvironment
    throw "The TowerScout host helper review session did not become ready."
}

function Get-TowerScoutReadiness {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Url
    )

    try {
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Timeout = 5000
        try {
            $response = $request.GetResponse()
        }
        catch [System.Net.WebException] {
            if ($_.Exception.Response -eq $null) {
                throw
            }
            $response = $_.Exception.Response
        }

        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        try {
            $body = $reader.ReadToEnd()
        }
        finally {
            $reader.Close()
            $response.Close()
        }

        $payload = $body | ConvertFrom-Json
        return [pscustomobject]@{
            Reachable = $true
            State = [string] $payload.state
            Payload = $payload
            Error = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Reachable = $false
            State = "unreachable"
            Payload = $null
            Error = $_.Exception.Message
        }
    }
}

function Write-TowerScoutReadinessSummary {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Readiness
    )

    if (-not $Readiness.Reachable) {
        Write-Host "TowerScout is not reachable yet. The container may still be starting."
        return
    }

    $payload = $Readiness.Payload
    Write-Host "TowerScout readiness state: $($Readiness.State)"
    switch ($Readiness.State) {
        "setup_required" {
            Write-Host "Next action: complete Setup Wizard or Settings with one valid Google Maps or Azure Maps provider key."
        }
        "degraded" {
            Write-Host "Next action: follow the recovery hints below. During first setup, this usually means importing the Model & Data Package assets."
        }
        "ready" {
            Write-Host "Next action: TowerScout is ready for normal use."
        }
        "fatal" {
            Write-Host "Next action: stop validation and collect support evidence with scripts\status.cmd and scripts\logs.cmd."
        }
        default {
            Write-Host "Next action: keep this PowerShell window open while TowerScout continues starting."
        }
    }
    $components = Get-TowerScoutPropertyValue -InputObject $payload -Name "components"
    $assets = Get-TowerScoutPropertyValue -InputObject $components -Name "assets"
    $assetStatus = Get-TowerScoutPropertyValue -InputObject $assets -Name "status"
    if ($assetStatus) {
        Write-Host "Asset status: $assetStatus"
    }
    $config = Get-TowerScoutPropertyValue -InputObject $components -Name "config"
    $configStatus = Get-TowerScoutPropertyValue -InputObject $config -Name "status"
    if ($configStatus) {
        Write-Host "Config status: $configStatus"
    }
    $runtime = Get-TowerScoutPropertyValue -InputObject $payload -Name "runtime"
    if ($runtime) {
        Write-Host (
            "Runtime: engine={0} device_policy={1} selected_device={2} pytorch_flavor={3}" -f
            (Get-TowerScoutPropertyValue -InputObject $runtime -Name "container_engine"),
            (Get-TowerScoutPropertyValue -InputObject $runtime -Name "device_policy"),
            (Get-TowerScoutPropertyValue -InputObject $runtime -Name "selected_device"),
            (Get-TowerScoutPropertyValue -InputObject $runtime -Name "pytorch_flavor")
        )
    }
    $version = Get-TowerScoutPropertyValue -InputObject $payload -Name "version"
    $imageDigest = Get-TowerScoutPropertyValue -InputObject $version -Name "image_digest"
    if ($imageDigest) {
        Write-Host "Image digest: $imageDigest"
    }
    $recovery = Get-TowerScoutPropertyValue -InputObject $payload -Name "recovery"
    if ($recovery) {
        foreach ($item in $recovery) {
            Write-Host "Recovery: $item"
        }
    }
}

function Test-TowerScoutCudaSelected {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Readiness
    )

    if (-not $Readiness.Reachable -or $null -eq $Readiness.Payload) {
        return $false
    }

    $payload = $Readiness.Payload
    $selectedDevice = ""
    $runtime = Get-TowerScoutPropertyValue -InputObject $payload -Name "runtime"
    $runtimeSelectedDevice = Get-TowerScoutPropertyValue -InputObject $runtime -Name "selected_device"
    if ($runtimeSelectedDevice) {
        $selectedDevice = [string] $runtimeSelectedDevice
    }
    else {
        $components = Get-TowerScoutPropertyValue -InputObject $payload -Name "components"
        $mlRuntime = Get-TowerScoutPropertyValue -InputObject $components -Name "ml_runtime"
        $mlRuntimeSelectedDevice = Get-TowerScoutPropertyValue -InputObject $mlRuntime -Name "selected_device"
        if ($mlRuntimeSelectedDevice) {
            $selectedDevice = [string] $mlRuntimeSelectedDevice
        }
    }

    return $selectedDevice.Trim().ToLowerInvariant() -eq "cuda"
}

function Write-TowerScoutHostDiagnostics {
    param(
        [Parameter(Mandatory = $true)]
        [string] $EngineName
    )

    if ($env:OS -ne "Windows_NT") {
        return
    }

    Write-Host ""
    Write-Host "Windows container runtime diagnostics:"

    $wslCommand = Get-Command "wsl.exe" -ErrorAction SilentlyContinue
    if ($null -eq $wslCommand) {
        Write-Host "- wsl.exe was not found. Docker Desktop or Podman on Windows usually needs WSL2 or Hyper-V/virtualization support."
    }
    else {
        Write-Host "- wsl.exe found at $($wslCommand.Source)."
        try {
            $wslStatus = & wsl.exe --status 2>&1
            foreach ($line in $wslStatus) {
                $normalizedLine = ([string] $line).Replace([string][char]0, "")
                if (-not [string]::IsNullOrWhiteSpace($normalizedLine)) {
                    Write-Host "  $normalizedLine"
                }
            }
        }
        catch {
            Write-Host "  Could not read WSL status: $($_.Exception.Message)"
        }
    }

    if ($EngineName -eq "podman") {
        Write-Host "- For Podman, check the machine state with: podman machine list"
        try {
            $podmanMachine = & podman machine list 2>&1
            foreach ($line in $podmanMachine) {
                $normalizedLine = ([string] $line).Replace([string][char]0, "")
                if (-not [string]::IsNullOrWhiteSpace($normalizedLine)) {
                    Write-Host "  $normalizedLine"
                }
            }
        }
        catch {
            Write-Host "  Could not read Podman machine state: $($_.Exception.Message)"
        }
    }

    if ($EngineName -eq "docker") {
        Write-Host "- For Docker Desktop, confirm Docker Desktop is running and that its WSL2 or Hyper-V backend is healthy."
    }

    Write-Host "- If the engine is managed by local IT, confirm virtualization, WSL2/Hyper-V, endpoint policy, and Compose provider access are approved."
}

if ($TimeoutSeconds -lt 5) {
    throw "TimeoutSeconds must be at least 5."
}
if ($SessionMaxHours -lt 0) {
    throw "SessionMaxHours must be 0 or greater."
}

Initialize-TowerScoutEnvFile -RootPath $repoRoot

$composeCommand = Get-TowerScoutComposeCommand -Engine $Engine
$effectiveEngine = [string] $composeCommand["Executable"]
$packageFlavor = Get-TowerScoutPackagePytorchFlavor -RootPath $repoRoot
if ([string]::IsNullOrWhiteSpace($packageFlavor)) {
    $packageFlavor = "source"
}
$env:TOWERSCOUT_CONTAINER_ENGINE = $effectiveEngine
$env:TOWERSCOUT_PORT = "$Port"
Save-TowerScoutHostHelperLaunchProfile `
    -Engine $effectiveEngine `
    -Gpu $Gpu `
    -AppPort $Port `
    -RootPath $repoRoot `
    -PackageFlavor $packageFlavor | Out-Null
$hostHelperReviewSessionId = Initialize-TowerScoutHostHelperReviewSession `
    -EngineName $effectiveEngine `
    -GpuMode $Gpu `
    -AppPort $Port `
    -RootPath $repoRoot `
    -PackageFlavor $packageFlavor

Write-Host "Starting TowerScout with $effectiveEngine on $appUrl..."
Write-TowerScoutComposeProviderSummary -Engine $effectiveEngine
Set-TowerScoutGpuEnvironment -Gpu $Gpu -Build:$Build
Write-TowerScoutGpuModeSummary -EngineName $effectiveEngine -Gpu $Gpu -Build:$Build
Invoke-TowerScoutStaleContainerGuard -EngineName $effectiveEngine -SessionMaxHours $SessionMaxHours | Out-Null

$composeArgs = @("up", "-d")
if ($Build) {
    $composeArgs += "--build"
}
Invoke-TowerScoutCompose `
    -Engine $effectiveEngine `
    -Build:$Build `
    -Gpu $Gpu `
    -PodmanMachineName $PodmanMachineName `
    -ComposeArguments $composeArgs
if ($script:TowerScoutComposeExitCode -ne 0) {
    if (-not [string]::IsNullOrWhiteSpace($hostHelperReviewSessionId)) {
        Stop-TowerScoutHostHelperReviewSession -RootPath $repoRoot
    }
    Write-Host "TowerScout container startup failed. Check the selected engine, Compose provider, and local permissions."
    Write-TowerScoutHostDiagnostics -EngineName $effectiveEngine
    exit $script:TowerScoutComposeExitCode
}

Write-Host "Waiting for TowerScout readiness at $readinessUrl..."
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$lastState = ""
$lastReadiness = $null

while ((Get-Date) -lt $deadline) {
    $readiness = Get-TowerScoutReadiness -Url $readinessUrl
    $lastReadiness = $readiness

    if ($readiness.Reachable) {
        if ($readiness.State -in @("setup_required", "degraded", "ready")) {
            Write-TowerScoutReadinessSummary -Readiness $readiness
            if ($Gpu -eq "on" -and -not (Test-TowerScoutCudaSelected -Readiness $readiness)) {
                Write-Host "GPU mode is on, but TowerScout readiness did not report selected_device=cuda."
                Write-Host "Check the image flavor, NVIDIA container access, and GPU overlay before continuing."
                Stop-TowerScoutHostHelperReviewSession -RootPath $repoRoot
                exit 1
            }
            if (-not $NoBrowser) {
                Write-Host "Opening TowerScout in your browser..."
                Start-Process $appUrl
            }
            else {
                Write-Host "Browser launch skipped. Open $appUrl when ready."
            }
            exit 0
        }

        if ($readiness.State -eq "fatal") {
            Write-TowerScoutReadinessSummary -Readiness $readiness
            Write-Host "Run scripts\logs.cmd for container logs or scripts\status.cmd for the current readiness payload."
            Stop-TowerScoutHostHelperReviewSession -RootPath $repoRoot
            exit 1
        }
    }

    if ($readiness.State -ne $lastState) {
        Write-TowerScoutReadinessSummary -Readiness $readiness
        $lastState = $readiness.State
    }

    Start-Sleep -Seconds 2
}

Write-Warning "Timed out after $TimeoutSeconds seconds waiting for TowerScout readiness."
if ($lastReadiness -ne $null) {
    Write-TowerScoutReadinessSummary -Readiness $lastReadiness
}
Write-Host "Use scripts\status.cmd to inspect readiness, scripts\logs.cmd -Tail 200 for logs, or scripts\stop.cmd to stop TowerScout."
if (-not [string]::IsNullOrWhiteSpace($hostHelperReviewSessionId)) {
    Stop-TowerScoutHostHelperReviewSession -RootPath $repoRoot
}
exit 2
