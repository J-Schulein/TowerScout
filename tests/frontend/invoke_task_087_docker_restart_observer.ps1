param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^towerscout-task087-[a-z0-9][a-z0-9-]*$")]
    [string] $ProjectName,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int] $AppPort,

    [Parameter(Mandatory = $true)]
    [string] $EdgePath,

    [ValidateRange(30, 600)]
    [int] $TimeoutSeconds = 180,

    [ValidateSet("setup_required", "degraded", "ready")]
    [string] $ExpectedReadinessState = "setup_required"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$composePath = Join-Path $repoRoot "compose.yaml"
$observerPath = Join-Path $PSScriptRoot "test_task_087_docker_restart_edge_observer.js"
$resolvedEdgePath = (Resolve-Path -LiteralPath $EdgePath).Path
if ([System.IO.Path]::GetFileName($resolvedEdgePath).ToLowerInvariant() -ne "msedge.exe") {
    throw "EdgePath must identify msedge.exe."
}

$docker = Get-Command "docker.exe" -CommandType Application -ErrorAction Stop
$node = Get-Command "node.exe" -CommandType Application -ErrorAction Stop

function Get-Task087ContainerId {
    $ids = @(
        & $docker.Source ps -a `
            --filter "label=com.docker.compose.project=$ProjectName" `
            --filter "label=com.docker.compose.service=towerscout" `
            --format "{{.ID}}"
    )
    if ($LASTEXITCODE -ne 0) {
        throw "Docker could not inspect the dedicated Task-087 project."
    }
    $ids = @($ids | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($ids.Count -ne 1) {
        throw "Expected exactly one towerscout container in project '$ProjectName'; found $($ids.Count)."
    }
    return ([string] $ids[0]).Trim()
}

function Assert-Task087ContainerIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ContainerId,

        [switch] $RequireRunning
    )

    $identity = & $docker.Source inspect `
        --format "{{index .Config.Labels `"com.docker.compose.project`"}}|{{index .Config.Labels `"com.docker.compose.service`"}}|{{.State.Running}}" `
        $ContainerId
    if ($LASTEXITCODE -ne 0) {
        throw "Docker could not inspect the dedicated Task-087 container."
    }
    $expectedRunning = if ($RequireRunning) { "true" } else { "false" }
    if (
        ([string] $identity).Trim().ToLowerInvariant() -ne
        ("{0}|towerscout|{1}" -f $ProjectName, $expectedRunning).ToLowerInvariant()
    ) {
        throw "The Docker container identity or running state did not match the requested Task-087 project."
    }
}

$containerId = Get-Task087ContainerId
Assert-Task087ContainerIdentity -ContainerId $containerId -RequireRunning
$publishedPort = @(& $docker.Source port $containerId "5000/tcp")
if (
    $LASTEXITCODE -ne 0 -or
    $publishedPort.Count -ne 1 -or
    ([string] $publishedPort[0]).Trim() -ne "127.0.0.1:$AppPort"
) {
    throw "The dedicated container must publish 127.0.0.1:$AppPort to container port 5000."
}

$runId = [guid]::NewGuid().ToString("N")
$signalPath = Join-Path ([System.IO.Path]::GetTempPath()) "towerscout-task087-$runId.ready"
$stdoutPath = Join-Path ([System.IO.Path]::GetTempPath()) "towerscout-task087-$runId.stdout"
$stderrPath = Join-Path ([System.IO.Path]::GetTempPath()) "towerscout-task087-$runId.stderr"
$observer = $null
$serviceStopped = $false
try {
    $env:TOWERSCOUT_BASE_URL = "http://localhost:$AppPort"
    $env:TOWERSCOUT_ALT_BASE_URL = "http://127.0.0.1:$AppPort"
    $env:TOWERSCOUT_EXECUTABLE_PATH = $resolvedEdgePath
    $env:TOWERSCOUT_BROWSER_READY_SIGNAL = $signalPath
    $env:TOWERSCOUT_RESTART_TRANSITION_TIMEOUT_MS = [string] ($TimeoutSeconds * 1000)
    $env:TOWERSCOUT_EXPECTED_READINESS_STATE = $ExpectedReadinessState

    $observerArgument = '"{0}"' -f $observerPath
    $observer = Start-Process `
        -FilePath $node.Source `
        -ArgumentList @($observerArgument) `
        -WorkingDirectory $repoRoot `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -PassThru

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while (-not (Test-Path -LiteralPath $signalPath)) {
        if ($observer.HasExited) {
            throw "The Edge observer exited before it signaled browser readiness."
        }
        if ((Get-Date) -ge $deadline) {
            throw "Timed out waiting for the Edge observer readiness signal."
        }
        Start-Sleep -Milliseconds 250
    }
    if ($observer.HasExited) {
        throw "The Edge observer exited before Docker restart orchestration began."
    }

    & $docker.Source compose -p $ProjectName -f $composePath stop towerscout
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose could not stop the dedicated Task-087 service."
    }
    $serviceStopped = $true
    Assert-Task087ContainerIdentity -ContainerId $containerId

    & $docker.Source compose -p $ProjectName -f $composePath start towerscout
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose could not restart the dedicated Task-087 service."
    }
    $serviceStopped = $false
    $restartedContainerId = Get-Task087ContainerId
    if ($restartedContainerId -ne $containerId) {
        throw "Docker Compose replaced the dedicated container instead of restarting the verified instance."
    }
    Assert-Task087ContainerIdentity -ContainerId $containerId -RequireRunning

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while (-not $observer.HasExited) {
        if ((Get-Date) -ge $deadline) {
            throw "Timed out waiting for the Edge observer to complete."
        }
        Start-Sleep -Milliseconds 250
    }
    if ($observer.ExitCode -ne 0) {
        throw "The Edge observer failed: $(Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue)"
    }
    Get-Content -LiteralPath $stdoutPath -Raw
}
finally {
    if ($serviceStopped) {
        & $docker.Source compose -p $ProjectName -f $composePath start towerscout | Out-Null
    }
    if ($null -ne $observer) {
        if (-not $observer.HasExited) {
            $observer.Kill()
            $observer.WaitForExit(5000) | Out-Null
        }
        $observer.Dispose()
    }
    foreach ($pathToRemove in @($signalPath, $stdoutPath, $stderrPath)) {
        if (Test-Path -LiteralPath $pathToRemove) {
            Remove-Item -LiteralPath $pathToRemove -Force
        }
    }
}
