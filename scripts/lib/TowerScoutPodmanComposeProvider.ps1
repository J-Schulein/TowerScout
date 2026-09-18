Set-StrictMode -Version Latest
. "$PSScriptRoot\TowerScoutProviderEnvironment.ps1"

function Get-TowerScoutProviderRepoRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

function Get-TowerScoutProviderCatalogPath {
    return (Join-Path (Get-TowerScoutProviderRepoRoot) "scripts\podman-compose-providers.v1.json")
}

function Get-TowerScoutPodmanComposeProviderCatalog {
    $catalogPath = Get-TowerScoutProviderCatalogPath
    if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) {
        throw "Podman Compose provider catalog was not found: $catalogPath"
    }

    return (Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json)
}

function Get-TowerScoutProviderObjectValue {
    param(
        [object] $InputObject,

        [string] $Name
    )

    if ($null -eq $InputObject) {
        return ""
    }
    if ($InputObject.PSObject.Properties.Name -notcontains $Name) {
        return ""
    }

    return [string] $InputObject.PSObject.Properties[$Name].Value
}

function Resolve-TowerScoutProviderCandidatePath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Value
    )

    if (Test-Path -LiteralPath $Value -PathType Leaf) {
        return (Resolve-Path -LiteralPath $Value).Path
    }

    $command = Get-Command $Value -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        return ""
    }

    if ($command.PSObject.Properties.Name -contains "Source" -and -not [string]::IsNullOrWhiteSpace([string] $command.Source)) {
        return [string] $command.Source
    }
    if ($command.PSObject.Properties.Name -contains "Path" -and -not [string]::IsNullOrWhiteSpace([string] $command.Path)) {
        return [string] $command.Path
    }

    return [string] $command.Name
}

function Test-TowerScoutProviderPathDisallowed {
    param(
        [string] $ProviderPath = "",

        [object] $Provider
    )

    if ([string]::IsNullOrWhiteSpace($ProviderPath)) {
        return $true
    }

    $normalized = ([string] $ProviderPath).Replace("/", "\")
    $normalized = $normalized -replace '\\{2,}', '\'
    foreach ($pattern in @($Provider.disallowed_path_patterns)) {
        if ($normalized -match ([string] $pattern)) {
            return $true
        }
    }

    return $false
}

function Invoke-TowerScoutProviderCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ProviderPath,

        [string[]] $Arguments = @()
    )

    $previousErrorActionPreference = $ErrorActionPreference
    $previousNoBytecode = [Environment]::GetEnvironmentVariable("PYTHONDONTWRITEBYTECODE", "Process")
    $ErrorActionPreference = "Continue"
    try {
        $env:PYTHONDONTWRITEBYTECODE = "1"
        $output = & $ProviderPath @Arguments 2>&1
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output = [string]::Join([Environment]::NewLine, @($output))
        }
    }
    catch {
        return [pscustomobject]@{
            ExitCode = 127
            Output = $_.Exception.Message
        }
    }
    finally {
        if ($null -eq $previousNoBytecode) {
            Remove-Item Env:PYTHONDONTWRITEBYTECODE -ErrorAction SilentlyContinue
        }
        else {
            $env:PYTHONDONTWRITEBYTECODE = $previousNoBytecode
        }
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

function Test-TowerScoutApprovedPodmanComposeProvider {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ProviderPath,

        [Parameter(Mandatory = $true)]
        [object] $Provider
    )

    $resolvedPath = Resolve-TowerScoutProviderCandidatePath -Value $ProviderPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return [pscustomobject]@{
            Accepted = $false
            Reason = "provider path was not found"
            Path = $ProviderPath
            Provider = $Provider
        }
    }

    $leafName = [System.IO.Path]::GetFileName($resolvedPath)
    $allowedNames = @($Provider.allowed_executable_names | ForEach-Object { ([string] $_).ToLowerInvariant() })
    if ($allowedNames -notcontains $leafName.ToLowerInvariant()) {
        return [pscustomobject]@{
            Accepted = $false
            Reason = "executable name '$leafName' is not allowlisted for $($Provider.id)"
            Path = $resolvedPath
            Provider = $Provider
        }
    }

    if (Test-TowerScoutProviderPathDisallowed -ProviderPath $resolvedPath -Provider $Provider) {
        return [pscustomobject]@{
            Accepted = $false
            Reason = "provider path is disallowed"
            Path = $resolvedPath
            Provider = $Provider
        }
    }

    $expectedSha256 = (Get-TowerScoutProviderObjectValue -InputObject $Provider -Name "windows_amd64_sha256").Trim().ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($expectedSha256)) {
        $actualSha256 = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualSha256 -ne $expectedSha256) {
            return [pscustomobject]@{
                Accepted = $false
                Reason = "provider SHA-256 did not match the allowlist"
                Path = $resolvedPath
                Provider = $Provider
            }
        }
    }

    foreach ($requiredCommand in @($Provider.required_commands)) {
        $arguments = @($requiredCommand.arguments | ForEach-Object { [string] $_ })
        $result = Invoke-TowerScoutProviderCommand -ProviderPath $resolvedPath -Arguments $arguments
        if ($result.ExitCode -ne 0) {
            return [pscustomobject]@{
                Accepted = $false
                Reason = "required command '$($arguments -join ' ')' failed"
                Path = $resolvedPath
                Provider = $Provider
            }
        }

        $expectedPattern = [string] $requiredCommand.expected_output_pattern
        if (-not [string]::IsNullOrWhiteSpace($expectedPattern) -and $result.Output -notmatch $expectedPattern) {
            return [pscustomobject]@{
                Accepted = $false
                Reason = "required command output did not match $($Provider.display_name)"
                Path = $resolvedPath
                Provider = $Provider
            }
        }
    }

    return [pscustomobject]@{
        Accepted = $true
        Reason = "approved"
        Path = $resolvedPath
        Provider = $Provider
    }
}

function Test-TowerScoutAnyApprovedPodmanComposeProvider {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ProviderPath
    )

    $catalog = Get-TowerScoutPodmanComposeProviderCatalog
    $rejections = New-Object System.Collections.Generic.List[string]
    foreach ($provider in @($catalog.providers)) {
        $check = Test-TowerScoutApprovedPodmanComposeProvider -ProviderPath $ProviderPath -Provider $provider
        if ($check.Accepted) {
            return $check
        }
        [void] $rejections.Add("$($provider.id): $($check.Reason)")
    }

    return [pscustomobject]@{
        Accepted = $false
        Reason = ([string]::Join("; ", @($rejections)))
        Path = $ProviderPath
        Provider = $null
    }
}

function Find-TowerScoutApprovedPodmanComposeProviders {
    $catalog = Get-TowerScoutPodmanComposeProviderCatalog
    $results = New-Object System.Collections.Generic.List[object]
    $seen = @{}

    foreach ($provider in @($catalog.providers)) {
        foreach ($name in @($provider.allowed_executable_names)) {
            foreach ($command in @(Get-Command ([string] $name) -All -ErrorAction SilentlyContinue)) {
                $candidateValue = ""
                if ($command.PSObject.Properties.Name -contains "Source" -and -not [string]::IsNullOrWhiteSpace([string] $command.Source)) {
                    $candidateValue = [string] $command.Source
                }
                elseif ($command.PSObject.Properties.Name -contains "Path" -and -not [string]::IsNullOrWhiteSpace([string] $command.Path)) {
                    $candidateValue = [string] $command.Path
                }
                else {
                    $candidateValue = [string] $command.Name
                }

                $candidatePath = Resolve-TowerScoutProviderCandidatePath -Value $candidateValue
                if ([string]::IsNullOrWhiteSpace($candidatePath)) {
                    continue
                }
                $key = $candidatePath.ToLowerInvariant()
                if ($seen.ContainsKey($key)) {
                    continue
                }
                $seen[$key] = $true

                $check = Test-TowerScoutApprovedPodmanComposeProvider -ProviderPath $candidatePath -Provider $provider
                if ($check.Accepted) {
                    [void] $results.Add($check)
                }
            }
        }
    }

    foreach ($result in $results) {
        $result
    }
}

function Get-TowerScoutProviderEnvironmentSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]] $Contents
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha256.ComputeHash($Contents))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function ConvertTo-TowerScoutProviderEnvironmentPlan {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]] $SourceContents,

        [Parameter(Mandatory = $true)]
        [string] $ProviderPath,

        [Parameter(Mandatory = $true)]
        [bool] $OriginalPresent
    )

    $maximumBytes = 262144
    if ($SourceContents.Length -gt $maximumBytes -or [string]::IsNullOrWhiteSpace($ProviderPath)) {
        throw "The package environment file cannot be updated safely."
    }
    foreach ($character in $ProviderPath.ToCharArray()) {
        if (
            [int] $character -lt 0x20 -or
            [int] $character -eq 0x7F -or
            $character -in @([char]0x85, [char]0x2028, [char]0x2029)
        ) {
            throw "The package environment file cannot be updated safely."
        }
    }

    $hasBom = (
        $SourceContents.Length -ge 3 -and
        $SourceContents[0] -eq 0xEF -and
        $SourceContents[1] -eq 0xBB -and
        $SourceContents[2] -eq 0xBF
    )
    $offset = if ($hasBom) { 3 } else { 0 }
    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    try {
        $text = $encoding.GetString($SourceContents, $offset, $SourceContents.Length - $offset)
    }
    catch [System.Text.DecoderFallbackException] {
        throw "The package environment file cannot be updated safely."
    }
    if (
        $text.Contains([char]0) -or
        $text.Contains([char]0xFEFF) -or
        $text.Contains([char]0x85) -or
        $text.Contains([char]0x2028) -or
        $text.Contains([char]0x2029) -or
        $text.Replace("`r`n", "").Contains("`r")
    ) {
        throw "The package environment file cannot be updated safely."
    }
    foreach ($character in $text.ToCharArray()) {
        if ([int] $character -lt 0x20 -and $character -notin @("`t", "`r", "`n")) {
            throw "The package environment file cannot be updated safely."
        }
    }

    $settingName = "PODMAN_COMPOSE_PROVIDER"
    $selectedNewline = if ($text.Contains("`r`n") -or $text.Length -eq 0) { "`r`n" } else { "`n" }
    $hadTrailingNewline = $text.EndsWith("`n")
    $seen = $false
    $builder = New-Object System.Text.StringBuilder
    $position = 0
    while ($position -lt $text.Length) {
        $lineFeed = $text.IndexOf("`n", $position, [System.StringComparison]::Ordinal)
        if ($lineFeed -lt 0) {
            $next = $text.Length
        }
        else {
            $next = $lineFeed + 1
        }
        $line = $text.Substring($position, $next - $position)
        $ending = ""
        $content = $line
        if ($line.EndsWith("`r`n")) {
            $ending = "`r`n"
            $content = $line.Substring(0, $line.Length - 2)
        }
        elseif ($line.EndsWith("`n")) {
            $ending = "`n"
            $content = $line.Substring(0, $line.Length - 1)
        }

        if (-not $content.TrimStart().StartsWith("#", [System.StringComparison]::Ordinal)) {
            $equals = $content.IndexOf("=", [System.StringComparison]::Ordinal)
            $name = if ($equals -ge 0) { $content.Substring(0, $equals) } else { $content }
            $key = $name.Trim()
            if ($key.Equals($settingName, [System.StringComparison]::OrdinalIgnoreCase)) {
                if (
                    $seen -or
                    $equals -lt 0 -or
                    -not $key.Equals($settingName, [System.StringComparison]::Ordinal)
                ) {
                    throw "The package environment file cannot be updated safely."
                }
                [void] $builder.Append($name)
                [void] $builder.Append("=")
                [void] $builder.Append($ProviderPath)
                [void] $builder.Append($ending)
                $seen = $true
            }
            else {
                $tokens = [regex]::Matches($name, "[A-Za-z_][A-Za-z0-9_]*")
                foreach ($token in $tokens) {
                    if ($token.Value.Equals($settingName, [System.StringComparison]::OrdinalIgnoreCase)) {
                        throw "The package environment file cannot be updated safely."
                    }
                }
                [void] $builder.Append($line)
            }
        }
        else {
            [void] $builder.Append($line)
        }
        $position = $next
    }

    if (-not $seen) {
        if ($builder.Length -gt 0 -and -not $hadTrailingNewline) {
            [void] $builder.Append($selectedNewline)
        }
        [void] $builder.Append($settingName)
        [void] $builder.Append("=")
        [void] $builder.Append($ProviderPath)
        [void] $builder.Append($selectedNewline)
    }

    $encoded = $encoding.GetBytes($builder.ToString())
    if ($hasBom) {
        $candidate = New-Object byte[] ($encoded.Length + 3)
        $candidate[0] = 0xEF
        $candidate[1] = 0xBB
        $candidate[2] = 0xBF
        [System.Array]::Copy($encoded, 0, $candidate, 3, $encoded.Length)
    }
    else {
        $candidate = $encoded
    }
    if ($candidate.Length -lt 1 -or $candidate.Length -gt $maximumBytes) {
        throw "The package environment file cannot be updated safely."
    }

    return [pscustomobject]@{
        SourceContents = $SourceContents
        SourceSha256 = Get-TowerScoutProviderEnvironmentSha256 -Contents $SourceContents
        OriginalContents = if ($OriginalPresent) { $SourceContents } else { $null }
        CandidateContents = $candidate
        OriginalSha256 = if ($OriginalPresent) {
            Get-TowerScoutProviderEnvironmentSha256 -Contents $SourceContents
        }
        else {
            "absent"
        }
        CandidateSha256 = Get-TowerScoutProviderEnvironmentSha256 -Contents $candidate
    }
}

function Set-TowerScoutPodmanComposeProviderEnv {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ProviderPath,

        [string] $RootPath = $(Get-TowerScoutProviderRepoRoot),

        [switch] $Apply
    )

    $resolvedPath = Resolve-TowerScoutProviderCandidatePath -Value $ProviderPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        throw "The provider path was not found."
    }

    $envPath = Join-Path $RootPath ".env"
    $originalPresent = Test-Path -LiteralPath $envPath -PathType Leaf
    if ($originalPresent) {
        $sourceContents = [System.IO.File]::ReadAllBytes($envPath)
    }
    else {
        $templatePath = Join-Path $RootPath ".env.example"
        if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
            throw "The authenticated package environment template is unavailable."
        }
        $sourceContents = [System.IO.File]::ReadAllBytes($templatePath)
    }
    $plan = ConvertTo-TowerScoutProviderEnvironmentPlan `
        -SourceContents $sourceContents `
        -ProviderPath $resolvedPath `
        -OriginalPresent $originalPresent

    if (-not $Apply) {
        Write-Host "The PODMAN_COMPOSE_PROVIDER update is ready for review."
        return [pscustomobject]@{
            Applied = $false
        }
    }

    $result = Invoke-TowerScoutProviderEnvironmentReplacement -RootPath $RootPath -Plan $plan
    if ($result.Applied -ne $true) {
        throw "The provider environment update could not be verified."
    }
    Write-Host "Updated PODMAN_COMPOSE_PROVIDER in .env."
    return [pscustomobject]@{ Applied = $true }
}
