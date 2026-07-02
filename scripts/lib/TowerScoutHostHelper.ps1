Set-StrictMode -Version Latest

$script:TowerScoutHostHelperVersion = "0.1.0-gate1"
$script:TowerScoutHostHelperReadTimeoutMs = 5000
$script:TowerScoutHostHelperMaxRequestLineLength = 4096
$script:TowerScoutHostHelperMaxHeaderLines = 64
$script:TowerScoutHostHelperMaxHeaderBytes = 16384

function New-TowerScoutHostHelperToken {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }

    return ([Convert]::ToBase64String($bytes).TrimEnd("=") -replace "\+", "-" -replace "/", "_")
}

function Get-TowerScoutHostHelperObjectValue {
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

function Set-TowerScoutHostHelperObjectValue {
    param(
        [Parameter(Mandatory = $true)]
        [object] $InputObject,

        [Parameter(Mandatory = $true)]
        [string] $Name,

        [object] $Value
    )

    $InputObject | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
}

function New-TowerScoutHostHelperSessionId {
    return [guid]::NewGuid().ToString("N")
}

function Resolve-TowerScoutHostHelperSessionId {
    param(
        [string] $SessionId = ""
    )

    if ([string]::IsNullOrWhiteSpace($SessionId)) {
        return New-TowerScoutHostHelperSessionId
    }

    $normalized = $SessionId.Trim().ToLowerInvariant()
    if ($normalized -notmatch "^[a-f0-9]{32}$") {
        throw "HelperSessionId must be a 32-character hexadecimal value."
    }

    return $normalized
}

function Get-TowerScoutHostHelperPackageRootIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PackageRoot
    )

    $normalizedRoot = ([System.IO.Path]::GetFullPath($PackageRoot)).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ).ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalizedRoot)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($bytes)
    }
    finally {
        $sha256.Dispose()
    }

    return (($hashBytes | ForEach-Object { $_.ToString("x2") }) -join "").Substring(0, 16)
}

function Get-TowerScoutHostHelperStateDirectory {
    param(
        [string] $RootPath = $(Resolve-Path (Join-Path $PSScriptRoot "..\.."))
    )

    $resolvedRoot = (Resolve-Path -LiteralPath $RootPath).Path
    return (Join-Path $resolvedRoot ".towerscout-runtime\host-helper")
}

function Save-TowerScoutHostHelperLaunchProfile {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("docker", "podman")]
        [string] $Engine,

        [Parameter(Mandatory = $true)]
        [ValidateSet("off", "auto", "on")]
        [string] $Gpu,

        [Parameter(Mandatory = $true)]
        [int] $AppPort,

        [string] $RootPath = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),

        [string] $PackageFlavor = "source"
    )

    if ($AppPort -lt 1 -or $AppPort -gt 65535) {
        throw "AppPort must be between 1 and 65535."
    }

    $resolvedRoot = (Resolve-Path -LiteralPath $RootPath).Path
    $stateDirectory = Get-TowerScoutHostHelperStateDirectory -RootPath $resolvedRoot
    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null

    $profilePath = Join-Path $stateDirectory "launch-profile.json"
    $launchProfile = [pscustomobject]@{
        helper_version = $script:TowerScoutHostHelperVersion
        created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        engine = $Engine
        gpu = $Gpu
        app_port = $AppPort
        base_url = "http://localhost:$AppPort"
        package_flavor = $PackageFlavor
        package_root_identity = Get-TowerScoutHostHelperPackageRootIdentity -PackageRoot $resolvedRoot
        state = "profile_captured"
    }

    $launchProfile | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $profilePath -Encoding ASCII
    return $profilePath
}

function Save-TowerScoutHostHelperSession {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Profile,

        [string] $RootPath = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),

        [string] $Token = ""
    )

    $stateDirectory = Get-TowerScoutHostHelperStateDirectory -RootPath $RootPath
    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null

    $sessionPath = Join-Path $stateDirectory ("session-{0}.json" -f $Profile.HelperSessionId)
    $tokenFileName = Get-TowerScoutHostHelperObjectValue -InputObject $Profile -Name "TokenFileName"
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $tokenFileName = "token-{0}.secret" -f $Profile.HelperSessionId
        $tokenPath = Join-Path $stateDirectory $tokenFileName
        Set-Content -LiteralPath $tokenPath -Value $Token -Encoding ASCII -NoNewline
        Set-TowerScoutHostHelperObjectValue -InputObject $Profile -Name "TokenFileName" -Value $tokenFileName
        Set-TowerScoutHostHelperObjectValue -InputObject $Profile -Name "TokenPath" -Value $tokenPath
    }

    $session = [pscustomobject]@{
        helper_version = [string] $Profile.HelperVersion
        helper_session_id = [string] $Profile.HelperSessionId
        created_at_utc = [string] $Profile.CreatedAtUtc
        engine = [string] $Profile.Engine
        gpu = [string] $Profile.Gpu
        app_port = [int] $Profile.AppPort
        helper_port = [int] $Profile.HelperPort
        package_flavor = [string] $Profile.PackageFlavor
        package_root_identity = Get-TowerScoutHostHelperPackageRootIdentity -PackageRoot $Profile.PackageRoot
        token_file = $tokenFileName
        state = "active"
    }

    $session | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $sessionPath -Encoding ASCII
    $Profile | Add-Member -NotePropertyName "SessionPath" -NotePropertyValue $sessionPath -Force
    return $sessionPath
}

function Clear-TowerScoutHostHelperSession {
    param(
        [string] $RootPath = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),

        [string] $SessionId = ""
    )

    $stateDirectory = Get-TowerScoutHostHelperStateDirectory -RootPath $RootPath
    if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
        return [pscustomobject]@{
            cleared = 0
            state = "no_sessions"
        }
    }

    $normalizedSessionId = if ([string]::IsNullOrWhiteSpace($SessionId)) { "" } else { Resolve-TowerScoutHostHelperSessionId -SessionId $SessionId }
    $sessionFilter = if ([string]::IsNullOrWhiteSpace($normalizedSessionId)) { "session-*.json" } else { "session-$normalizedSessionId.json" }
    $tokenFilter = if ([string]::IsNullOrWhiteSpace($normalizedSessionId)) { "token-*.secret" } else { "token-$normalizedSessionId.secret" }
    $sessionFiles = @(Get-ChildItem -LiteralPath $stateDirectory -Filter $sessionFilter -File -ErrorAction SilentlyContinue)
    $tokenFiles = @(Get-ChildItem -LiteralPath $stateDirectory -Filter $tokenFilter -File -ErrorAction SilentlyContinue)
    foreach ($file in @($sessionFiles + $tokenFiles)) {
        Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
    }

    return [pscustomobject]@{
        cleared = $sessionFiles.Count
        token_files_cleared = $tokenFiles.Count
        state = "invalidated"
    }
}

function Test-TowerScoutHostHelperSessionActive {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Profile
    )

    $sessionPath = Get-TowerScoutHostHelperObjectValue -InputObject $Profile -Name "SessionPath"
    if ([string]::IsNullOrWhiteSpace($sessionPath)) {
        return $true
    }

    return (Test-Path -LiteralPath $sessionPath -PathType Leaf)
}

function New-TowerScoutHostHelperRuntimeProfile {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("docker", "podman")]
        [string] $Engine,

        [Parameter(Mandatory = $true)]
        [ValidateSet("off", "auto", "on")]
        [string] $Gpu,

        [Parameter(Mandatory = $true)]
        [int] $AppPort,

        [string] $PackageRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),

        [string] $PackageFlavor = "source",

        [string[]] $AllowedOrigins = @(),

        [int] $HelperPort = 0,

        [string] $HelperSessionId = ""
    )

    if ($AppPort -lt 1 -or $AppPort -gt 65535) {
        throw "AppPort must be between 1 and 65535."
    }
    if ($HelperPort -lt 0 -or $HelperPort -gt 65535) {
        throw "HelperPort must be 0 or between 1 and 65535."
    }

    $resolvedRoot = (Resolve-Path -LiteralPath $PackageRoot).Path
    if ($AllowedOrigins.Count -eq 0) {
        $AllowedOrigins = @(
            "http://localhost:$AppPort",
            "http://127.0.0.1:$AppPort"
        )
    }
    $resolvedSessionId = Resolve-TowerScoutHostHelperSessionId -SessionId $HelperSessionId

    return [pscustomobject]@{
        HelperVersion = $script:TowerScoutHostHelperVersion
        HelperSessionId = $resolvedSessionId
        CreatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        Engine = $Engine
        Gpu = $Gpu
        AppPort = $AppPort
        BaseUrl = "http://localhost:$AppPort"
        PackageRoot = $resolvedRoot
        PackageFlavor = $PackageFlavor
        AllowedOrigins = @($AllowedOrigins)
        HelperPort = $HelperPort
    }
}

function ConvertTo-TowerScoutHostHelperPublicRuntimeProfile {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Profile
    )

    return [pscustomobject]@{
        helper_version = [string] $Profile.HelperVersion
        state = "ready"
        runtime = [pscustomobject]@{
            engine = [string] $Profile.Engine
            gpu = [string] $Profile.Gpu
            app_port = [int] $Profile.AppPort
            package_flavor = [string] $Profile.PackageFlavor
        }
        capabilities = [pscustomobject]@{
            provider_tls_repair = $false
            podman_provider_repair = $false
            max_active_operations = 1
        }
    }
}

function Test-TowerScoutHostHelperOrigin {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Profile,

        [string] $Origin = ""
    )

    if ([string]::IsNullOrWhiteSpace($Origin)) {
        return $false
    }

    foreach ($allowedOrigin in @($Profile.AllowedOrigins)) {
        if ([string]::Equals($Origin, [string] $allowedOrigin, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Read-TowerScoutHostHelperRequest {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Stream] $Stream
    )

    $reader = New-Object System.IO.StreamReader($Stream, [System.Text.Encoding]::ASCII, $false, 1024, $true)
    $requestLine = $reader.ReadLine()
    if ([string]::IsNullOrWhiteSpace($requestLine)) {
        throw "The helper request was empty."
    }
    if ($requestLine.Length -gt $script:TowerScoutHostHelperMaxRequestLineLength) {
        throw "The helper request line was too large."
    }

    $parts = $requestLine.Split([char[]] @(" "), [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($parts.Count -lt 3) {
        throw "The helper request line was invalid."
    }

    $headers = @{}
    $headerLines = 0
    $headerBytes = 0
    while ($true) {
        $line = $reader.ReadLine()
        if ($null -eq $line -or $line.Length -eq 0) {
            break
        }
        $headerLines += 1
        $headerBytes += [System.Text.Encoding]::ASCII.GetByteCount($line)
        if ($headerLines -gt $script:TowerScoutHostHelperMaxHeaderLines -or $headerBytes -gt $script:TowerScoutHostHelperMaxHeaderBytes) {
            throw "The helper request headers were too large."
        }

        $separatorIndex = $line.IndexOf(":")
        if ($separatorIndex -le 0) {
            continue
        }

        $name = $line.Substring(0, $separatorIndex).Trim().ToLowerInvariant()
        $value = $line.Substring($separatorIndex + 1).Trim()
        $headers[$name] = $value
    }

    return [pscustomobject]@{
        Method = ([string] $parts[0]).ToUpperInvariant()
        Path = [string] $parts[1]
        Headers = $headers
    }
}

function Write-TowerScoutHostHelperResponse {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Stream] $Stream,

        [Parameter(Mandatory = $true)]
        [int] $StatusCode,

        [Parameter(Mandatory = $true)]
        [string] $Reason,

        [object] $Body = @{},

        [string] $AccessControlAllowOrigin = ""
    )

    $json = ($Body | ConvertTo-Json -Depth 8 -Compress)
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $lines = @(
        "HTTP/1.1 $StatusCode $Reason",
        "Content-Type: application/json; charset=utf-8",
        "Content-Length: $($bodyBytes.Length)",
        "Cache-Control: no-store",
        "X-Content-Type-Options: nosniff",
        "Connection: close"
    )
    if (-not [string]::IsNullOrWhiteSpace($AccessControlAllowOrigin)) {
        $lines += @(
            "Access-Control-Allow-Origin: $AccessControlAllowOrigin",
            "Access-Control-Allow-Headers: X-TowerScout-Helper-Token, Content-Type",
            "Access-Control-Allow-Methods: GET, OPTIONS",
            "Vary: Origin"
        )
    }

    $headerText = ([string]::Join("`r`n", $lines)) + "`r`n`r`n"
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($headerText)
    $Stream.Write($headerBytes, 0, $headerBytes.Length)
    $Stream.Write($bodyBytes, 0, $bodyBytes.Length)
    $Stream.Flush()
}

function Invoke-TowerScoutHostHelperRequest {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.Sockets.TcpClient] $Client,

        [Parameter(Mandatory = $true)]
        [object] $Profile,

        [Parameter(Mandatory = $true)]
        [string] $Token
    )

    try {
        $Client.ReceiveTimeout = $script:TowerScoutHostHelperReadTimeoutMs
        $Client.SendTimeout = $script:TowerScoutHostHelperReadTimeoutMs
        $stream = $Client.GetStream()
        $remoteEndpoint = $Client.Client.RemoteEndPoint
        if ($null -eq $remoteEndpoint -or -not [System.Net.IPAddress]::IsLoopback($remoteEndpoint.Address)) {
            Write-TowerScoutHostHelperResponse `
                -Stream $stream `
                -StatusCode 403 `
                -Reason "Forbidden" `
                -Body @{ state = "rejected_non_loopback" }
            return
        }

        try {
            $request = Read-TowerScoutHostHelperRequest -Stream $stream
        }
        catch {
            Write-TowerScoutHostHelperResponse `
                -Stream $stream `
                -StatusCode 400 `
                -Reason "Bad Request" `
                -Body @{ state = "rejected_bad_request" }
            return
        }

        $path = ([string] $request.Path).Split([char[]] @("?"), 2)[0]
        $origin = [string] $request.Headers["origin"]
        $originAllowed = Test-TowerScoutHostHelperOrigin -Profile $Profile -Origin $origin
        $corsOrigin = if ($originAllowed) { $origin } else { "" }

        if (-not $originAllowed) {
            Write-TowerScoutHostHelperResponse `
                -Stream $stream `
                -StatusCode 403 `
                -Reason "Forbidden" `
                -Body @{ state = "rejected_origin" }
            return
        }

        if (-not (Test-TowerScoutHostHelperSessionActive -Profile $Profile)) {
            Write-TowerScoutHostHelperResponse `
                -Stream $stream `
                -StatusCode 410 `
                -Reason "Gone" `
                -Body @{ state = "session_invalidated" } `
                -AccessControlAllowOrigin $corsOrigin
            return
        }

        if ($request.Method -eq "OPTIONS") {
            if ($path -notin @("/health", "/runtime-profile")) {
                Write-TowerScoutHostHelperResponse `
                    -Stream $stream `
                    -StatusCode 404 `
                    -Reason "Not Found" `
                    -Body @{ state = "rejected_unknown_endpoint" } `
                    -AccessControlAllowOrigin $corsOrigin
                return
            }

            Write-TowerScoutHostHelperResponse `
                -Stream $stream `
                -StatusCode 200 `
                -Reason "OK" `
                -Body @{ state = "cors_preflight_ok" } `
                -AccessControlAllowOrigin $corsOrigin
            return
        }

        $providedToken = [string] $request.Headers["x-towerscout-helper-token"]
        if ([string]::IsNullOrWhiteSpace($providedToken) -or -not [string]::Equals($providedToken, $Token, [System.StringComparison]::Ordinal)) {
            Write-TowerScoutHostHelperResponse `
                -Stream $stream `
                -StatusCode 401 `
                -Reason "Unauthorized" `
                -Body @{ state = "rejected_token" } `
                -AccessControlAllowOrigin $corsOrigin
            return
        }

        if ($request.Method -ne "GET") {
            Write-TowerScoutHostHelperResponse `
                -Stream $stream `
                -StatusCode 405 `
                -Reason "Method Not Allowed" `
                -Body @{ state = "rejected_method" } `
                -AccessControlAllowOrigin $corsOrigin
            return
        }

        switch ($path) {
            "/health" {
                Write-TowerScoutHostHelperResponse `
                    -Stream $stream `
                    -StatusCode 200 `
                    -Reason "OK" `
                    -Body (ConvertTo-TowerScoutHostHelperPublicRuntimeProfile -Profile $Profile) `
                    -AccessControlAllowOrigin $corsOrigin
                return
            }
            "/runtime-profile" {
                Write-TowerScoutHostHelperResponse `
                    -Stream $stream `
                    -StatusCode 200 `
                    -Reason "OK" `
                    -Body (ConvertTo-TowerScoutHostHelperPublicRuntimeProfile -Profile $Profile) `
                    -AccessControlAllowOrigin $corsOrigin
                return
            }
            default {
                Write-TowerScoutHostHelperResponse `
                    -Stream $stream `
                    -StatusCode 404 `
                    -Reason "Not Found" `
                    -Body @{ state = "rejected_unknown_endpoint" } `
                    -AccessControlAllowOrigin $corsOrigin
            }
        }
    }
    finally {
        $Client.Close()
    }
}

function Start-TowerScoutHostHelper {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Profile,

        [Parameter(Mandatory = $true)]
        [string] $Token,

        [int] $HelperPort = 0,

        [int] $MaxRequests = 0
    )

    if ($HelperPort -lt 0 -or $HelperPort -gt 65535) {
        throw "HelperPort must be 0 or between 1 and 65535."
    }
    if ($MaxRequests -lt 0) {
        throw "MaxRequests must be 0 or greater."
    }

    $address = [System.Net.IPAddress]::Parse("127.0.0.1")
    $listener = New-Object System.Net.Sockets.TcpListener($address, $HelperPort)
    $handled = 0
    try {
        $listener.Start()
        $boundPort = ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
        Set-TowerScoutHostHelperObjectValue -InputObject $Profile -Name "HelperPort" -Value $boundPort
        if (-not [string]::IsNullOrWhiteSpace((Get-TowerScoutHostHelperObjectValue -InputObject $Profile -Name "SessionPath"))) {
            Save-TowerScoutHostHelperSession -Profile $Profile | Out-Null
        }

        while (($MaxRequests -eq 0 -or $handled -lt $MaxRequests) -and (Test-TowerScoutHostHelperSessionActive -Profile $Profile)) {
            if (-not $listener.Pending()) {
                Start-Sleep -Milliseconds 200
                continue
            }

            $client = $listener.AcceptTcpClient()
            Invoke-TowerScoutHostHelperRequest -Client $client -Profile $Profile -Token $Token
            $handled += 1
        }
    }
    finally {
        $listener.Stop()
    }
}

function Invoke-TowerScoutHostHelperSelfTestRequest {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.Sockets.TcpListener] $Listener,

        [Parameter(Mandatory = $true)]
        [object] $Profile,

        [Parameter(Mandatory = $true)]
        [string] $ServerToken,

        [string] $RequestToken = "",

        [string] $Origin = "http://localhost:5000",

        [string] $Path = "/health",

        [ValidateSet("GET", "POST", "OPTIONS")]
        [string] $Method = "GET"
    )

    $port = ([System.Net.IPEndPoint] $Listener.LocalEndpoint).Port
    $accept = $Listener.BeginAcceptTcpClient($null, $null)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.Connect([System.Net.IPAddress]::Loopback, $port)
        $stream = $client.GetStream()
        $lines = @(
            "$Method $Path HTTP/1.1",
            "Host: 127.0.0.1",
            "Origin: $Origin",
            "Connection: close"
        )
        if (-not [string]::IsNullOrWhiteSpace($RequestToken)) {
            $lines += "X-TowerScout-Helper-Token: $RequestToken"
        }
        if ($Method -eq "OPTIONS") {
            $lines += "Access-Control-Request-Method: GET"
            $lines += "Access-Control-Request-Headers: X-TowerScout-Helper-Token"
        }

        $requestText = ([string]::Join("`r`n", $lines)) + "`r`n`r`n"
        $requestBytes = [System.Text.Encoding]::ASCII.GetBytes($requestText)
        $stream.Write($requestBytes, 0, $requestBytes.Length)
        $stream.Flush()

        $serverClient = $Listener.EndAcceptTcpClient($accept)
        Invoke-TowerScoutHostHelperRequest -Client $serverClient -Profile $Profile -Token $ServerToken

        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
        $raw = $reader.ReadToEnd()
    }
    finally {
        $client.Close()
    }

    $statusCode = 0
    if ($raw -match "^HTTP/\d\.\d\s+(\d{3})") {
        $statusCode = [int] $Matches[1]
    }

    $headers = @{}
    $headerEnd = $raw.IndexOf("`r`n`r`n")
    if ($headerEnd -ge 0) {
        $headerText = $raw.Substring(0, $headerEnd)
        foreach ($line in @($headerText -split "`r`n" | Select-Object -Skip 1)) {
            $separatorIndex = ([string] $line).IndexOf(":")
            if ($separatorIndex -le 0) {
                continue
            }
            $name = ([string] $line).Substring(0, $separatorIndex).Trim().ToLowerInvariant()
            $value = ([string] $line).Substring($separatorIndex + 1).Trim()
            $headers[$name] = $value
        }
    }

    $body = $null
    $bodyStart = $raw.IndexOf("`r`n`r`n")
    if ($bodyStart -ge 0) {
        $bodyText = $raw.Substring($bodyStart + 4)
        if (-not [string]::IsNullOrWhiteSpace($bodyText)) {
            try {
                $body = $bodyText | ConvertFrom-Json
            }
            catch {
                $body = $null
            }
        }
    }

    return [pscustomobject]@{
        StatusCode = $statusCode
        Headers = $headers
        Body = $body
    }
}

function Invoke-TowerScoutHostHelperSelfTest {
    $token = New-TowerScoutHostHelperToken
    $profile = New-TowerScoutHostHelperRuntimeProfile `
        -Engine "docker" `
        -Gpu "off" `
        -AppPort 5000 `
        -PackageFlavor "self-test"
    $invalidatedProfile = New-TowerScoutHostHelperRuntimeProfile `
        -Engine "docker" `
        -Gpu "off" `
        -AppPort 5000 `
        -PackageFlavor "self-test"
    Set-TowerScoutHostHelperObjectValue `
        -InputObject $invalidatedProfile `
        -Name "SessionPath" `
        -Value (Join-Path (Get-TowerScoutHostHelperStateDirectory) "missing-session.json")

    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse("127.0.0.1"), 0)
    $listener.Start()
    try {
        $results = @(
            [pscustomobject]@{
                Scenario = "authorized_health"
                Response = (Invoke-TowerScoutHostHelperSelfTestRequest -Listener $listener -Profile $profile -ServerToken $token -RequestToken $token)
                Expected = 200
            },
            [pscustomobject]@{
                Scenario = "wrong_token"
                Response = (Invoke-TowerScoutHostHelperSelfTestRequest -Listener $listener -Profile $profile -ServerToken $token -RequestToken "wrong-token")
                Expected = 401
            },
            [pscustomobject]@{
                Scenario = "wrong_origin"
                Response = (Invoke-TowerScoutHostHelperSelfTestRequest -Listener $listener -Profile $profile -ServerToken $token -RequestToken $token -Origin "http://example.invalid")
                Expected = 403
            },
            [pscustomobject]@{
                Scenario = "unknown_endpoint"
                Response = (Invoke-TowerScoutHostHelperSelfTestRequest -Listener $listener -Profile $profile -ServerToken $token -RequestToken $token -Path "/unknown")
                Expected = 404
            },
            [pscustomobject]@{
                Scenario = "cors_preflight"
                Response = (Invoke-TowerScoutHostHelperSelfTestRequest -Listener $listener -Profile $profile -ServerToken $token -Method "OPTIONS")
                Expected = 200
            },
            [pscustomobject]@{
                Scenario = "invalidated_session"
                Response = (Invoke-TowerScoutHostHelperSelfTestRequest -Listener $listener -Profile $invalidatedProfile -ServerToken $token -RequestToken $token)
                Expected = 410
            }
        )
    }
    finally {
        $listener.Stop()
    }

    foreach ($result in $results) {
        if ($result.Response.StatusCode -ne $result.Expected) {
            throw "Host helper self-test scenario '$($result.Scenario)' returned $($result.Response.StatusCode); expected $($result.Expected)."
        }
    }
    $corsPreflight = @($results | Where-Object { $_.Scenario -eq "cors_preflight" } | Select-Object -First 1)
    if ($corsPreflight.Count -ne 1 -or [string] $corsPreflight[0].Response.Headers["access-control-allow-methods"] -ne "GET, OPTIONS") {
        throw "Host helper self-test did not return the expected GET-only CORS method policy."
    }

    return [pscustomobject]@{
        result = "passed"
        helper_version = $script:TowerScoutHostHelperVersion
        listener = "loopback"
        scenarios = @($results | ForEach-Object {
            [pscustomobject]@{
                name = $_.Scenario
                status_code = $_.Response.StatusCode
                state = if ($null -ne $_.Response.Body) { [string] $_.Response.Body.state } else { "" }
            }
        })
        redaction_check = "no tokens, helper listener ports, local paths, provider keys, certificate details, or raw subprocess output returned"
    }
}
