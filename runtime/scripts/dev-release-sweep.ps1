#Requires -Version 7
<#
.SYNOPSIS
  Sweep the npm dev CLI against the development server using isolated data.
  Run only in GitHub Actions; the default port would disrupt a developer runtime.
  Authenticate shutdown of the previous test runtime before switching libraries.
.DESCRIPTION
  Use disposable accounts. Keep keys in the isolated secrets directory, never reports.
  Usage: pwsh -NoProfile -File scripts/dev-release-sweep.ps1
#>
[CmdletBinding()]
param(
    [string]$Server = $env:RSRS_DEV_SERVER_ADDR,
    [string]$Package = 'rsrs-cli@dev',
    [string]$Root = '',
    [string]$Exe = '',
    [string]$ExpectVersion = '',
    [switch]$DeferSupplemental
)

$ErrorActionPreference = 'Stop'

# The taxonomy parent and the cause/action/result markers are built from code points so this
# script stays pure ASCII while still producing the exact values the store expects.
$TX_DEV = [string]::Join('', @(0x7F16, 0x7A0B, 0x5F00, 0x53D1 | ForEach-Object { [char]$_ }))
$MARK_CAUSE = [string]::Join('', @(0x3010, 0x524D, 0x56E0, 0x3011 | ForEach-Object { [char]$_ }))
$MARK_ACTION = [string]::Join('', @(0x3010, 0x884C, 0x4E3A, 0x3011 | ForEach-Object { [char]$_ }))
$MARK_RESULT = [string]::Join('', @(0x3010, 0x540E, 0x679C, 0x3011 | ForEach-Object { [char]$_ }))
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Release smoke may run only in GitHub Actions.' }
if ($Server -cne 'https://api-dev.rsrs.rs') { throw 'Release smoke requires exactly https://api-dev.rsrs.rs.' }
if (-not $Exe -or $ExpectVersion -notmatch '^\d+\.\d+\.\d+(-dev\.\d+)?$') {
    throw 'Release smoke requires an exact CI artifact via -Exe and its -ExpectVersion.'
}
if ($env:CLI_SHA -notmatch '^[0-9a-fA-F]{40}$') { throw 'CLI_SHA must identify the verified artifact source commit.' }
if ([string]::IsNullOrWhiteSpace($env:RSRS_DEV_SERVER_ADDR) -or $Server -ne $env:RSRS_DEV_SERVER_ADDR) {
    throw 'Configure RSRS_DEV_SERVER_ADDR with the approved development server before running this sweep.'
}
$pkgMatch = [regex]::Match($Package, '^rsrs-cli@(dev|\d+\.\d+\.\d+(-dev\.\d+)?)$')
if (-not $pkgMatch.Success) {
    throw "Refused: the package must be rsrs-cli@dev or rsrs-cli@x.y.z[-dev.n], got $Package"
}
$requested = $pkgMatch.Groups[1].Value

$stamp = "$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
if (-not $Root) {
    if ($env:RUNNER_TEMP) {
        $Root = Join-Path $env:RUNNER_TEMP "om-dev-sweep-$stamp"
    } elseif (Test-Path 'E:\tmp_rust_target') {
        $Root = "E:\tmp_rust_target\om-dev-sweep-$stamp"
    } else {
        $Root = Join-Path ([System.IO.Path]::GetTempPath()) "om-dev-sweep-$stamp"
    }
}
$resolvedRoot = [System.IO.Path]::GetFullPath($Root)
if ($resolvedRoot -match '(?i)[/\\]\.(onememory|respire)([/\\]|$)') {
    throw "Refused: the root sits inside the user store .onememory/.respire: $resolvedRoot"
}
$Root = $resolvedRoot
New-Item -ItemType Directory -Force -Path $Root, (Join-Path $Root 'logs'), (Join-Path $Root 'secrets'), (Join-Path $Root 'work') | Out-Null
$Prefix = Join-Path $Root 'npm'
$DirA = Join-Path $Root 'a'
$DirB = Join-Path $Root 'b'
$DirD = Join-Path $Root 'd'
$Work = Join-Path $Root 'work'
$Secrets = Join-Path $Root 'secrets'
$ReportPath = Join-Path $Root 'report.md'
$CoveragePath = Join-Path $Root 'coverage.json'
$SmokeHome = Join-Path $Root 'home'
New-Item -ItemType Directory -Force -Path $SmokeHome | Out-Null
if ($IsMacOS) {
    # The native keyring reads user-domain preferences under the CLI's isolated HOME.
    # Configure only this disposable home; never replace the runner's default keychain.
    $preferences = Join-Path $SmokeHome 'Library/Preferences'
    $keychains = Join-Path $SmokeHome 'Library/Keychains'
    New-Item -ItemType Directory -Force -Path $preferences, $keychains | Out-Null
    $keychain = Join-Path $keychains 'rsrs-smoke.keychain-db'
    function Invoke-SmokeSecurity([string[]]$SecurityArgs) {
        $output = & /usr/bin/env "HOME=$SmokeHome" /usr/bin/security @SecurityArgs 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Isolated keychain setup failed: $($SecurityArgs[0])" }
        return ($output -join "`n")
    }
    Invoke-SmokeSecurity @('create-keychain', '-p', '', $keychain) | Out-Null
    Invoke-SmokeSecurity @('list-keychains', '-d', 'user', '-s', $keychain) | Out-Null
    Invoke-SmokeSecurity @('default-keychain', '-d', 'user', '-s', $keychain) | Out-Null
    Invoke-SmokeSecurity @('unlock-keychain', '-p', '', $keychain) | Out-Null
    Invoke-SmokeSecurity @('set-keychain-settings', '-t', '3600', '-u', $keychain) | Out-Null
    $selectedKeychain = (Invoke-SmokeSecurity @('default-keychain', '-d', 'user')).Trim().Trim('"')
    if ($selectedKeychain -cne $keychain) { throw 'Isolated keychain default readback does not match the fixture.' }
}
$script:Catalog = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'dev-smoke-cli-coverage.json') -Raw -Encoding utf8 | ConvertFrom-Json
if ($DeferSupplemental) {
    $approved = @('runtime', 'ai_inject', 'outbox', 'legacy_vault', 'profile_migration')
    $actual = @($script:Catalog.supplemental_required | Sort-Object -Unique)
    if (@($script:Catalog.required_remaining).Count -gt 0 -or @($actual | Where-Object { $_ -notin $approved }).Count -gt 0 -or $actual.Count -ne $approved.Count -or @($script:Catalog.supplemental_required).Count -ne $approved.Count) {
        throw 'Only the five explicitly assigned supplemental suites may be deferred; unknown required functionality must fail closed.'
    }
}
function Stop-OurRuntimes {
    # Runtime command lines contain --runtime-internal; the data directory is in the environment.
    # With -Exe, the binary is outside the npm prefix; locate the isolated runtime correctly.
    $self = $PID
    $targets = New-Object System.Collections.Generic.List[int]
    if (Test-Path -LiteralPath $resolvedRoot) {
        Get-ChildItem -LiteralPath $resolvedRoot -Filter endpoint.json -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '[\\/]runtime[\\/]endpoint\.json$' } |
            ForEach-Object {
                try {
                    $ep = Get-Content -LiteralPath $_.FullName -Raw -Encoding utf8 | ConvertFrom-Json
                    $procId = 0
                    if ($null -ne $ep.pid) { $procId = [int]$ep.pid }
                    if ($procId -gt 0 -and $procId -ne $self) { [void]$targets.Add($procId) }
                } catch { }
            }
    }
    foreach ($procId in ($targets | Select-Object -Unique)) {
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
    foreach ($procId in ($targets | Select-Object -Unique)) {
        for ($i = 0; $i -lt 25; $i++) {
            if (-not (Get-Process -Id $procId -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Milliseconds 200
        }
    }
}
$script:CloudAccounts = New-Object System.Collections.Generic.List[object]
$script:CloudCleanup = @{ passed = $false; events = @(); remaining_users = @() }
$script:CloudCleanupCompleted = $false
$script:CloudCleanupRunning = $false
$script:ModelProgressEvidence = $null
$script:IndexPendingEvents = New-Object System.Collections.Generic.List[object]
$script:SweepReportClock = [Diagnostics.Stopwatch]::StartNew()
trap { $failure = $_; Invoke-CloudCleanup; Write-SweepReport -Force; Stop-OurRuntimes; throw $failure }
$Rows = New-Object System.Collections.Generic.List[object]
$script:Step = 0

function Write-SweepReport([switch]$Force) {
    # Keep periodic diagnostics without rebuilding the entire report after every assertion.
    if (-not $Force -and $script:SweepReportClock.Elapsed.TotalSeconds -lt 5) { return }
    $lines = @('# CLI development sweep', '', "- Server: $Server", "- Version: $ExpectVersion", '', '| Step | Command | Exit | Status | Result | Note |', '| --- | --- | --- | --- | --- | --- |')
    foreach ($row in $Rows) {
        $mark = if (-not $row.Ok) { 'FAIL' } elseif ($row.Status -eq 'fail') { 'EXPECTED_ERROR' } elseif ($row.Status -eq 'skip') { 'SKIP' } else { 'PASS' }
        $note = Get-SafeReportNote (($row.Note + ' ' + $row.Leak).Trim())
        $lines += "| $($row.Step) | $($row.Name) | $($row.Exit) | $($row.Status) | $mark | $note |"
    }
    [IO.File]::WriteAllText($ReportPath, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
    # Deliberately omit command output, arguments, notes, and credential material.
    $observed = @($Rows | ForEach-Object {
        @{ case = $_.Name; command = $_.Command; step = $_.Step; exit = $_.Exit; status = $_.Status; result = $(if (-not $_.Ok) { 'failed' } elseif ($_.Status -eq 'skip') { 'skipped' } elseif ($_.Status -eq 'fail') { 'expected_error_contract' } else { 'passed' }) }
    })
    $coverage = @{
        schema_version = 1; server = $Server; source_sha = $env:CLI_SHA; workflow_sha = $env:GITHUB_SHA
        expected_version = $ExpectVersion; observed_version = $script:ObservedVersion
        observed_version_display = $script:ObservedVersionDisplay
        cloud_cleanup = $script:CloudCleanup
        model_progress = $script:ModelProgressEvidence
        index_pending_events = @($script:IndexPendingEvents.ToArray())
        binary_sha256 = $script:BinarySha256; catalog = $script:Catalog
        cases = $observed; passed = @($Rows | Where-Object { $_.Ok -and $_.Status -notin @('skip', 'fail') }).Count
        expected_errors = @($Rows | Where-Object { $_.Ok -and $_.Status -eq 'fail' }).Count
        failed = @($Rows | Where-Object { -not $_.Ok }).Count
        skipped = @($Rows | Where-Object { $_.Status -eq 'skip' }).Count
        required_missing = @($script:Catalog.required_assertions | Where-Object { $required = $_; -not @($Rows | Where-Object { $_.Name -ceq $required -and $_.Ok -and $_.Status -ceq 'ok' }).Count })
        base_complete = @($Rows | Where-Object { -not $_.Ok }).Count -eq 0 -and @($script:Catalog.required_assertions | Where-Object { $required = $_; -not @($Rows | Where-Object { $_.Name -ceq $required -and $_.Ok -and $_.Status -ceq 'ok' }).Count }).Count -eq 0
        supplemental_required = @($script:Catalog.supplemental_required)
        supplemental_deferred = [bool]$DeferSupplemental
        coverage_full = @($script:Catalog.required_remaining).Count -eq 0 -and @($script:Catalog.supplemental_required).Count -eq 0 -and @($Rows | Where-Object { -not $_.Ok }).Count -eq 0 -and @($script:Catalog.required_assertions | Where-Object { $required = $_; -not @($Rows | Where-Object { $_.Name -ceq $required -and $_.Ok -and $_.Status -ceq 'ok' }).Count }).Count -eq 0
    }
    [IO.File]::WriteAllText($CoveragePath, ($coverage | ConvertTo-Json -Depth 20) + "`n", [Text.UTF8Encoding]::new($false))
    $script:SweepReportClock.Restart()
}

function Get-SafeReportNote([string]$Text) {
    $Text = [regex]::Replace($Text, '(?i)(Bearer\s+)[a-z0-9._-]+', '${1}[redacted]')
    $Text = [regex]::Replace($Text, '(?i)([?&]token=)[^&\s|]+', '${1}[redacted]')
    $Text = [regex]::Replace($Text, '(?i)("(?:token|super|secret_key|pass|password|wrapped_urk|kdf_salt|urk_nonce)"\s*:\s*")[^"]*', '${1}[redacted]')
    return $Text -replace '\|', '/'
}

function Get-SafeFailureReason($Envelope) {
    # Report fixed classifications only, never raw authentication responses.
    $message = @($Envelope.errors) -join ' '
    if ($message -match '\b([45]\d\d)\b') { return "http_$($Matches[1])" }
    foreach ($entry in @(
        @('already registered', 'account_exists'),
        @('runtime owns its boot profile', 'profile_change_requires_host'),
        @('read.only', 'readonly_local_guard'),
        @('none in the local keyring|super password required', 'recovery_key_missing'),
        @('keyring write did not round-trip', 'keyring_readback_failed'),
        @('local keyring write failed|keyring write failed', 'keyring_write_failed'),
        @('keyring|keychain', 'keyring'),
        @('session not unlocked|vault.*locked', 'vault_locked'),
        @('TLS|certificate', 'tls'),
        @('DNS|resolve', 'dns'),
        @('connect|timeout|transport', 'transport'),
        @('runtime.*token|runtime.*auth', 'runtime_auth')
    )) {
        if ($message -match $entry[0]) { return $entry[1] }
    }
    return 'unclassified'
}

function Assert-DevEnvelope($Envelope, [string]$Where) {
    if (-not $Envelope -or -not $Envelope.summary) { return }
    foreach ($key in @('addr', 'server_addr')) {
        $prop = $Envelope.summary.PSObject.Properties[$key]
        if ($prop -and [string]$prop.Value -and [string]$prop.Value -ne $Server) {
            throw "$Where has a $key outside the approved development server. Sweep stopped."
        }
    }
}

function Get-JsonRpc([string]$Text, $Id) {
    foreach ($line in ($Text -split "`n")) {
        $t = $line.Trim()
        if (-not $t.StartsWith('{')) { continue }
        try {
            $obj = $t | ConvertFrom-Json
            if ($null -ne $obj.id -and [string]$obj.id -eq [string]$Id) { return $obj }
        } catch { }
    }
    return $null
}

function Get-McpToolEnvelope($Rpc) {
    if (-not $Rpc -or -not $Rpc.result) { return $null }
    if ($Rpc.result.isError -eq $true) { return $null }
    $content = $Rpc.result.content
    if (-not $content -or $content.Count -lt 1) { return $null }
    $text = [string]$content[0].text
    try { return $text | ConvertFrom-Json } catch { return $null }
}

function Add-SweepRow([string]$Name, [bool]$Ok, [string]$Note) {
    $script:Step++
    $Rows.Add([pscustomobject]@{
        Step = $script:Step; Name = $Name; Exit = $(if ($Ok) { 0 } else { 1 }); Status = $(if ($Ok) { 'ok' } else { 'fail' }); Ok = $Ok; Leak = ''; Note = $Note
    }) | Out-Null
    Write-Host "$(if ($Ok) {'PASS'} else {'FAIL'}) $Name $Note"
}

function Assert-Smoke([string]$Name, [bool]$Condition) {
    Add-SweepRow $Name $Condition 'semantic assertion'
    Write-SweepReport -Force:(-not $Condition)
    if (-not $Condition) { throw "Release smoke assertion failed: $Name" }
}

function Invoke-McpStdioTool {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Tool,
        [hashtable]$Arguments = @{},
        [Parameter(Mandatory)][string]$DataDir,
        [switch]$AllowDestructiveMcpFixture,
        [int]$TimeoutSec = 90
    )
    $argJson = if ($Arguments.Count -eq 0) { '{}' } else { $Arguments | ConvertTo-Json -Compress -Depth 8 }
    $stdin = (@(
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"sweep","version":"0"}}}'
        '{"jsonrpc":"2.0","method":"notifications/initialized"}'
        "{`"jsonrpc`":`"2.0`",`"id`":2,`"method`":`"tools/call`",`"params`":{`"name`":`"$Tool`",`"arguments`":$argJson}}"
    ) -join "`n") + "`n"
    $run = Invoke-Om -Name $Name -ArgList @('mcp') -DataDir $DataDir -Raw -TimeoutSec $TimeoutSec -StdinText $stdin -Note $Tool -AllowDestructiveMcpFixture:$AllowDestructiveMcpFixture
    $rpc = Get-JsonRpc $run.Stdout 2
    $envlp = Get-McpToolEnvelope $rpc
    return [pscustomobject]@{ Run = $run; Rpc = $rpc; Envelope = $envlp }
}

function Get-Envelope([string]$Text) {
    $t = $Text.Trim()
    if (-not $t) { return $null }
    $start = $t.IndexOf("{")
    if ($start -lt 0) { return $null }
    $slice = $t.Substring($start)
    try { return $slice | ConvertFrom-Json } catch { return $null }
}

function Get-Leak([string]$Text, [bool]$Secret) {
    $hits = @()
    if ($Text -cmatch 'DETAILS') { $hits += 'DETAILS' }
    if (-not $Secret) {
        foreach ($w in @('"ciphertext"', '"embedding_enc"', '"wrapped_urk"', '"kdf_salt"', '"embedding"', '"nonce"')) {
            if ($Text.Contains($w)) { $hits += $w }
        }
    }
    return $hits
}

# Only the endpoint and token beneath the current disposable device are used.
function Invoke-OwnedRuntimeRpc([string]$DataDir, [string]$Method, [string[]]$Arguments = @(), [int]$TimeoutSec = 5) {
    $endpoint = Get-Content -LiteralPath (Join-Path $DataDir 'runtime/endpoint.json') -Raw | ConvertFrom-Json
    $uri = [Uri][string]$endpoint.url
    if ($uri.Scheme -ne 'http' -or $uri.Host -notin @('127.0.0.1', 'localhost', '::1')) {
        throw 'Owned runtime endpoint is not loopback HTTP.'
    }
    if (Test-Path -LiteralPath (Join-Path $DataDir 'runtime/token')) { throw 'Owned loopback runtime created a token.' }
    $origin = $uri.GetLeftPart([UriPartial]::Authority)
    try {
        if ($Method -eq 'health') {
            return Invoke-RestMethod -Uri "$origin/api/health" -TimeoutSec $TimeoutSec
        }
        $requestId = [Guid]::NewGuid().ToString('N')
        $body = @{ v = 1; id = $requestId; method = $Method; args = $Arguments } | ConvertTo-Json -Compress
        $response = Invoke-RestMethod -Uri "$origin/api/rpc" -Method Post -ContentType 'application/json' `
            -Body $body -TimeoutSec 5
        if ($response.ok -ne $true -or [string]$response.id -cne $requestId -or [string]$response.bin -cne $ExpectVersion) {
            throw 'Owned runtime RPC response identity failed.'
        }
        return $response.envelope.summary
    } catch { throw 'Owned runtime request failed.' }
}

function Get-OwnedRuntimeHealth([string]$DataDir, [int]$TimeoutSec = 5) {
    $health = Invoke-OwnedRuntimeRpc $DataDir 'health' -TimeoutSec $TimeoutSec
    $profile = [IO.Path]::GetFullPath([string]$health.data_dir)
    $device = [IO.Path]::GetFullPath($DataDir).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $nativeName = if ($IsWindows) { 'rsrs.exe' } else { 'rsrs' }
    $ownedExecutable = [IO.Path]::GetFullPath((Join-Path $DataDir "bin/$nativeName"))
    if ([int]$health.v -ne 1 -or [string]$health.bin -cne $ExpectVersion -or [int]$health.pid -le 0 `
        -or ($profile -ne $device -and -not $profile.StartsWith($device + [IO.Path]::DirectorySeparatorChar)) `
        -or [IO.Path]::GetFullPath([string]$health.exe) -ne $ownedExecutable `
        -or (Get-FileHash -LiteralPath $ownedExecutable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $script:BinarySha256) {
        throw 'Owned runtime health identity failed.'
    }
    return $health
}

function Test-RuntimeChanged($Before, $After, [string]$Profile) {
    # Shutdown and process reaping are asynchronous; bound the observation only.
    for ($i = 0; $i -lt 20 -and (Get-Process -Id ([int]$Before.pid) -ErrorAction SilentlyContinue); $i++) {
        Start-Sleep -Milliseconds 50
    }
    return [int]$Before.pid -ne [int]$After.pid `
        -and -not (Get-Process -Id ([int]$Before.pid) -ErrorAction SilentlyContinue) `
        -and [IO.Path]::GetFullPath([string]$After.data_dir) -eq [IO.Path]::GetFullPath($Profile)
}

function Wait-OwnedModelIdle([string]$DataDir, [int]$TimeoutSec) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $taskId = [Guid]::NewGuid().ToString('N')
    while ($clock.Elapsed.TotalSeconds -lt [Math]::Min(120, $TimeoutSec)) {
        $health = Get-OwnedRuntimeHealth $DataDir
        $state = [string]$health.retrieval_index.state
        if ($state -ceq 'failed') { throw 'Owned retrieval index failed before model installation.' }
        if ($state -cnotin @('idle', 'scheduled', 'running', 'ready')) { throw 'Owned retrieval index readiness state is invalid.' }
        $progress = Invoke-OwnedRuntimeRpc $DataDir 'model.control' @($taskId, 'false')
        if ($progress.active -ne $true -and $progress.active -ne $false) { throw 'Model progress active flag is missing.' }
        if ($state -ceq 'ready' -and $progress.active -eq $false) {
            return [int][Math]::Floor($TimeoutSec - $clock.Elapsed.TotalSeconds)
        }
        Start-Sleep -Milliseconds 100
    }
    throw 'Owned model/index work did not finish within the bounded installation deadline.'
}

function Invoke-Om {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$ArgList = @(),
        [Parameter(Mandatory)][string]$DataDir,
        [int[]]$ExpectExit = @(0),
        [string[]]$AllowStatus = @('ok', 'warn', 'skip'),
        [switch]$Secret,
        [switch]$Raw,
        [switch]$HostProfile,
        [switch]$AllowDestructiveMcpFixture,
        [switch]$AllowIndexWait,
        [string]$ModelTaskId = '',
        [int]$TimeoutSec = 180,
        [string]$StdinText = '',
        [string]$Note = '',
        [int]$MinStdout = 0,
        [string]$RequireCommand = ''
    )
    # These are separate simulated devices sharing one CI host/port. The host
    # must stop the old device with its own credentials before switching roots.
    if ($script:ActiveDataDir -and $script:ActiveDataDir -ne $DataDir) {
        Invoke-Om -Name 'host-stop-before-device-switch' -ArgList @('--runtime-internal', '--stop') `
            -DataDir $script:ActiveDataDir -Raw | Out-Null
    }
    $script:ActiveDataDir = $DataDir
    if ($HostProfile) {
        # Only stop this disposable sweep runtime. The following normal command
        # autostarts its replacement after the host has switched the profile.
        Invoke-Om -Name 'host-stop-before-profile-change' -ArgList @('--runtime-internal', '--stop') `
            -DataDir $DataDir -Raw -ExpectExit @(0, 2) | Out-Null
        Stop-OurRuntimes
        if ($ArgList -notcontains '--direct') { $ArgList = @('--direct') + $ArgList }
    }
    if ($ModelTaskId) { $ArgList = @('--model-task-id', $ModelTaskId) + $ArgList }
    if ($AllowIndexWait) {
        $readCommand = @($ArgList | Where-Object { $_ -notin @('--direct', '--client-only', '--json') })[0]
        if ($readCommand -notin @('recall', 'candidates') -or $Raw -or $Secret -or $ModelTaskId) {
            throw 'Index readiness waiting is restricted to explicit JSON retrieval reads.'
        }
    }
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    $script:Step++
    $safe = ($Name -replace '[^\w\-]+', '_')
    $outFile = Join-Path $Root "logs\$($script:Step)-$safe.out.txt"
    $errFile = Join-Path $Root "logs\$($script:Step)-$safe.err.txt"
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    if ($script:UseExe) {
        $psi.FileName = $script:ExePath
    } else {
        $psi.FileName = 'node'
        $psi.ArgumentList.Add($script:CliJs)
    }
    $psi.WorkingDirectory = $Work
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardOutputEncoding = $utf8
    $psi.StandardErrorEncoding = $utf8
    $psi.StandardInputEncoding = $utf8
    foreach ($a in $ArgList) { $psi.ArgumentList.Add([string]$a) }
    $psi.Environment['RSRS_DATA_DIR'] = $DataDir
    $psi.Environment['RSRS_LANG'] = 'en'
    $psi.Environment['HOME'] = $SmokeHome
    $psi.Environment['USERPROFILE'] = $SmokeHome
    $psi.Environment['XDG_CONFIG_HOME'] = Join-Path $SmokeHome '.config'
    $psi.Environment['XDG_DATA_HOME'] = Join-Path $SmokeHome '.local/share'
    $psi.Environment['RSRS_M3_DIR'] = Join-Path $Root 'models/bge-m3'
    $psi.Environment['RSRS_M3_DIR'] = Join-Path $Root 'models/bge-m3'
    # Only this disposable child may opt into the three named lifecycle tools.
    # Parent environment and all normal/default-policy calls remain unchanged.
    foreach ($policyPrefix in @('RSRS_', 'ONEMEMORY_', 'RESPIRE_')) {
        foreach ($policyName in @('MCP_ALLOW','MCP_DENY','MCP_ALLOW_TOOLS','MCP_DENY_TOOLS')) {
            [void]$psi.Environment.Remove($policyPrefix + $policyName)
        }
    }
    if ($AllowDestructiveMcpFixture) {
        $psi.Environment['RSRS_MCP_ALLOW'] = 'memory_show,memory_forget,memory_restore'
    }
    [void]$psi.Environment.Remove('RSRS_SERVER')
    Write-Host "STEP $script:Step $Name"
    $readyTries = 0
    $indexRetried = $false
    $indexEvent = $null
    $indexCommandBudget = [Diagnostics.Stopwatch]::StartNew()
    do {
        $readyTries++
        if ($readyTries -gt 1) { Write-Host "RETRY $Name" }
    $attemptTimeout = $TimeoutSec
    if ($AllowIndexWait) {
        $attemptTimeout = [int][Math]::Floor($TimeoutSec - $indexCommandBudget.Elapsed.TotalSeconds)
        if ($attemptTimeout -le 0) { throw 'Index readiness retry exceeded the original command deadline.' }
    }
    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($StdinText) { $proc.StandardInput.Write($StdinText) }
    $proc.StandardInput.Close()
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $timedOut = $false
    $progressSamples = New-Object System.Collections.Generic.List[object]
    $finished = $false
    if ($ModelTaskId) {
        $waitStarted = [Diagnostics.Stopwatch]::StartNew()
        while (-not ($finished = $proc.WaitForExit(25)) -and $waitStarted.Elapsed.TotalSeconds -lt $TimeoutSec) {
            $progress = Invoke-OwnedRuntimeRpc $DataDir 'model.control' @($ModelTaskId, 'false')
            if ($progress.active -eq $true) {
                $progressSamples.Add($progress) | Out-Null
            } elseif ($progress.active -ne $false) { throw 'Model progress active flag is missing.' }
        }
    } else { $finished = $proc.WaitForExit($attemptTimeout * 1000) }
    if (-not $finished) {
        $timedOut = $true
        try { $proc.Kill($true) } catch { try { $proc.Kill() } catch { } }
        Stop-OurRuntimes
        $proc.WaitForExit(5000) | Out-Null
    }
    $stdout = ''
    $stderr = ''
    if ($outTask.Wait(10000)) { try { $stdout = $outTask.Result } catch { $stdout = '' } }
    if ($errTask.Wait(10000)) { try { $stderr = $errTask.Result } catch { $stderr = '' } }
    $exit = if ($timedOut) { 124 } else { $proc.ExitCode }
    $blob = $stdout + "`n" + $stderr
    if ($ModelTaskId) {
        $finalProgress = Invoke-OwnedRuntimeRpc $DataDir 'model.control' @($ModelTaskId, 'false')
        $script:ModelProgressEvidence = @{
            observed = $progressSamples.Count -gt 0; samples = @($progressSamples | ForEach-Object {
                @{ phase = $_.phase; done = $_.done; total = $_.total; elapsed = $_.elapsed; idle = $_.idle }
            })
            completed_inactive = $finalProgress.active -eq $false
            limitation = 'A completed operation clears progress; a fast operation may finish before a poll observes it. The 15-second foreground budget branch is not exercised by this fixture.'
        }
    }
    if ($Secret) {
        [System.IO.File]::WriteAllText((Join-Path $Secrets "$script:Step-$safe.txt"), $blob, [Text.UTF8Encoding]::new($false))
        $stdoutForScan = $stdout
    } else {
        [System.IO.File]::WriteAllText($outFile, $stdout, [Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText($errFile, $stderr, [Text.UTF8Encoding]::new($false))
        $stdoutForScan = $stdout
    }
    $leaks = @(Get-Leak $stdoutForScan $Secret.IsPresent)
    $envlp = Get-Envelope $stdout
    Assert-DevEnvelope $envlp $Name
    $status = ''
    if ($envlp -and $envlp.PSObject.Properties['status']) { $status = [string]$envlp.status }
    if ($envlp -and [string]$envlp.command -eq 'cli') {
        $keys = @($envlp.summary.PSObject.Properties.Name)
        if ($keys.Count -eq 0) { $Note = ("RPC returned an empty cli envelope " + $Note).Trim() }
    }
    if ($Raw -or -not $status) {
        $exitOk = $ExpectExit -contains [int]$exit
        $statusOk = $true
    } else {
        $want = switch ($status) { 'ok' { 0 } 'skip' { 0 } 'warn' { 2 } 'pending' { 2 } 'fail' {
            if ([string]$envlp.summary.reason -eq 'invalid_input' -and [string]$envlp.details.error_type -eq 'user') { 2 } else { 1 }
        } default { -1 } }
        $exitOk = ($exit -eq $want)
        $statusOk = $AllowStatus -contains $status
    }
    if ($stdout.Length -lt $MinStdout) { $statusOk = $false; $Note = ("stdout too short " + $Note).Trim() }
    if ($RequireCommand) {
        $got = [string]$envlp.command
        $total = $null
        if ($envlp -and $envlp.summary) { $total = $envlp.summary.total }
        if ($got -ne $RequireCommand -or $null -eq $total) {
            $statusOk = $false
            $Note = ("command=$got total=$total want $RequireCommand " + $Note).Trim()
        }
    }
    $readyFail = ($stdout + $stderr) -match 'did not become ready'
        if ($readyFail -and $readyTries -lt 2) { Stop-OurRuntimes; Start-Sleep -Seconds 1 }
    $retryIndexPending = $AllowIndexWait -and -not $indexRetried -and -not $timedOut `
        -and $exit -eq 2 -and $status -ceq 'pending' -and [string]$envlp.summary.state -ceq 'index_pending' `
        -and @($envlp.errors).Count -eq 0 -and $leaks.Count -eq 0
    if ($retryIndexPending) {
        $indexRetried = $true
        # Preserve the first response separately. It is an observed Pending,
        # not a passing command or a replacement for the final data assertions.
        [IO.File]::WriteAllText($outFile + '.index-pending', $stdout, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($errFile + '.index-pending', $stderr, [Text.UTF8Encoding]::new($false))
        $indexEvent = [ordered]@{ case = $Name; exit = 2; state = 'index_pending'; readiness = 'waiting'; polls = 0; wait_ms = 0; retried = $false }
        $script:IndexPendingEvents.Add($indexEvent) | Out-Null
        Write-SweepReport
        $indexWait = [Diagnostics.Stopwatch]::StartNew()
        $indexWaitBudget = [Math]::Min(120, $TimeoutSec - $indexCommandBudget.Elapsed.TotalSeconds)
        while ($true) {
            $remaining = [Math]::Min($indexWaitBudget - $indexWait.Elapsed.TotalSeconds, $TimeoutSec - $indexCommandBudget.Elapsed.TotalSeconds)
            if ($remaining -lt 1) {
                $indexEvent.readiness = 'timeout'
                throw 'Owned retrieval index did not become ready within the bounded command deadline.'
            }
            $health = Get-OwnedRuntimeHealth $DataDir -TimeoutSec ([int][Math]::Min(5, [Math]::Floor($remaining)))
            $indexEvent.polls++
            $indexEvent.wait_ms = [int]$indexWait.Elapsed.TotalMilliseconds
            $indexState = [string]$health.retrieval_index.state
            if ($indexState -ceq 'failed') {
                $indexEvent.readiness = 'failed'
                throw 'Owned retrieval index reported failed; the command was not retried.'
            }
            if ($indexState -ceq 'ready') {
                $indexEvent.readiness = 'ready'
                $indexEvent.retried = $true
                break
            }
            if ($indexState -cnotin @('idle', 'scheduled', 'running')) { throw 'Owned retrieval index readiness state is invalid.' }
            Start-Sleep -Milliseconds 100
        }
    }
    } while (($readyFail -and $readyTries -lt 2) -or $retryIndexPending)
    if ($readyTries -gt 1) { $Note = ("runtime retried $readyTries time(s) " + $Note).Trim() }
    $ok = $exitOk -and $statusOk -and ($leaks.Count -eq 0) -and (-not $timedOut)
    $commandTokens = @($ArgList | Where-Object { $_ -notin @('--direct', '--client-only', '--json') })
    $commandPath = ''
    foreach ($entry in @($script:Catalog.command_paths | Sort-Object { $_.command.Length } -Descending)) {
        $pathTokens = @($entry.command -split ' ')
        if ($commandTokens.Count -ge $pathTokens.Count -and ($commandTokens[0..($pathTokens.Count - 1)] -join ' ') -eq $entry.command) {
            $commandPath = $entry.command
            break
        }
    }
    if (-not $ok) { $Note = ("failure_reason=$(Get-SafeFailureReason $envlp) $Note").Trim() }
    $row = [pscustomobject]@{
        Step   = $script:Step
        Name   = $Name
        Command = $commandPath
        Exit   = $exit
        Status = $status
        Ok     = $ok
        Leak   = ($leaks -join ',')
        Note   = $(if ($timedOut) { "timeout ${TimeoutSec}s; $Note" } else { $Note })
    }
    $Rows.Add($row) | Out-Null
    Write-SweepReport -Force:(-not $ok)
    $flag = if (-not $ok) { 'FAIL' } elseif ($status -eq 'fail') { 'EXPECTED_ERROR' } elseif ($status -eq 'skip') { 'SKIP' } else { 'PASS' }
    Write-Host "$flag $Name exit=$exit status=$status leak=$($row.Leak)"
    if (-not $ok) {
        $detail = if ($Secret) { "failure_reason=$(Get-SafeFailureReason $envlp)" } else { $stderr + ' ' + $stdout }
        $detail = [regex]::Replace($detail, '(?i)(super|secret|token|password|nonce|wrapped_urk|kdf_salt)[^,\s"]{0,120}', '${1}=[redacted]')
        $detail = ($detail -replace '\s+', ' ').Trim()
        if ($detail.Length -gt 240) { $detail = $detail.Substring($detail.Length - 240) }
        if ($detail) { Write-Host "DETAIL $detail" }
    }
    return [pscustomobject]@{ Ok = $ok; Exit = $exit; Envelope = $envlp; Stdout = $(if ($Secret) { '' } else { $stdout }); Row = $row; Progress = @($progressSamples.ToArray()) }
}

function Assert-Count([string]$Name, $Envelope, [string]$Field, [int]$Min) {
    $n = 0
    if ($Envelope -and $Envelope.summary -and $null -ne $Envelope.summary.$Field) {
        $n = [int]$Envelope.summary.$Field
    }
    if ($n -lt $Min) { throw "$Name ${Field}=$n, expected at least $Min" }
}

function New-Pass {
    -join ((48..57 + 65..90 + 97..122 | Get-Random -Count 24 | ForEach-Object { [char]$_ }))
}

function Get-SmokeSession([string]$DataRoot, [string]$ExpectedUser) {
    $sessions = @(Get-ChildItem -LiteralPath $DataRoot -Filter session.json -Recurse -File | ForEach-Object {
        $value = Get-Content -LiteralPath $_.FullName -Raw -Encoding utf8 | ConvertFrom-Json
        if ([string]$value.user -eq $ExpectedUser -and $value.token) { [pscustomobject]@{ Path = $_.FullName; Value = $value } }
    })
    if ($sessions.Count -ne 1) { throw 'Expected exactly one disposable session for this device/user.' }
    return $sessions[0]
}

function Add-CloudRegistration([string]$User, [string]$Password) {
    # Record before the request: a failed response does not prove no account was created.
    if ($User -notmatch "^(sweep|oth|sps)$stamp$") { throw 'Registration is outside this sweep namespace.' }
    $account = [pscustomobject]@{ User = $User; Password = $Password; Super = ''; Confirmed = $false; Purged = $false }
    $script:CloudAccounts.Add($account)
    return $account
}

function Confirm-CloudRegistration($Account, $Registration) {
    if ($Registration.Ok -and $Registration.Envelope.summary.ok -eq $true -and
        [string]$Registration.Envelope.summary.user -ceq $Account.User -and
        [string]$Registration.Envelope.summary.addr -ceq $Server -and
        [bool]$Registration.Envelope.summary.super) {
        $Account.Super = [string]$Registration.Envelope.summary.super
        $Account.Confirmed = $true
    }
}

function Invoke-CloudCleanup {
    if ($script:CloudCleanupCompleted -or $script:CloudCleanupRunning) { return }
    $script:CloudCleanupRunning = $true
    $events = New-Object System.Collections.Generic.List[object]
    foreach ($account in $script:CloudAccounts) {
        $event = @{ user = $account.User; passed = $false; old_token_rejected = $false }
        try {
            if (-not $account.Confirmed) { throw 'registration_outcome_unconfirmed' }
            if ($account.User -notmatch "^(sweep|oth|sps)$stamp$") { throw 'cleanup_scope_mismatch' }
            $dataDir = Join-Path $Root "cleanup/$($account.User)"
            $login = Invoke-Om -Name 'cleanup-owned-account-login' -ArgList @('--json', 'login', '--interactive', '--addr', $Server, '--user', $account.User, '--pass', $account.Password, '--super', $account.Super) -DataDir $dataDir -Secret -HostProfile -TimeoutSec 120
            if (-not $login.Ok -or [string]$login.Envelope.summary.user -cne $account.User) { throw 'cleanup_login_failed' }
            $session = Get-SmokeSession $dataDir $account.User
            if ([string]$session.Value.addr -cne $Server) { throw 'cleanup_session_server_mismatch' }
            $headers = @{ Authorization = "Bearer $($session.Value.token)" }
            $response = Invoke-WebRequest -Uri "$Server/api/self/purge" -Method Post -Headers $headers -ContentType 'application/json' -Body (@{ confirm = $account.User } | ConvertTo-Json -Compress) -MaximumRedirection 0 -SkipHttpErrorCheck -TimeoutSec 45
            if ([int]$response.StatusCode -ne 200) { throw 'cleanup_purge_not_confirmed' }
            $result = $response.Content | ConvertFrom-Json
            if ($result.purged -ne $true -or [string]$result.user -cne $account.User) { throw 'cleanup_purge_not_confirmed' }
            $rejected = Invoke-WebRequest -Uri "$Server/api/self" -Method Get -Headers $headers -MaximumRedirection 0 -SkipHttpErrorCheck -TimeoutSec 45
            if ([int]$rejected.StatusCode -ne 401) { throw 'cleanup_old_token_still_accepted' }
            $account.Purged = $true
            $event.passed = $true
            $event.old_token_rejected = $true
        } catch {
            # Use a fixed classification; exception text can include authenticated request details.
            $known = @('registration_outcome_unconfirmed', 'cleanup_scope_mismatch', 'cleanup_login_failed', 'cleanup_session_server_mismatch', 'cleanup_purge_not_confirmed', 'cleanup_old_token_still_accepted')
            $reason = [string]$_.Exception.Message
            $event.reason = if ($reason -cin $known) { $reason } else { 'cleanup_request_failed' }
        }
        $events.Add($event)
    }
    $remaining = @($script:CloudAccounts | Where-Object { -not $_.Purged } | ForEach-Object { $_.User })
    $script:CloudCleanup = @{ passed = $remaining.Count -eq 0; events = @($events.ToArray()); remaining_users = $remaining }
    $script:CloudCleanupCompleted = $true
    $script:CloudCleanupRunning = $false
}

$script:UseExe = [bool]$Exe
$script:ExePath = $Exe
if ($script:UseExe) {
    if (-not (Test-Path $script:ExePath)) { throw "binary not found: $($script:ExePath)" }
    Write-Host "ROOT $resolvedRoot"
    Write-Host "EXE $($script:ExePath)"
    $script:CliJs = ''
    $cliVersion = ''
    $script:BinarySha256 = (Get-FileHash -LiteralPath $script:ExePath -Algorithm SHA256).Hash.ToLowerInvariant()
} else {
Write-Host "ROOT $resolvedRoot"
Write-Host "WAIT $Package"
$seen = ''
for ($try = 0; $try -lt 24; $try++) {
    $seen = (npm view $Package version --registry https://registry.npmjs.org 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -eq 0 -and $seen) { break }
    Start-Sleep -Seconds 10
}
if (-not $seen) { throw "package not visible on npm yet: $Package" }
Write-Host "INSTALL $Package ($seen)"
npm install --prefix $Prefix $Package --include=optional --no-fund --no-audit --registry https://registry.npmjs.org
if ($LASTEXITCODE -ne 0) { throw "npm install failed: $LASTEXITCODE" }
$script:CliJs = Join-Path $Prefix 'node_modules\rsrs-cli\bin\cli.js'
if (-not (Test-Path $script:CliJs)) { throw "$script:CliJs not found" }
$pkgJson = Get-Content (Join-Path $Prefix 'node_modules\rsrs-cli\package.json') -Raw | ConvertFrom-Json
$cliVersion = [string]$pkgJson.version
$tags = npm view rsrs-cli dist-tags --json --registry https://registry.npmjs.org | ConvertFrom-Json
$specIsDev = $requested -eq 'dev' -or $requested -match '-dev\.'
if ($specIsDev -and $cliVersion -notmatch '-dev') { throw "Refused: the installed version is not a dev build: $cliVersion" }
if ($requested -ne 'dev' -and $cliVersion -ne $requested) { throw "installed $cliVersion but $requested was requested" }
if ($specIsDev -and [string]$tags.latest -eq $cliVersion) { throw "Refused: dev version $cliVersion already equals latest" }
Write-Host "CLI $cliVersion latest=$($tags.latest) dev=$($tags.dev)"
$rid = [System.Runtime.InteropServices.RuntimeInformation]::RuntimeIdentifier
$plat = switch ($rid) {
    'win-x64' { '@rsrsai/win-x64' }
    'win-arm64' { '@rsrsai/win-arm64' }
    'osx-arm64' { '@rsrsai/macos-arm64' }
    'linux-x64' { '@rsrsai/linux-x64' }
    'linux-arm64' { '@rsrsai/linux-arm64' }
    default { '' }
}
if ($env:RSRS_LIBC -and $rid -like 'linux-*') {
    if ($env:RSRS_LIBC -notin @('glibc', 'musl')) { throw 'RSRS_LIBC must be musl or glibc' }
    if ($plat -and $env:RSRS_LIBC -eq 'glibc') { $plat += '-gnu' }
}
if ($plat) {
    npm install --prefix $Prefix "$plat@$cliVersion" --no-fund --no-audit --registry https://registry.npmjs.org
    if ($LASTEXITCODE -ne 0) { throw "platform package $plat install failed: $LASTEXITCODE" }
}
}

$ver = Invoke-Om -Name 'version' -ArgList @('--version') -DataDir $DirA -Raw -Note $(if ($cliVersion) { $cliVersion } else { $ExpectVersion })
$wantVersion = if ($ExpectVersion) { $ExpectVersion.Trim().TrimStart('v') } else { $cliVersion }
Invoke-Om -Name 'version-short' -ArgList @('-v') -DataDir $DirA -Raw -Note $wantVersion | Out-Null
Invoke-Om -Name 'version-v' -ArgList @('v') -DataDir $DirA -Raw -Note $wantVersion | Out-Null
$verJson = Invoke-Om -Name 'version-json' -ArgList @('--json', 'v') -DataDir $DirA -Note 'command=version'
if (-not ($verJson.Stdout -like '*"command":"version"*')) {
    Add-SweepRow 'version-json-command' $false $verJson.Stdout
}
if ($wantVersion -and $ver.Stdout -notmatch [regex]::Escape($wantVersion)) { throw "version output does not match $wantVersion" }
$script:ObservedVersion = [string]$verJson.Envelope.summary.version
$script:ObservedVersionDisplay = $ver.Stdout.Trim()
Assert-Smoke 'exact-artifact-version' ($ver.Ok -and $verJson.Ok -and $script:ObservedVersion -ceq $wantVersion -and $script:ObservedVersionDisplay -ceq "rsrs $wantVersion")

Invoke-Om -Name 'help' -ArgList @('--help') -DataDir $DirA -Raw | Out-Null
foreach ($path in $script:Catalog.command_paths) {
    $helpArgs = @($path.command -split ' ') + @('--help')
    $commandHelp = Invoke-Om -Name "help-$($path.command.Replace(' ', '-'))" -ArgList $helpArgs -DataDir $DirA -Raw -MinStdout 20
    Assert-Smoke "help-$($path.command.Replace(' ', '-'))-contract" ($commandHelp.Ok -and $commandHelp.Stdout -match 'Usage:')
}
$prompt = Invoke-Om -Name 'prompt' -ArgList @('--json', 'prompt') -DataDir $DirA
Assert-Smoke 'prompt-instructions-present' ($prompt.Ok -and [string]$prompt.Envelope.command -eq 'prompt' -and [string]$prompt.Envelope.summary.instructions -match 'rsrs')
Invoke-Om -Name 'no-args-no-tty' -ArgList @() -DataDir $DirA -ExpectExit @(2) -Raw -Note 'no TTY should exit 2' | Out-Null
Invoke-Om -Name 'parse-error' -ArgList @('not-a-command') -DataDir $DirA -ExpectExit @(2) -Raw | Out-Null

$splitHelp = Invoke-Om -Name 'split-help-contract' -ArgList @('split', '--help') -DataDir $DirA -Raw
if ($splitHelp.Stdout -notmatch 'Split a mixed node' -or $splitHelp.Stdout -match 'Tree hygiene|--parent') {
    throw 'split help contains another command description'
}
$cureHelp = Invoke-Om -Name 'tree-cure-help-contract' -ArgList @('tree-cure', '--help') -DataDir $DirA -Raw
if ($cureHelp.Stdout -notmatch 'Tree hygiene') { throw 'tree-cure help has no description' }
$pluginHelp = Invoke-Om -Name 'plugin-help-contract' -ArgList @('plugin', '--help') -DataDir $DirA -Raw
if ($pluginHelp.Stdout -match '--list' -or $pluginHelp.Stdout -notmatch 'list shows config') {
    throw 'plugin help does not match its subcommands'
}
Invoke-Om -Name 'plugin-reject-list-flag' -ArgList @('plugin', '--list') -DataDir $DirA -ExpectExit @(2) -Raw | Out-Null
Invoke-Om -Name 'plugin-test-requires-event' -ArgList @('plugin', 'test') -DataDir $DirA -ExpectExit @(2) -Raw | Out-Null
Invoke-Om -Name 'chain-reject-from-flag' -ArgList @('chain', '--from', 'missing') -DataDir $DirA -ExpectExit @(2) -Raw | Out-Null

Invoke-Om -Name 'config-addr' -ArgList @('--json', 'config', '--addr', $Server) -DataDir $DirA | Out-Null
$cfg = Invoke-Om -Name 'config-read' -ArgList @('--json', 'config') -DataDir $DirA
$cfgAddr = [string]$cfg.Envelope.summary.addr
if ($cfgAddr -ne $Server) { throw "config address is not the test server: $cfgAddr" }
$configWrite = Invoke-Om -Name 'config-isolated-settings' -ArgList @('--json', 'config', '--autosync', 'false', '--cure-auto', 'false', '--rpc-parallelism', '1') -DataDir $DirA
$configRead = Invoke-Om -Name 'config-settings-readback' -ArgList @('--json', 'config') -DataDir $DirA
Assert-Smoke 'config-settings-persisted' ($configWrite.Ok -and $configRead.Ok -and $configRead.Envelope.summary.autosync -eq $false -and $configRead.Envelope.summary.cure_auto -eq $false -and [int]$configRead.Envelope.summary.rpc_parallelism -eq 1)
$bgeInstall = Invoke-Om -Name 'model-install' -ArgList @('--json', 'model', 'install') -DataDir $DirA -TimeoutSec 900
Assert-Smoke 'model-bge-installed' ($bgeInstall.Ok -and [string]$bgeInstall.Envelope.summary.model -eq 'm3' -and (Test-Path -LiteralPath (Join-Path $Root 'models/bge-m3/onnx/model_quantized.onnx')))
$engine = Invoke-Om -Name 'model-engine-cpu' -ArgList @('--json', 'model', 'engine', 'cpu') -DataDir $DirA
Assert-Smoke 'model-engine-cpu-selected' ($engine.Ok -and [string]$engine.Envelope.summary.engine -eq 'cpu')
foreach ($configuredEngine in @('gpu', 'npu')) {
    $savedEngine = Invoke-Om -Name "model-engine-configure-$configuredEngine" -ArgList @('--json', 'model', 'engine', $configuredEngine) -DataDir $DirA -HostProfile
    $engineSettings = Get-Content -LiteralPath (Join-Path $DirA 'inference.json') -Raw -Encoding utf8 | ConvertFrom-Json
    # This asserts saved selection only; it does not claim accelerated inference.
    Assert-Smoke "model-engine-$configuredEngine-selection-persisted" ($savedEngine.Ok -and [string]$engineSettings.engine -eq $configuredEngine -and $engineSettings.force_cpu -eq $false)
}
Invoke-Om -Name 'model-engine-restore-cpu' -ArgList @('--json', 'model', 'engine', 'cpu') -DataDir $DirA -HostProfile | Out-Null
$probe = Invoke-Om -Name 'model-probe-m3' -ArgList @('--json', 'model', 'probe', '--text', 'isolated release smoke') -DataDir $DirA -TimeoutSec 300
Assert-Smoke 'model-m3-default-probe-success' ($probe.Ok -and [string]$probe.Envelope.status -eq 'ok' -and [string]$probe.Envelope.summary.model -eq 'm3' -and [int]$probe.Envelope.summary.dimensions -eq 1024)

$offlineDir = Join-Path $Root 'offline'
Invoke-Om -Name 'offline-config' -ArgList @('--json', 'config', '--addr', $Server, '--autosync', 'false') -DataDir $offlineDir | Out-Null
$offlineKeys = Invoke-Om -Name 'keygen-local-success' -ArgList @('--json', 'keygen', '--pass', (New-Pass)) -DataDir $offlineDir -Secret -HostProfile
Assert-Smoke 'keygen-local-v4-material' ($offlineKeys.Ok -and [bool]$offlineKeys.Envelope.summary.super -and (Test-Path -LiteralPath (Join-Path $offlineDir 'session.json')))
$firstLocalWrap = (Get-Content -LiteralPath (Join-Path $offlineDir 'session.json') -Raw | ConvertFrom-Json).wrapped_urk
$offlineEntry = Invoke-Om -Name 'keygen-local-write' -ArgList @('--json', 'remember', "offline-$stamp", '--title', "offline-$stamp", '--importance', 'important', '--force') -DataDir $offlineDir
$offlineId = [string]$offlineEntry.Envelope.summary.id
$offlineRead = Invoke-Om -Name 'keygen-local-readback' -ArgList @('--json', 'show', $offlineId) -DataDir $offlineDir
Assert-Smoke 'keygen-local-memory-readable' ($offlineEntry.Ok -and $offlineRead.Ok -and [string]$offlineRead.Envelope.details.entry.content -eq "offline-$stamp")
$localRefuse = Invoke-Om -Name 'keygen-local-overwrite-refused' -ArgList @('--json', 'keygen') -DataDir $offlineDir -Secret -AllowStatus @('fail')
Assert-Smoke 'keygen-local-overwrite-guard' ($localRefuse.Ok -and $localRefuse.Exit -eq 1 -and (Get-Content -LiteralPath (Join-Path $offlineDir 'session.json') -Raw | ConvertFrom-Json).wrapped_urk -eq $firstLocalWrap)
$forcedKeys = Invoke-Om -Name 'keygen-force-disposable' -ArgList @('--json', 'keygen', '--force') -DataDir $offlineDir -Secret -HostProfile
Assert-Smoke 'keygen-force-rotates-material' ($forcedKeys.Ok -and [bool]$forcedKeys.Envelope.summary.super -and (Get-Content -LiteralPath (Join-Path $offlineDir 'session.json') -Raw | ConvertFrom-Json).wrapped_urk -ne $firstLocalWrap)
$offlineLogout = Invoke-Om -Name 'offline-full-logout' -ArgList @('--json', 'logout', '--full') -DataDir $offlineDir -HostProfile
Assert-Smoke 'full-logout-session-file-removed' ($offlineLogout.Ok -and -not (Test-Path -LiteralPath (Join-Path $offlineDir 'session.json')))

$user = "sweep$stamp"
$pass = New-Pass
$mainCloudAccount = Add-CloudRegistration $user $pass
[System.IO.File]::WriteAllText((Join-Path $Secrets 'account.txt'), "user=$user`n", [Text.UTF8Encoding]::new($false))
$reg = Invoke-Om -Name 'register' -ArgList @('--json', 'register', '--addr', $Server, '--user', $user, '--pass', $pass) -DataDir $DirA -Secret -TimeoutSec 120
Confirm-CloudRegistration $mainCloudAccount $reg
if (-not $reg.Ok) { throw 'register failed, aborting. The key lives in secrets; never share it.' }
$super = ''
if ($reg.Envelope.summary.super) { $super = [string]$reg.Envelope.summary.super }
if (-not $super) { throw 'register response has no summary.super' }
$regAddr = [string]$reg.Envelope.summary.addr
if ($regAddr -ne $Server) { throw "register address is not the test server: $regAddr" }

$st = Invoke-Om -Name 'status-json' -ArgList @('--json', 'status') -DataDir $DirA
$serverAddr = ''
if ($st.Envelope.summary.server_addr) { $serverAddr = [string]$st.Envelope.summary.server_addr }
if ($serverAddr -ne $Server) { throw "status.server_addr=$serverAddr is not the test server. Aborting." }
Invoke-Om -Name 'status-human' -ArgList @('status') -DataDir $DirA -Raw | Out-Null
$revisionInitial = Invoke-Om -Name 'memory-revision-json' -ArgList @('--json', 'memory-revision') -DataDir $DirA
Assert-Smoke 'memory-revision-profile-token' ($revisionInitial.Ok -and [string]$revisionInitial.Envelope.command -ceq 'memory-revision' -and [string]$revisionInitial.Envelope.summary.profile -ceq [string]$st.Envelope.summary.data_dir -and [string]$revisionInitial.Envelope.summary.revision -cmatch '^[0-9a-f]{32}$')
Invoke-Om -Name 'status-before-revision-repeat' -ArgList @('--json', 'status') -DataDir $DirA | Out-Null
$revisionRepeat = Invoke-Om -Name 'memory-revision-repeat' -ArgList @('--json', 'memory-revision') -DataDir $DirA
Assert-Smoke 'memory-revision-reads-stable' ($revisionRepeat.Ok -and [string]$revisionRepeat.Envelope.command -ceq 'memory-revision' -and [string]$revisionRepeat.Envelope.summary.profile -ceq [string]$revisionInitial.Envelope.summary.profile -and [string]$revisionRepeat.Envelope.summary.revision -ceq [string]$revisionInitial.Envelope.summary.revision)

Invoke-Om -Name 'doctor-human' -ArgList @('doctor') -DataDir $DirA -Raw -ExpectExit @(0, 1, 2) -MinStdout 40 -TimeoutSec 180 -Note 'exit 1 means a check failed; allowed on a clean runner' | Out-Null
$docj = Invoke-Om -Name 'doctor-json' -ArgList @('--json', 'doctor') -DataDir $DirA -TimeoutSec 180 -AllowStatus @('ok', 'warn', 'fail', 'skip') -RequireCommand 'doctor' -Note 'the envelope must be doctor and summary.total must exist'
$mcpBinItem = @($docj.Envelope.items) | Where-Object { [string]$_.name -eq 'mcp bin' } | Select-Object -First 1
$mcpHttpItem = @($docj.Envelope.items) | Where-Object { [string]$_.name -eq 'mcp http' } | Select-Object -First 1
$binName = if ($IsWindows) { 'rsrs.exe' } else { 'rsrs' }
$mcpBinPath = Join-Path $DirA "bin\$binName"
Add-SweepRow 'doctor-mcp-bin-item' ($null -ne $mcpBinItem -and [string]$mcpBinItem.status -eq 'ok') ([string]$mcpBinItem.value)
Add-SweepRow 'doctor-mcp-http-item' ($null -ne $mcpHttpItem -and ([string]$mcpHttpItem.value -like '*/mcp*')) ([string]$mcpHttpItem.value)
Add-SweepRow 'mcp-bin-file' (Test-Path -LiteralPath $mcpBinPath) $mcpBinPath
$embedder = @($docj.Envelope.items) | Where-Object { [string]$_.name -eq 'embedder' } | Select-Object -First 1
if ($embedder -and [string]$embedder.status -eq 'fail') {
    Invoke-Om -Name 'doctor-fix' -ArgList @('--json', 'doctor', '--fix') -DataDir $DirA -TimeoutSec 900 -AllowStatus @('ok', 'warn', 'fail') -RequireCommand 'doctor' -Note 'install BGE on a clean environment' | Out-Null
}
$remoteDoctor = Invoke-Om -Name 'doctor-remote' -ArgList @('--json', 'doctor', '--remote') -DataDir $DirA -TimeoutSec 180 -AllowStatus @('ok', 'warn', 'fail') -RequireCommand 'doctor'
$remoteItem = @($remoteDoctor.Envelope.items | Where-Object { [string]$_.name -eq 'remote' } | Select-Object -First 1)
Assert-Smoke 'doctor-remote-health-reachable' ($remoteDoctor.Ok -and $remoteItem.Count -eq 1 -and [string]$remoteItem[0].status -eq 'ok' -and [string]$remoteItem[0].value -like "$Server /health -> 200*")

Invoke-Om -Name 'taxonomy' -ArgList @('--json', 'taxonomy') -DataDir $DirA | Out-Null
Invoke-Om -Name 'taxonomy-list' -ArgList @('--json', 'taxonomy', '--list') -DataDir $DirA | Out-Null
Invoke-Om -Name 'taxonomy-ensure' -ArgList @('--json', 'taxonomy', '--ensure', $TX_DEV) -DataDir $DirA | Out-Null
Invoke-Om -Name 'agent-config' -ArgList @('--json', 'agent-config') -DataDir $DirA | Out-Null
Invoke-Om -Name 'agent-config-set' -ArgList @('--json', 'agent-config', '--set', 'diary_mode=concise') -DataDir $DirA | Out-Null
Invoke-Om -Name 'update-check' -ArgList @('--json', 'update-check') -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'update-check-clear' -ArgList @('--json', 'update-check', '--clear') -DataDir $DirA | Out-Null
$pluginList = Invoke-Om -Name 'plugin-list' -ArgList @('--json', 'plugin', 'list') -DataDir $DirA
if (($pluginList.Envelope.actions -join ' ') -match '--event') { throw 'plugin action suggests unsupported --event' }
Invoke-Om -Name 'plugin-test' -ArgList @('--json', 'plugin', 'test', 'post-recall', '--payload', '{}') -DataDir $DirA | Out-Null
$vetoCommand = if ($IsWindows) { 'echo {"verdict":"block","reason":"sweep veto"}' } else { 'echo ''{"verdict":"block","reason":"sweep veto"}''' }
$pluginConfig = @{ hooks = @{ 'pre-remember' = @(@{ cmd = $vetoCommand; on_error = 'skip'; timeout_ms = 2000 }) } } | ConvertTo-Json -Depth 5
$pluginPath = Join-Path $DirA 'plugins.json'
[IO.File]::WriteAllText($pluginPath, $pluginConfig, [Text.UTF8Encoding]::new($false))
try {
    $veto = Invoke-Om -Name 'plugin-explicit-veto' -ArgList @('--json', 'plugin', 'test', 'pre-remember', '--payload', '{}') -DataDir $DirA -AllowStatus @('warn')
    if (-not $veto.Envelope.summary.blocked -or $veto.Envelope.details.reason -notmatch 'sweep veto') {
        throw 'configured plugin did not execute and return its veto'
    }
} finally {
    Remove-Item -LiteralPath $pluginPath
}
Invoke-Om -Name 'inject-targets' -ArgList @('--json', 'inject', '--targets') -DataDir $DirA | Out-Null
Invoke-Om -Name 'inject-preview-codex' -ArgList @('--json', 'inject', '--preview', '--id', 'codex') -DataDir $DirA -ExpectExit @(0, 1, 2) -Raw -Note 'preview only, do not write local agent config' | Out-Null
Invoke-Om -Name 'inject-tui-no-tty' -ArgList @('inject', '--tui') -DataDir $DirA -ExpectExit @(1, 2) -Raw -Note 'no TTY' | Out-Null

# Disable autosync so the later explicit sync owns the push step.
Invoke-Om -Name 'config-autosync-off-before-write' -ArgList @('--json', 'config', '--autosync', 'false') -DataDir $DirA | Out-Null
$revisionBeforeWrite = Invoke-Om -Name 'memory-revision-before-write' -ArgList @('--json', 'memory-revision') -DataDir $DirA
$marker = "sweep-marker-$stamp"
$title = "sweep-marker-$stamp"
$rem = Invoke-Om -Name 'remember-force' -ArgList @(
    '--json', 'remember', "dev sweep marker $marker on TB16P",
    '--title', $title, '--type', 'decision', '--importance', 'important', '--force', '--project', 'respire-cli'
) -DataDir $DirA -TimeoutSec 300
$id = ''
if ($rem.Envelope.summary.id) { $id = [string]$rem.Envelope.summary.id }
if (-not $id) { throw 'remember returned no summary.id, the extraction chain cannot continue.' }
$revisionAfterWrite = Invoke-Om -Name 'memory-revision-after-write-read' -ArgList @('--json', 'memory-revision') -DataDir $DirA
Assert-Smoke 'memory-revision-after-write' ($revisionBeforeWrite.Ok -and $revisionAfterWrite.Ok -and [string]$revisionBeforeWrite.Envelope.command -ceq 'memory-revision' -and [string]$revisionAfterWrite.Envelope.command -ceq 'memory-revision' -and [string]$revisionBeforeWrite.Envelope.summary.profile -ceq [string]$revisionAfterWrite.Envelope.summary.profile -and [string]$revisionBeforeWrite.Envelope.summary.revision -cne [string]$revisionAfterWrite.Envelope.summary.revision)
$short = $id.Substring(0, [Math]::Min(8, $id.Length))
Invoke-Om -Name 'remember-human' -ArgList @('remember', "human path $marker", '--title', "human-$stamp", '--force', '--importance', 'trivial') -DataDir $DirA -Raw -TimeoutSec 300 | Out-Null
$child = Invoke-Om -Name 'remember-parent' -ArgList @(
    '--json', 'remember', "child of $marker", '--title', "child-$stamp", '--parent', $short, '--force', '--importance', 'important', '--type', 'context'
) -DataDir $DirA -TimeoutSec 300
$childId = [string]$child.Envelope.summary.id
$disp = Invoke-Om -Name 'remember-disposable' -ArgList @(
    '--json', 'remember', "disposable $marker", '--title', "discard-$stamp", '--force', '--importance', 'important'
) -DataDir $DirA -TimeoutSec 300
$dispId = [string]$disp.Envelope.summary.id

$mergeA = Invoke-Om -Name 'merge-src-a' -ArgList @(
    '--json', 'remember', "merge source A $marker",
    '--title', "merge-a-$stamp", '--type', 'decision', '--importance', 'important', '--force', '--project', 'respire-cli'
) -DataDir $DirA -TimeoutSec 180
$mergeAId = [string]$mergeA.Envelope.summary.id
if (-not $mergeAId) { throw 'merge-src-a returned no id' }
$mergeShort = $mergeAId.Substring(0, [Math]::Min(8, $mergeAId.Length))
Invoke-Om -Name 'merge-src-b' -ArgList @(
    '--json', 'remember', "merge source B $marker",
    '--title', "merge-b-$stamp", '--type', 'decision', '--importance', 'important', '--force', '--project', 'respire-cli'
) -DataDir $DirA -TimeoutSec 180 | Out-Null
$merged = Invoke-Om -Name 'merge-ids-short-and-title' -ArgList @(
    '--json', 'remember', "merged $marker",
    '--title', "merge-result-$stamp", '--merge-ids', "$mergeShort,merge-b-$stamp",
    '--type', 'decision', '--importance', 'important', '--force', '--project', 'respire-cli'
) -DataDir $DirA -TimeoutSec 180
if (-not $merged.Ok) { throw 'merge-ids failed' }
if ([int]$merged.Envelope.summary.dropped -lt 2) {
    throw "merge-ids dropped=$($merged.Envelope.summary.dropped); the short id or taxonomy name was not removed"
}
$gone = Invoke-Om -Name 'merge-old-gone' -ArgList @('--json', 'show', $mergeShort) -DataDir $DirA -ExpectExit @(1, 2) -AllowStatus @('fail')
if ($gone.Exit -eq 0) { throw "the old short id $mergeShort still resolves after the merge, so the old entry is still there" }

# Full merge regressions: both input orders, a root and an external parent,
# surviving descendants, and rejection before deleting any source.
foreach ($rootCase in @($true, $false)) {
    foreach ($reverseCase in @($false, $true)) {
        $case = "merge-tree-$rootCase-$reverseCase"
        $expectedParent = if ($rootCase) { '' } else { $id }
        $argsA = @('--json', 'remember', "$case ancestor $marker", '--title', "$case-a-$stamp", '--importance', 'important', '--force')
        if ($expectedParent) { $argsA += @('--parent', $expectedParent) }
        $aResult = Invoke-Om -Name "$case-create-a" -ArgList $argsA -DataDir $DirA
        $aId = [string]$aResult.Envelope.summary.id
        $bResult = Invoke-Om -Name "$case-create-b" -ArgList @('--json', 'remember', "$case child $marker", '--title', "$case-b-$stamp", '--importance', 'important', '--parent', $aId) -DataDir $DirA
        $bId = [string]$bResult.Envelope.summary.id
        $leafResult = Invoke-Om -Name "$case-create-leaf" -ArgList @('--json', 'remember', "$case leaf $marker", '--title', "$case-leaf-$stamp", '--importance', 'important', '--parent', $bId) -DataDir $DirA
        $leafId = [string]$leafResult.Envelope.summary.id
        $mergeIds = if ($reverseCase) { "$bId,$aId" } else { "$aId,$bId" }
        $rejected = Invoke-Om -Name "$case-reject-deleted-parent" -ArgList @('--json', 'remember', "$case rejected", '--title', "$case-rejected", '--importance', 'important', '--merge-ids', $mergeIds, '--parent', $aId) -DataDir $DirA -ExpectExit @(1) -AllowStatus @('fail')
        if (-not $rejected.Ok) { throw "$case did not reject a merged parent" }
        Invoke-Om -Name "$case-source-survives" -ArgList @('--json', 'show', $aId) -DataDir $DirA | Out-Null
        $result = Invoke-Om -Name "$case-apply" -ArgList @('--json', 'remember', "$case combined $marker", '--title', "$case-result-$stamp", '--importance', 'important', '--merge-ids', $mergeIds) -DataDir $DirA
        if (-not $result.Ok -or [string]$result.Envelope.summary.parent -ne $expectedParent -or [int]$result.Envelope.summary.dropped -ne 2) { throw "$case wrong merge result" }
        $leafResult = Invoke-Om -Name "$case-leaf-parent" -ArgList @('--json', 'show', $leafId) -DataDir $DirA
        if ([string]$leafResult.Envelope.details.entry.parent_id -ne $expectedParent) { throw "$case lost descendant ancestry" }
        $treeAudit = Invoke-Om -Name "$case-audit" -ArgList @('--json', 'audit') -DataDir $DirA
        if ([int]$treeAudit.Envelope.summary.orphans -ne 0) { throw "$case left orphans" }
    }
}

$recA = Invoke-Om -Name 'recall' -ArgList @('--json', 'recall', $marker, '--limit', '3', '--project', 'respire-cli') -DataDir $DirA -TimeoutSec 180
if ($recA.Stdout -notlike "*$marker*") { throw "A recall did not return the marker $marker" }
Invoke-Om -Name 'recall-human' -ArgList @('recall', $marker, '--limit', '3') -DataDir $DirA -Raw -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'recall-trace' -ArgList @('--json', 'recall', $marker, '--trace', '--limit', '3') -DataDir $DirA -TimeoutSec 180 | Out-Null
$filtered = Invoke-Om -Name 'recall-filtered-titles' -ArgList @('--json', 'recall', $marker, '--mode', 'fast', '--type', 'decision', '--project', 'respire-cli', '--titles', '--limit', '10') -DataDir $DirA
Assert-Smoke 'recall-filtered-marker-title' ($filtered.Ok -and $filtered.Stdout -like "*$title*")
Invoke-Om -Name 'list-since' -ArgList @('--json', 'list', '--since', '2000-01-01', '--limit', '100') -DataDir $DirA | Out-Null
Invoke-Om -Name 'list-since-resort' -ArgList @('--json', 'list', '--since-resort', '--limit', '100') -DataDir $DirA | Out-Null
$listSnapshot = Invoke-Om -Name 'list' -ArgList @('--json', 'list', '--limit', '10') -DataDir $DirA
Assert-Smoke 'list-profile-contract' ($listSnapshot.Ok -and [string]$listSnapshot.Envelope.summary.profile -ceq [string]$revisionInitial.Envelope.summary.profile)
Invoke-Om -Name 'list-human' -ArgList @('list', '--limit', '5') -DataDir $DirA -Raw | Out-Null
Invoke-Om -Name 'show' -ArgList @('--json', 'show', $short) -DataDir $DirA | Out-Null
Invoke-Om -Name 'show-human' -ArgList @('show', $short) -DataDir $DirA -Raw | Out-Null
Invoke-Om -Name 'chain' -ArgList @('--json', 'chain', $short, '--depth', '2') -DataDir $DirA | Out-Null
Invoke-Om -Name 'candidates' -ArgList @('--json', 'candidates', "dev sweep marker $marker") -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'update' -ArgList @('--json', 'update', $short, '--title', "sweep-updated-$stamp", '--content', "updated $marker") -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'retitle' -ArgList @('--json', 'retitle', $short, '--title', $title) -DataDir $DirA -TimeoutSec 180 | Out-Null
$retitleFile = Join-Path $Work 'retitle.json'
[System.IO.File]::WriteAllText($retitleFile, "[{`"id`":`"$id`",`"title`":`"$title`"}]", [Text.UTF8Encoding]::new($false))
Invoke-Om -Name 'retitle-many' -ArgList @('--json', 'retitle-many', $retitleFile) -DataDir $DirA -TimeoutSec 180 | Out-Null
$updated = Invoke-Om -Name 'update-readback' -ArgList @('--json', 'show', $id) -DataDir $DirA
Assert-Smoke 'update-title-content-persisted' ($updated.Ok -and [string]$updated.Envelope.details.entry.title -eq $title -and [string]$updated.Envelope.details.entry.content -eq "updated $marker")
if ($childId) {
    Invoke-Om -Name 'attach' -ArgList @('--json', 'attach', $childId, '--parent', $short) -DataDir $DirA | Out-Null
    Invoke-Om -Name 'demote' -ArgList @('--json', 'demote', $childId, '--parent', $short) -DataDir $DirA | Out-Null
    Invoke-Om -Name 'promote' -ArgList @('--json', 'promote', $childId) -DataDir $DirA | Out-Null
}
Invoke-Om -Name 'tree' -ArgList @('--json', 'tree', '--depth', '3') -DataDir $DirA | Out-Null
Invoke-Om -Name 'tree-outline' -ArgList @('--json', 'tree', '--outline') -DataDir $DirA | Out-Null
Invoke-Om -Name 'tree-from' -ArgList @('--json', 'tree', '--from', $short, '--depth', '2') -DataDir $DirA | Out-Null
Invoke-Om -Name 'tree-material' -ArgList @('--json', 'tree', '--material', $short) -DataDir $DirA | Out-Null
Invoke-Om -Name 'diary' -ArgList @('--json', 'diary', '--limit', '5') -DataDir $DirA | Out-Null
Invoke-Om -Name 'diary-today' -ArgList @('--json', 'diary', '--date', 'today') -DataDir $DirA | Out-Null
$diaryFiltered = Invoke-Om -Name 'diary-range-contains' -ArgList @('--json', 'diary', '--from', '2000-01-01', '--to', '2100-01-01', '--contains', $marker, '--limit', '100') -DataDir $DirA
Assert-Smoke 'diary-filter-contains-marker' ($diaryFiltered.Ok -and $diaryFiltered.Stdout -like "*$marker*")
Invoke-Om -Name 'history' -ArgList @('--json', 'history', $short, '--limit', '10') -DataDir $DirA | Out-Null
Invoke-Om -Name 'query-log' -ArgList @('--json', 'query-log', '--limit', '10') -DataDir $DirA | Out-Null
Invoke-Om -Name 'query-log-stats' -ArgList @('--json', 'query-log', '--stats') -DataDir $DirA | Out-Null
$markRecall = Invoke-Om -Name 'query-log-mark-candidates' -ArgList @('--json', 'recall', $marker, '--titles', '--limit', '3') -DataDir $DirA -TimeoutSec 180
$markCandidates = @($markRecall.Envelope.details)
if (-not $markRecall.Ok -or $markCandidates.Count -eq 0) { throw 'No fresh candidates for query-log prefix verification' }
$markId = [string]$markCandidates[0].id
if ($markId.Length -lt 8) { throw 'Recall did not return a usable candidate UUID' }
$marked = Invoke-Om -Name 'query-log-mark' -ArgList @('--json', 'query-log', 'mark', $markId.Substring(0, 8), '--good') -DataDir $DirA
if (-not $marked.Ok -or [int]$marked.Envelope.summary.marked -ne 1) { throw 'Fresh 8-character candidate prefix was not marked' }
Invoke-Om -Name 'audit' -ArgList @('--json', 'audit') -DataDir $DirA | Out-Null
Invoke-Om -Name 'resort-status' -ArgList @('--json', 'resort', '--status') -DataDir $DirA | Out-Null
Invoke-Om -Name 'resort-threshold' -ArgList @('--json', 'resort', '--threshold', '50') -DataDir $DirA | Out-Null
if ($childId) {
    $spec = (@{ ops = @(@{ id = $childId; parent = $id }) } | ConvertTo-Json -Compress)
    Invoke-Om -Name 'resort-dry' -ArgList @('--json', 'resort', '--spec', $spec) -DataDir $DirA -AllowStatus @('ok', 'pending', 'warn') -Note 'without --go it must be pending' | Out-Null
}
Invoke-Om -Name 'defrag' -ArgList @('--json', 'defrag', '--top', '5') -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'tree-cure' -ArgList @('--json', 'tree-cure', '--top', '5') -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'tree-float' -ArgList @('--json', 'tree-float') -DataDir $DirA | Out-Null
Invoke-Om -Name 'split-material' -ArgList @('--json', 'split', $short) -DataDir $DirA | Out-Null
$splitEntry = Invoke-Om -Name 'split-fixture-create' -ArgList @('--json', 'remember', "split fixture $stamp", '--title', "split-$stamp", '--parent', $id, '--importance', 'important', '--force') -DataDir $DirA
$splitId = [string]$splitEntry.Envelope.summary.id
Assert-Smoke 'split-fixture-id' ($splitEntry.Ok -and [bool]$splitId)
$splitSummary = "split outline $stamp"
$splitSpec = @{ summary = $splitSummary; items = @(
    @{ title = "split-a-$stamp"; content = "split child A $stamp"; kind = 'context'; tags = @('smoke') },
    @{ title = "split-b-$stamp"; content = "split child B $stamp"; kind = 'context'; tags = @('smoke') }
) } | ConvertTo-Json -Compress -Depth 8
$splitApply = Invoke-Om -Name 'split-go' -ArgList @('--json', 'split', $splitId, '--go', '--spec', $splitSpec) -DataDir $DirA
$splitRead = Invoke-Om -Name 'split-summary-readback' -ArgList @('--json', 'show', $splitId) -DataDir $DirA
$splitTree = Invoke-Om -Name 'split-children-readback' -ArgList @('--json', 'tree', '--from', $splitId, '--depth', '2') -DataDir $DirA
Assert-Smoke 'split-created-two-children' ($splitApply.Ok -and [int]$splitApply.Envelope.summary.created -eq 2 -and $splitRead.Ok -and [string]$splitRead.Envelope.details.entry.content -eq $splitSummary -and $splitTree.Stdout -like "*split-a-$stamp*" -and $splitTree.Stdout -like "*split-b-$stamp*")
if ($childId) {
    $applySpec = @{ ops = @(@{ id = $childId; parent = $splitId }) } | ConvertTo-Json -Compress -Depth 8
    $resortApply = Invoke-Om -Name 'resort-go' -ArgList @('--json', 'resort', '--go', '--spec', $applySpec) -DataDir $DirA
    $resortRead = Invoke-Om -Name 'resort-parent-readback' -ArgList @('--json', 'show', $childId) -DataDir $DirA
    Assert-Smoke 'resort-parent-persisted' ($resortApply.Ok -and $resortRead.Ok -and [string]$resortRead.Envelope.details.entry.parent_id -eq $splitId)
    $cureApply = Invoke-Om -Name 'tree-cure-attach' -ArgList @('--json', 'tree-cure', '--id', $childId, '--parent', $id) -DataDir $DirA
    $cureRead = Invoke-Om -Name 'tree-cure-parent-readback' -ArgList @('--json', 'show', $childId) -DataDir $DirA
    Assert-Smoke 'tree-cure-parent-persisted' ($cureApply.Ok -and $cureRead.Ok -and [string]$cureRead.Envelope.details.entry.parent_id -eq $id)
}
Invoke-Om -Name 'resort-reset' -ArgList @('--json', 'resort', '--reset') -DataDir $DirA | Out-Null
Invoke-Om -Name 'tree-float-go' -ArgList @('--json', 'tree-float', '--go') -DataDir $DirA | Out-Null
$structuralAudit = Invoke-Om -Name 'tree-mutations-audit' -ArgList @('--json', 'audit') -DataDir $DirA
Assert-Smoke 'tree-mutations-no-orphans' ($structuralAudit.Ok -and [int]$structuralAudit.Envelope.summary.orphans -eq 0)
Invoke-Om -Name 'tree-deepen' -ArgList @('--json', 'tree-deepen', '--root', $short) -DataDir $DirA -AllowStatus @('ok', 'fail') -Note 'a small tree must refuse deepening' | Out-Null
Invoke-Om -Name 'classify-plan' -ArgList @('--json', 'classify', '--plan', '--limit', '5') -DataDir $DirA | Out-Null
Invoke-Om -Name 'classify-dry-run' -ArgList @('--json', 'classify', '--dry-run', '--limit', '1') -DataDir $DirA | Out-Null
Invoke-Om -Name 'repack' -ArgList @('--json', 'repack') -DataDir $DirA -TimeoutSec 300 | Out-Null
$beforeReembed = Invoke-Om -Name 'reembed-before-readback' -ArgList @('--json', 'show', $id) -DataDir $DirA
$entryBeforeReembed = $beforeReembed.Envelope.details.entry | ConvertTo-Json -Depth 20 -Compress
$reembedTask = [Guid]::NewGuid().ToString('N')
$reembed = Invoke-Om -Name 'reembed' -ArgList @('--json', 'reembed') -DataDir $DirA -TimeoutSec 300 -ModelTaskId $reembedTask
$invalidProgress = @($reembed.Progress | Where-Object {
    [string]$_.id -cne $reembedTask -or $_.phase -notin @('load', 'index-load', 'index') -or $_.cancelled -ne $false `
        -or ($_.done -isnot [long] -and $_.done -isnot [int]) -or $_.done -lt 0 `
        -or ($null -ne $_.total -and (($_.total -isnot [long] -and $_.total -isnot [int]) -or $_.total -lt $_.done))
})
$script:ModelProgressEvidence.contract = @{
    reembed_ok = [bool]$reembed.Ok
    invalid_count = $invalidProgress.Count
    completed_inactive = [bool]$script:ModelProgressEvidence.completed_inactive
    return_object_count = @($reembed).Count
    returned_sample_count = @($reembed.Progress).Count
    invalid_id_count = @($reembed.Progress | Where-Object { [string]$_.id -cne $reembedTask }).Count
    invalid_phase_count = @($reembed.Progress | Where-Object { $_.phase -notin @('load', 'index-load', 'index') }).Count
    invalid_cancelled_count = @($reembed.Progress | Where-Object { $_.cancelled -ne $false }).Count
    invalid_done_count = @($reembed.Progress | Where-Object { ($_.done -isnot [long] -and $_.done -isnot [int]) -or $_.done -lt 0 }).Count
    invalid_total_count = @($reembed.Progress | Where-Object { $null -ne $_.total -and (($_.total -isnot [long] -and $_.total -isnot [int]) -or $_.total -lt $_.done) }).Count
}
Assert-Smoke 'reembed-progress-contract' (@($reembed).Count -eq 1 -and $reembed.Ok -and $invalidProgress.Count -eq 0 -and $script:ModelProgressEvidence.completed_inactive)
Assert-Smoke 'reembed-count-dimensions' (($reembed.Envelope.summary.reembedded -is [long] -or $reembed.Envelope.summary.reembedded -is [int]) -and [long]$reembed.Envelope.summary.reembedded -ge 0 -and [int]$reembed.Envelope.summary.dims -eq 1024)
$afterReembed = Invoke-Om -Name 'reembed-after-readback' -ArgList @('--json', 'show', $id) -DataDir $DirA
Assert-Smoke 'reembed-entry-preserved' ($beforeReembed.Ok -and $afterReembed.Ok -and [string]$afterReembed.Envelope.details.entry.id -ceq $id -and ($afterReembed.Envelope.details.entry | ConvertTo-Json -Depth 20 -Compress) -ceq $entryBeforeReembed)
$cachedReembed = Invoke-Om -Name 'reembed-cached' -ArgList @('--json', 'reembed') -DataDir $DirA -TimeoutSec 300
Assert-Smoke 'reembed-cached-zero' ($cachedReembed.Ok -and ($cachedReembed.Envelope.summary.reembedded -is [long] -or $cachedReembed.Envelope.summary.reembedded -is [int]) -and [long]$cachedReembed.Envelope.summary.reembedded -eq 0 -and [int]$cachedReembed.Envelope.summary.dims -eq 1024)
Invoke-Om -Name 'book-material' -ArgList @('--json', 'book-material', $short) -DataDir $DirA | Out-Null
Invoke-Om -Name 'portrait-material' -ArgList @('--json', 'portrait-material', '--limit', '10') -DataDir $DirA | Out-Null
Invoke-Om -Name 'passport' -ArgList @('--json', 'passport') -DataDir $DirA | Out-Null
$shareFile = Join-Path $Work 'share.txt'
Invoke-Om -Name 'share' -ArgList @('--json', 'share', '--root', $short, '--out', $shareFile) -DataDir $DirA | Out-Null
if (Test-Path $shareFile) {
    Invoke-Om -Name 'share-import-preview' -ArgList @('--json', 'share-import', $shareFile) -DataDir $DirA -AllowStatus @('ok', 'pending', 'warn') -Note 'a pending preview has status=pending and exit 2' | Out-Null
    Invoke-Om -Name 'share-import-go' -ArgList @('--json', 'share-import', $shareFile, '--go', '--force', '--title', "imported-$stamp") -DataDir $DirA | Out-Null
}
$exportFile = Join-Path $Work 'export.json'
$backupFile = Join-Path $Work 'backup.sqlite'
$missingOutput = Join-Path $Work 'missing-output/unused.json'
$modeConfigBefore = [IO.File]::ReadAllBytes((Join-Path $DirA 'client.json'))
foreach ($invalidOutput in @(
    @{ Name = 'export-missing-output'; Args = @('--json', 'export', $missingOutput) },
    @{ Name = 'backup-missing-output'; Args = @('--json', 'backup', $missingOutput) },
    @{ Name = 'agent-config-invalid-mode'; Args = @('--json', 'agent-config', '--set', 'workspace_mode=bogus') }
)) {
    $rejectedOutput = Invoke-Om -Name $invalidOutput.Name -ArgList $invalidOutput.Args -DataDir $DirA -AllowStatus @('fail')
    Assert-Smoke "$($invalidOutput.Name)-input-contract" ($rejectedOutput.Ok -and $rejectedOutput.Exit -eq 2 -and [string]$rejectedOutput.Envelope.summary.reason -eq 'invalid_input' -and [string]$rejectedOutput.Envelope.details.error_type -eq 'user')
}
Assert-Smoke 'invalid-output-does-not-create-directory' (-not (Test-Path -LiteralPath (Split-Path -Parent $missingOutput)))
Assert-Smoke 'invalid-mode-preserves-config' ([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $DirA 'client.json'))) -ceq [Convert]::ToBase64String($modeConfigBefore))
Invoke-Om -Name 'export' -ArgList @('--json', 'export', $exportFile) -DataDir $DirA | Out-Null
if (-not (Test-Path $exportFile) -or (Get-Item $exportFile).Length -lt 10) { throw 'export wrote no non-empty file' }
Invoke-Om -Name 'backup' -ArgList @('--json', 'backup', $backupFile) -DataDir $DirA | Out-Null
Assert-Smoke 'backup-file-sqlite-header' ((Test-Path -LiteralPath $backupFile) -and (Get-Item -LiteralPath $backupFile).Length -gt 16 -and [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($backupFile)[0..15]) -eq "SQLite format 3`0")
$imported = Invoke-Om -Name 'import' -ArgList @('--json', 'import', $exportFile) -DataDir $DirA -TimeoutSec 300
if (-not $imported.Ok) { throw 'import failed' }
$evalFile = Join-Path $Work 'eval.jsonl'
[System.IO.File]::WriteAllText($evalFile, "{`"query`":`"$marker`",`"expect`":[`"$short`"]}`n", [Text.UTF8Encoding]::new($false))
$benchOut = Join-Path $Work 'bench.json'
Invoke-Om -Name 'bench-mine' -ArgList @('--json', 'bench', 'mine', '--out', (Join-Path $Work 'mined.jsonl'), '--limit', '5') -DataDir $DirA | Out-Null
Invoke-Om -Name 'bench-run' -ArgList @('--json', 'bench', 'run', $evalFile, '--save', $benchOut, '--verbose') -DataDir $DirA -TimeoutSec 180 | Out-Null
if (Test-Path $benchOut) {
    Invoke-Om -Name 'bench-baseline' -ArgList @('--json', 'bench', 'run', $evalFile, '--baseline', $benchOut) -DataDir $DirA -TimeoutSec 180 | Out-Null
}
Invoke-Om -Name 'keygen-refuse' -ArgList @('--json', 'keygen') -DataDir $DirA -AllowStatus @('fail') -Note 'a cloud key already exists, so overwriting must be refused' | Out-Null
Invoke-Om -Name 'secret-masked' -ArgList @('--json', 'secret') -DataDir $DirA -Secret | Out-Null
Invoke-Om -Name 'keys-export' -ArgList @('--json', 'keys-export', '--out', (Join-Path $Secrets 'keys.txt')) -DataDir $DirA -Secret | Out-Null
Invoke-Om -Name 'account-list' -ArgList @('--json', 'account', 'list') -DataDir $DirA | Out-Null
$otherUser = "oth$stamp"
$otherPass = New-Pass
$otherCloudAccount = Add-CloudRegistration $otherUser $otherPass
$otherReg = Invoke-Om -Name 'register-second-user' -ArgList @('--json', 'register', '--addr', $Server, '--user', $otherUser, '--pass', $otherPass) -DataDir $DirA -Secret -HostProfile
Confirm-CloudRegistration $otherCloudAccount $otherReg
if (-not $otherReg.Ok) { throw 'registering a second user failed while a main account exists; it must not report none in the local keyring.' }
if (-not $otherReg.Envelope.summary.super) { throw 'the second user register did not issue a new super' }
# Exercise host takeover while the actual fixture runtime is still serving.
Invoke-Om -Name 'account-live-initial-status' -ArgList @('--json', 'status') -DataDir $DirA | Out-Null
$otherHealth = Get-OwnedRuntimeHealth $DirA
$accountMain = Invoke-Om -Name 'account-back-after-second-register' -ArgList @('--json', 'account', 'use', 'main') -DataDir $DirA
$mainHealth = Get-OwnedRuntimeHealth $DirA
Assert-Smoke 'account-live-main-takeover' ($accountMain.Ok -and (Test-RuntimeChanged $otherHealth $mainHealth $DirA))
$mainEntry = Invoke-Om -Name 'account-live-main-readback' -ArgList @('--json', 'show', $id) -DataDir $DirA
Assert-Smoke 'account-live-main-library-preserved' ($mainEntry.Ok -and [string]$mainEntry.Envelope.details.entry.id -ceq $id -and [string]$mainEntry.Envelope.details.entry.content -ceq [string]$afterReembed.Envelope.details.entry.content)
$accountOther = Invoke-Om -Name 'account-live-shorthand' -ArgList @('--json', 'account', $otherUser) -DataDir $DirA
$switchedHealth = Get-OwnedRuntimeHealth $DirA
$otherStatus = Invoke-Om -Name 'account-live-other-status' -ArgList @('--json', 'status') -DataDir $DirA
Assert-Smoke 'account-live-shorthand-takeover' ($accountOther.Ok -and (Test-RuntimeChanged $mainHealth $switchedHealth (Join-Path $DirA "accounts/$otherUser")))
Assert-Smoke 'account-live-other-identity' ($otherStatus.Ok -and [string]$otherStatus.Envelope.summary.session.user -ceq $otherUser -and $otherStatus.Envelope.summary.unlocked -eq $true)
$profileConfig = [IO.File]::ReadAllBytes((Join-Path $DirA 'client.json'))
$invalidAccount = Invoke-Om -Name 'account-live-invalid-rejected' -ArgList @('--json', 'account', 'use', '../invalid') -DataDir $DirA -AllowStatus @('fail')
$rejectedHealth = Get-OwnedRuntimeHealth $DirA
Assert-Smoke 'account-live-rejected-restores-service' ($invalidAccount.Ok -and $invalidAccount.Exit -eq 1 -and ($invalidAccount.Envelope.errors -join ' ') -match 'profile name allows' -and (Test-RuntimeChanged $switchedHealth $rejectedHealth (Join-Path $DirA "accounts/$otherUser")) -and [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $DirA 'client.json'))) -ceq [Convert]::ToBase64String($profileConfig))
$clientSwitch = Invoke-Om -Name 'account-live-client-only-rejected' -ArgList @('--client-only', '--json', 'account', 'use', 'main') -DataDir $DirA -AllowStatus @('fail')
$clientHealth = Get-OwnedRuntimeHealth $DirA
Assert-Smoke 'account-live-client-only-preserves-host' ($clientSwitch.Ok -and $clientSwitch.Exit -eq 1 -and ($clientSwitch.Envelope.errors -join ' ') -match 'client.only' -and [int]$clientHealth.pid -eq [int]$rejectedHealth.pid -and [string]$clientHealth.data_dir -ceq [string]$rejectedHealth.data_dir -and [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $DirA 'client.json'))) -ceq [Convert]::ToBase64String($profileConfig))
$accountRestore = Invoke-Om -Name 'account-live-restore-main' -ArgList @('--json', 'account', 'use', 'main') -DataDir $DirA
$restoredHealth = Get-OwnedRuntimeHealth $DirA
Assert-Smoke 'account-live-restore-main-takeover' ($accountRestore.Ok -and (Test-RuntimeChanged $clientHealth $restoredHealth $DirA))
$configOther = Invoke-Om -Name 'config-live-profile' -ArgList @('--json', 'config', '--data-dir', (Join-Path $DirA "accounts/$otherUser")) -DataDir $DirA
$configOtherHealth = Get-OwnedRuntimeHealth $DirA
Assert-Smoke 'config-live-profile-takeover' ($configOther.Ok -and (Test-RuntimeChanged $restoredHealth $configOtherHealth (Join-Path $DirA "accounts/$otherUser")))
$configMain = Invoke-Om -Name 'config-live-restore-main' -ArgList @('--json', 'config', '--data-dir', $DirA) -DataDir $DirA
$configMainHealth = Get-OwnedRuntimeHealth $DirA
Assert-Smoke 'config-live-restore-main-takeover' ($configMain.Ok -and (Test-RuntimeChanged $configOtherHealth $configMainHealth $DirA))
$accountRemove = Invoke-Om -Name 'account-remove-disposable' -ArgList @('--json', 'account', 'remove', $otherUser, '--yes') -DataDir $DirA -HostProfile
$accountAfterRemove = Invoke-Om -Name 'account-remove-list-readback' -ArgList @('--json', 'account', 'list') -DataDir $DirA
Assert-Smoke 'account-remove-profile-gone' ($accountRemove.Ok -and $accountAfterRemove.Ok -and -not (Test-Path -LiteralPath (Join-Path $DirA "accounts/$otherUser")) -and @($accountAfterRemove.Envelope.details.accounts | Where-Object { [string]$_.name -eq $otherUser }).Count -eq 0)
Invoke-Om -Name 'space-list' -ArgList @('--json', 'space', 'list') -DataDir $DirA | Out-Null
Invoke-Om -Name 'space-create' -ArgList @('--json', 'space', 'create', 'sweepspace') -DataDir $DirA -HostProfile | Out-Null
$spaceUser = "sps$stamp"
$spacePass = New-Pass
$spaceCloudAccount = Add-CloudRegistration $spaceUser $spacePass
$spaceReg = Invoke-Om -Name 'space-register' -ArgList @('--json', 'register', '--addr', $Server, '--user', $spaceUser, '--pass', $spacePass) -DataDir $DirA -Secret
Confirm-CloudRegistration $spaceCloudAccount $spaceReg
if (-not $spaceReg.Ok) { throw 'register failed on the space profile. An empty profile must issue a new super and must not report none in the local keyring.' }
if (-not $spaceReg.Envelope.summary.super) { throw 'space register did not issue a new super' }
$spaceMarker = "space-marker-$stamp"
$spaceWrite = Invoke-Om -Name 'space-owner-write' -ArgList @('--json', 'remember', $spaceMarker, '--title', $spaceMarker, '--importance', 'important', '--force') -DataDir $DirA
$spaceEntryId = [string]$spaceWrite.Envelope.summary.id
$spaceSync = Invoke-Om -Name 'space-owner-sync' -ArgList @('--json', 'sync') -DataDir $DirA
Assert-Smoke 'space-owner-entry-synced' ($spaceWrite.Ok -and [bool]$spaceEntryId -and $spaceSync.Ok -and [int]$spaceSync.Envelope.summary.pushed -gt 0)
$spaceHealth = Get-OwnedRuntimeHealth $DirA
$spaceMain = Invoke-Om -Name 'space-live-main' -ArgList @('--json', 'space', 'use', 'main') -DataDir $DirA
$spaceMainHealth = Get-OwnedRuntimeHealth $DirA
Assert-Smoke 'space-live-main-takeover' ($spaceMain.Ok -and (Test-RuntimeChanged $spaceHealth $spaceMainHealth $DirA))
$spaceReturn = Invoke-Om -Name 'space-live-return' -ArgList @('--json', 'space', 'use', 'sweepspace') -DataDir $DirA
$spaceReturnHealth = Get-OwnedRuntimeHealth $DirA
$spaceReadback = Invoke-Om -Name 'space-live-return-readback' -ArgList @('--json', 'show', $spaceEntryId) -DataDir $DirA
Assert-Smoke 'space-live-return-takeover' ($spaceReturn.Ok -and (Test-RuntimeChanged $spaceMainHealth $spaceReturnHealth (Join-Path $DirA 'accounts/sweepspace')))
Assert-Smoke 'space-live-library-preserved' ($spaceReadback.Ok -and [string]$spaceReadback.Envelope.details.entry.id -ceq $spaceEntryId -and [string]$spaceReadback.Envelope.details.entry.content -ceq $spaceMarker)
$spaceProfileConfig = [IO.File]::ReadAllBytes((Join-Path $DirA 'client.json'))
$missingSpace = "missing$stamp"
$spaceRejected = Invoke-Om -Name 'space-live-missing-rejected' -ArgList @('--json', 'space', 'use', $missingSpace) -DataDir $DirA -AllowStatus @('fail')
$spaceRejectedHealth = Get-OwnedRuntimeHealth $DirA
Assert-Smoke 'space-live-rejected-restores-service' ($spaceRejected.Ok -and $spaceRejected.Exit -eq 2 -and [string]$spaceRejected.Envelope.summary.reason -eq 'invalid_input' -and [string]$spaceRejected.Envelope.details.error_type -eq 'user' -and ($spaceRejected.Envelope.errors -join ' ') -match ('space "' + [regex]::Escape($missingSpace) + '" does not exist') -and -not (Test-Path -LiteralPath (Join-Path $DirA "accounts/$missingSpace")) -and (Test-RuntimeChanged $spaceReturnHealth $spaceRejectedHealth (Join-Path $DirA 'accounts/sweepspace')) -and [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $DirA 'client.json'))) -ceq [Convert]::ToBase64String($spaceProfileConfig))
$inv = Invoke-Om -Name 'space-invite' -ArgList @('--json', 'space', 'invite', '--note', 'sweep') -DataDir $DirA -Secret
Invoke-Om -Name 'space-members' -ArgList @('--json', 'space', 'members') -DataDir $DirA | Out-Null
$inviteCode = ''
$memberSid = ''
if ($inv.Envelope.details.code) { $inviteCode = [string]$inv.Envelope.details.code }
if ($inv.Envelope.details.session_id) { $memberSid = [string]$inv.Envelope.details.session_id }
Assert-Smoke 'space-invite-code-session-present' ($inv.Ok -and [bool]$inviteCode -and [bool]$memberSid)
$DirC = Join-Path $Root 'c'
if ($inviteCode) {
    Invoke-Om -Name 'config-addr-c' -ArgList @('--json', 'config', '--addr', $Server) -DataDir $DirC | Out-Null
    Invoke-Om -Name 'space-join' -ArgList @('--json', 'space', 'join', $inviteCode) -DataDir $DirC -Secret -HostProfile | Out-Null
    Invoke-Om -Name 'space-use-c' -ArgList @('--json', 'space', 'use', 'sweepspace') -DataDir $DirC -HostProfile | Out-Null
    $stC = Invoke-Om -Name 'status-c' -ArgList @('--json', 'status') -DataDir $DirC
    $addrC = ''
    if ($stC.Envelope.summary.server_addr) { $addrC = [string]$stC.Envelope.summary.server_addr }
    if ($addrC -ne $Server) { throw "server_addr=$addrC after space join" }
    $spacePull = Invoke-Om -Name 'space-member-sync' -ArgList @('--json', 'sync') -DataDir $DirC
    $spaceRead = Invoke-Om -Name 'space-member-readback' -ArgList @('--json', 'show', $spaceEntryId) -DataDir $DirC
    Assert-Smoke 'space-member-can-read-owner-entry' ($spacePull.Ok -and $spaceRead.Ok -and [string]$spaceRead.Envelope.details.entry.content -eq $spaceMarker)
}
$readonlyTombstone = Invoke-Om -Name 'space-readonly-tombstone-create' -ArgList @('--json', 'remember', "readonly-tombstone-$stamp", '--title', 'readonly-tombstone', '--importance', 'important', '--force') -DataDir $DirA
$readonlyTombstoneId = [string]$readonlyTombstone.Envelope.summary.id
$readonlyDeleted = Invoke-Om -Name 'space-readonly-tombstone-delete' -ArgList @('--json', 'forget', $readonlyTombstoneId) -DataDir $DirA
$readonlySeedSync = Invoke-Om -Name 'space-readonly-tombstone-sync' -ArgList @('--json', 'sync') -DataDir $DirA
Assert-Smoke 'space-readonly-tombstone-ready' ($readonlyTombstone.Ok -and [bool]$readonlyTombstoneId -and $readonlyDeleted.Ok -and $readonlySeedSync.Ok)
$readonlyInvite = Invoke-Om -Name 'space-invite-readonly' -ArgList @('--json', 'space', 'invite', '--readonly', '--note', 'readonly-smoke') -DataDir $DirA -Secret -AllowStatus @('warn')
$readonlyCode = [string]$readonlyInvite.Envelope.details.code
Assert-Smoke 'space-readonly-invite-present' ($readonlyInvite.Ok -and $readonlyInvite.Envelope.details.readonly -eq $true -and [bool]$readonlyCode)
$readonlyDir = Join-Path $Root 'readonly-member'
Invoke-Om -Name 'space-readonly-config' -ArgList @('--json', 'config', '--addr', $Server, '--autosync', 'false') -DataDir $readonlyDir | Out-Null
$readonlyJoin = Invoke-Om -Name 'space-readonly-join' -ArgList @('--json', 'space', 'join', $readonlyCode) -DataDir $readonlyDir -Secret -HostProfile -AllowStatus @('warn')
Invoke-Om -Name 'space-readonly-use' -ArgList @('--json', 'space', 'use', 'sweepspace') -DataDir $readonlyDir -HostProfile | Out-Null
Invoke-Om -Name 'space-readonly-immediate-purge-config' -ArgList @('--json', 'agent-config', '--set', 'purge_days=0') -DataDir $readonlyDir | Out-Null
$readonlyPull = Invoke-Om -Name 'space-readonly-sync' -ArgList @('--json', 'sync') -DataDir $readonlyDir
Assert-Smoke 'space-readonly-no-auto-purge' ($readonlyPull.Ok -and [int]$readonlyPull.Envelope.summary.purged -eq 0 -and [int]$readonlyPull.Envelope.summary.pushed -eq 0 -and [int]$readonlyPull.Envelope.summary.pending -eq 0)
$readonlyRead = Invoke-Om -Name 'space-readonly-show' -ArgList @('--json', 'show', $spaceEntryId) -DataDir $readonlyDir
Assert-Smoke 'space-readonly-can-read' ($readonlyJoin.Ok -and $readonlyPull.Ok -and $readonlyRead.Ok -and [string]$readonlyRead.Envelope.details.entry.content -eq $spaceMarker)
$readonlyWrite = Invoke-Om -Name 'space-readonly-write-refused' -ArgList @('--json', 'remember', "forbidden-$stamp", '--title', 'must-not-write', '--force') -DataDir $readonlyDir -AllowStatus @('fail')
Assert-Smoke 'space-readonly-write-guard' ($readonlyWrite.Ok -and $readonlyWrite.Exit -eq 1 -and ($readonlyWrite.Envelope.errors -join ' ') -match 'read.only')
$readonlyUnlock = Invoke-Om -Name 'space-readonly-self-unlock-refused' -ArgList @('--json', 'agent-config', '--set', 'readonly=false') -DataDir $readonlyDir -AllowStatus @('fail')
Assert-Smoke 'space-readonly-self-unlock-guard' ($readonlyUnlock.Ok -and $readonlyUnlock.Exit -eq 1 -and ($readonlyUnlock.Envelope.errors -join ' ') -match 'read.only')
if ($memberSid) {
    $kick = Invoke-Om -Name 'space-kick' -ArgList @('--json', 'space', 'kick', '--session', $memberSid) -DataDir $DirA
    Assert-Smoke 'space-kick-real-member' ($kick.Ok -and [int]$kick.Envelope.summary.revoked -eq 1 -and [int]$kick.Envelope.summary.failed -eq 0)
    $kickedPull = Invoke-Om -Name 'space-kicked-member-cloud-denied' -ArgList @('--json', 'sync') -DataDir $DirC -AllowStatus @('fail')
    Assert-Smoke 'space-kicked-session-denied' ($kickedPull.Ok -and $kickedPull.Exit -eq 1 -and ($kickedPull.Envelope.errors -join ' ') -match 'unauthorized|token rejected|401')
}
$kickAll = Invoke-Om -Name 'space-kick-all' -ArgList @('--json', 'space', 'kick', '--all') -DataDir $DirA
Assert-Smoke 'space-kick-all-member-sessions' ($kickAll.Ok -and [int]$kickAll.Envelope.summary.revoked -ge 1 -and [int]$kickAll.Envelope.summary.failed -eq 0 -and [int]$kickAll.Envelope.summary.remaining -eq 0)
$readonlyKicked = Invoke-Om -Name 'space-kicked-readonly-cloud-denied' -ArgList @('--json', 'sync') -DataDir $readonlyDir -AllowStatus @('fail')
Assert-Smoke 'space-kicked-readonly-session-denied' ($readonlyKicked.Ok -and $readonlyKicked.Exit -eq 1 -and ($readonlyKicked.Envelope.errors -join ' ') -match 'unauthorized|token rejected|401')
Invoke-Om -Name 'runtime-stop-before-space-remove' -ArgList @('--runtime-internal', '--stop') -DataDir $DirA -Raw -ExpectExit @(0, 2) | Out-Null
Stop-OurRuntimes
Start-Sleep -Seconds 1
Invoke-Om -Name 'account-use-main' -ArgList @('--direct', '--json', 'account', 'use', 'main') -DataDir $DirA -Note 'web --stop may return while the process is still alive; end this runtime first and then use --direct' | Out-Null
Invoke-Om -Name 'space-remove' -ArgList @('--direct', '--json', 'space', 'remove', 'sweepspace', '--yes') -DataDir $DirA | Out-Null
Invoke-Om -Name 'root-create' -ArgList @('--json', 'root-create', "sweep-root-$stamp", '--content', 'disposable acceptance root', '--yes') -DataDir $DirA | Out-Null
$grant = Invoke-Om -Name 'grant-create' -ArgList @('--json', 'grant', 'create', '--root', $id, '--label', 'sweep') -DataDir $DirA -Secret
$grantList = Invoke-Om -Name 'grant-list' -ArgList @('--json', 'grant', 'list') -DataDir $DirA
$grantId = ''
if ($grant.Envelope.details.grant.id) { $grantId = [string]$grant.Envelope.details.grant.id }
elseif ($grant.Envelope.details.id) { $grantId = [string]$grant.Envelope.details.id }
if ($grantId) {
    Assert-Smoke 'grant-created-persisted' ($grant.Ok -and [string]$grant.Envelope.details.token -match '^[0-9a-f]{64}$' -and @($grantList.Envelope.details.grants | Where-Object { $_.id -eq $grantId -and $_.root_id -eq $id -and $_.revoked -eq $false }).Count -eq 1)
    $grantRevoke = Invoke-Om -Name 'grant-revoke' -ArgList @('--json', 'grant', 'revoke', $grantId.Substring(0, 8)) -DataDir $DirA
    $grantRevoked = Invoke-Om -Name 'grant-revoke-readback' -ArgList @('--json', 'grant', 'list') -DataDir $DirA
    Assert-Smoke 'grant-revocation-persisted' ($grantRevoke.Ok -and $grantRevoke.Envelope.details.revoked -eq $true -and @($grantRevoked.Envelope.details.grants | Where-Object { $_.id -eq $grantId -and $_.revoked -eq $true }).Count -eq 1)
} else {
    Assert-Smoke 'grant-created-persisted' $false
}
$grantRoot = Invoke-Om -Name 'grant-delete-root-fixture' -ArgList @('--json', 'remember', "grant-root-$stamp", '--title', "grant-root-$stamp", '--importance', 'important', '--force') -DataDir $DirA
$grantRootId = [string]$grantRoot.Envelope.summary.id
$deleteGrant = Invoke-Om -Name 'grant-delete-root-create' -ArgList @('--json', 'grant', 'create', '--root', $grantRootId, '--label', 'delete-root') -DataDir $DirA -Secret
$deleteGrantId = [string]$deleteGrant.Envelope.details.grant.id
Invoke-Om -Name 'grant-root-forget' -ArgList @('--json', 'forget', $grantRootId) -DataDir $DirA | Out-Null
$autoRevoked = Invoke-Om -Name 'grant-delete-root-readback' -ArgList @('--json', 'grant', 'list') -DataDir $DirA
Assert-Smoke 'grant-delete-root-auto-revoked' ($deleteGrant.Ok -and [bool]$deleteGrantId -and @($autoRevoked.Envelope.details.grants | Where-Object { $_.id -eq $deleteGrantId -and $_.revoked -eq $true }).Count -eq 1)
Invoke-Om -Name 'session-list' -ArgList @('--json', 'session', 'list') -DataDir $DirA -TimeoutSec 120 | Out-Null
Invoke-Om -Name 'session-revoke-bogus' -ArgList @('--json', 'session', 'revoke', '00000000-0000-0000-0000-000000000000') -DataDir $DirA -ExpectExit @(0, 1) -Note 'do not revoke the current session' | Out-Null
$retiredInstall = Invoke-Om -Name 'model-install-rerank' -ArgList @('--json', 'model', 'install-rerank') -DataDir $DirA -ExpectExit @(2) -Raw

$syncA = Invoke-Om -Name 'sync-a' -ArgList @('--json', 'sync') -DataDir $DirA -TimeoutSec 180
if (-not $syncA.Ok) { throw 'A sync failed' }
Assert-Count 'A sync' $syncA.Envelope 'pushed' 1
Invoke-Om -Name 'sync-human' -ArgList @('sync') -DataDir $DirA -Raw -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'sync-conflicts' -ArgList @('--json', 'sync-conflicts') -DataDir $DirA -TimeoutSec 120 | Out-Null
Invoke-Om -Name 'sync-conflicts-all' -ArgList @('--json', 'sync-conflicts', '--all') -DataDir $DirA -TimeoutSec 120 | Out-Null
$hist = Invoke-Om -Name 'sync-history' -ArgList @('--json', 'sync-history', '--id', $short) -DataDir $DirA -TimeoutSec 120
Invoke-Om -Name 'sync-history-remote' -ArgList @('--json', 'sync-history', '--id', $short, '--remote') -DataDir $DirA -TimeoutSec 120 | Out-Null
$restoreFixture = Invoke-Om -Name 'sync-restore-fixture' -ArgList @('--json', 'remember', "restore original $stamp", '--title', "restore-$stamp", '--parent', $id, '--importance', 'important', '--force') -DataDir $DirA
$restoreId = [string]$restoreFixture.Envelope.summary.id
Assert-Smoke 'sync-restore-fixture-id' ($restoreFixture.Ok -and [bool]$restoreId)
$restoreHistory = Invoke-Om -Name 'sync-restore-local-history' -ArgList @('--json', 'sync-history', '--id', $restoreId) -DataDir $DirA
$localRevision = @($restoreHistory.Envelope.details | Where-Object { $_.op_id -and [string]$_.entry.content -eq "restore original $stamp" } | Select-Object -First 1)
Assert-Smoke 'sync-restore-local-revision-exists' ($restoreHistory.Ok -and $localRevision.Count -eq 1)
Invoke-Om -Name 'sync-restore-fixture-edit' -ArgList @('--json', 'update', $restoreId, '--content', "restore changed $stamp") -DataDir $DirA | Out-Null
$restoreOp = Invoke-Om -Name 'sync-restore-op-id' -ArgList @('--json', 'sync-restore', '--op-id', ([string]$localRevision[0].op_id)) -DataDir $DirA -AllowStatus @('pending')
$restoreRead = Invoke-Om -Name 'sync-restore-op-readback' -ArgList @('--json', 'show', $restoreId) -DataDir $DirA
Assert-Smoke 'sync-restore-op-content-persisted' ($restoreOp.Ok -and [string]$restoreOp.Envelope.summary.restored -eq $restoreId -and $restoreRead.Ok -and [string]$restoreRead.Envelope.details.entry.content -eq "restore original $stamp")
Invoke-Om -Name 'sync-restore-upload' -ArgList @('--json', 'sync') -DataDir $DirA | Out-Null
$remoteHistory = Invoke-Om -Name 'sync-restore-remote-history' -ArgList @('--json', 'sync-history', '--id', $restoreId, '--remote') -DataDir $DirA
$remoteRevision = @($remoteHistory.Envelope.details | Where-Object { $_.epoch -and $null -ne $_.rev -and [string]$_.entry.id -eq $restoreId -and [string]$_.entry.content -eq "restore original $stamp" } | Select-Object -First 1)
Assert-Smoke 'sync-restore-remote-revision-exists' ($remoteHistory.Ok -and $remoteRevision.Count -eq 1)
Invoke-Om -Name 'sync-restore-remote-fixture-edit' -ArgList @('--json', 'update', $restoreId, '--content', "restore remote changed $stamp") -DataDir $DirA | Out-Null
$restoreRemote = Invoke-Om -Name 'sync-restore-epoch-rev' -ArgList @('--json', 'sync-restore', '--epoch', ([string]$remoteRevision[0].epoch), '--rev', ([string]$remoteRevision[0].rev)) -DataDir $DirA -AllowStatus @('pending')
$remoteRead = Invoke-Om -Name 'sync-restore-remote-readback' -ArgList @('--json', 'show', $restoreId) -DataDir $DirA
Assert-Smoke 'sync-restore-remote-content-persisted' ($restoreRemote.Ok -and $remoteRead.Ok -and [string]$remoteRead.Envelope.details.entry.content -eq "restore original $stamp")
Invoke-Om -Name 'sync-resolve-bogus' -ArgList @(
    '--json', 'sync-resolve', '--epoch', '0', '--rev', '0', '--head-rev', '0', '--action', 'keep-current'
) -DataDir $DirA -AllowStatus @('fail') -Note 'must fail when there is no conflict' | Out-Null

Invoke-Om -Name 'config-addr-b' -ArgList @('--json', 'config', '--addr', $Server) -DataDir $DirB | Out-Null
$loginB = Invoke-Om -Name 'login-b' -ArgList @('--json', 'login', '--interactive', '--addr', $Server, '--user', $user, '--pass', $pass, '--super', $super) -DataDir $DirB -Secret -HostProfile -TimeoutSec 180
if (-not $loginB.Ok) { throw 'B login failed. super must come from the register response summary.super. Aborted so later commands do not hit the default production server.' }
$stB = Invoke-Om -Name 'status-b' -ArgList @('--json', 'status') -DataDir $DirB
$addrB = ''
if ($stB.Envelope.summary.server_addr) { $addrB = [string]$stB.Envelope.summary.server_addr }
if ($addrB -ne $Server) { throw "B server_addr=$addrB" }
$syncB = Invoke-Om -Name 'sync-b' -ArgList @('--json', 'sync') -DataDir $DirB -TimeoutSec 180
if (-not $syncB.Ok) { throw 'B download sync failed' }
Assert-Smoke 'device-b-sync-converged' ($syncB.Envelope.summary.converged -eq $true -and [int]$syncB.Envelope.summary.pending -eq 0)
$recB = Invoke-Om -Name 'recall-b' -ArgList @('--json', 'recall', $marker, '--limit', '3') -DataDir $DirB -TimeoutSec 180 -AllowIndexWait
if ($recB.Stdout -notlike "*$marker*") { throw "B recall did not return the marker $marker written by A" }
Invoke-Om -Name 'show-b' -ArgList @('--json', 'show', $short) -DataDir $DirB | Out-Null
$bad = Join-Path $Root 'bad'
Invoke-Om -Name 'config-addr-bad' -ArgList @('--json', 'config', '--addr', $Server) -DataDir $bad | Out-Null
Invoke-Om -Name 'login-wrong-pass' -ArgList @('--json', 'login', '--interactive', '--addr', $Server, '--user', $user, '--pass', 'wrong-pass-000') -DataDir $bad -AllowStatus @('fail') -Secret -HostProfile -Note 'a wrong passphrase must fail' | Out-Null

# The second device uses fivekeys. Read material from device A without printing it.
$sessionPath = Join-Path $DirA 'session.json'
if (-not (Test-Path $sessionPath)) {
    $sessionPath = Get-ChildItem -Path $DirA -Filter session.json -Recurse | Select-Object -First 1 -ExpandProperty FullName
}
if ($sessionPath -and (Test-Path $sessionPath)) {
    Invoke-Om -Name 'config-addr-d' -ArgList @('--json', 'config', '--addr', $Server) -DataDir $DirD | Out-Null
    $sess = Get-Content $sessionPath -Raw -Encoding utf8 | ConvertFrom-Json
    Invoke-Om -Name 'fivekeys-d' -ArgList @(
        '--json', 'fivekeys',
        '--addr', $Server,
        '--user', $user,
        '--pass', $pass,
        '--secret', ([string]$sess.secret_key),
        '--kdf-salt', ([string]$sess.kdf_salt),
        '--wrapped-urk', ([string]$sess.wrapped_urk),
        '--urk-nonce', ([string]$sess.urk_nonce),
        '--super', $super
    ) -DataDir $DirD -Secret -TimeoutSec 180 | Out-Null
}

Invoke-Om -Name 'config-autosync-off-a' -ArgList @('--json', 'config', '--autosync', 'false') -DataDir $DirA | Out-Null
Invoke-Om -Name 'config-autosync-off-b' -ArgList @('--json', 'config', '--autosync', 'false') -DataDir $DirB | Out-Null
Invoke-Om -Name 'update-a-offline' -ArgList @('--json', 'update', $short, '--content', "conflict-a $marker") -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'update-b-offline' -ArgList @('--json', 'update', $short, '--content', "conflict-b $marker") -DataDir $DirB -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'sync-a-after-edit' -ArgList @('--json', 'sync') -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'sync-b-conflict' -ArgList @('--json', 'sync') -DataDir $DirB -TimeoutSec 180 | Out-Null
$conf = Invoke-Om -Name 'sync-conflicts-after' -ArgList @('--json', 'sync-conflicts', '--refresh') -DataDir $DirB -TimeoutSec 180
$epoch = ''
$rev = 0
$head = 0
$conflict = $null
if ($conf.Envelope.details -is [System.Array] -and $conf.Envelope.details.Count -gt 0) {
    $conflict = $conf.Envelope.details[0]
} elseif ($conf.Envelope.details -and $conf.Envelope.details.epoch) {
    $conflict = $conf.Envelope.details
}
if ($conflict) {
    $epoch = [string]$conflict.epoch
    $rev = [int]$conflict.rev
    $head = [int]$conflict.current.rev
}
if ($epoch) {
    $resolved = Invoke-Om -Name 'sync-resolve' -ArgList @(
        '--json', 'sync-resolve', '--epoch', $epoch, '--rev', "$rev", '--head-rev', "$head",
        '--action', 'merge', '--content', "merged $marker"
    ) -DataDir $DirB -TimeoutSec 180
    $resolvedRead = Invoke-Om -Name 'sync-resolve-merge-readback' -ArgList @('--json', 'show', $short) -DataDir $DirB
    Assert-Smoke 'sync-resolve-merge-content-persisted' ($resolved.Ok -and $resolvedRead.Ok -and [string]$resolvedRead.Envelope.details.entry.content -eq "merged $marker")
} else {
    Assert-Smoke 'sync-resolve-merge-content-persisted' $false
}

foreach ($resolveAction in @('keep-current', 'take-incoming', 'merge')) {
    $resolveName = "resolve-$resolveAction"
    $resolveCreate = Invoke-Om -Name "$resolveName-create" -ArgList @('--json', 'remember', "$resolveName original $stamp", '--title', "$resolveName-$stamp", '--parent', $id, '--importance', 'important', '--force') -DataDir $DirA
    $resolveId = [string]$resolveCreate.Envelope.summary.id
    Assert-Smoke "$resolveName-fixture-id" ($resolveCreate.Ok -and [bool]$resolveId)
    Invoke-Om -Name "$resolveName-baseline-upload" -ArgList @('--json', 'sync') -DataDir $DirA | Out-Null
    Invoke-Om -Name "$resolveName-baseline-download" -ArgList @('--json', 'sync') -DataDir $DirB | Out-Null
    Invoke-Om -Name "$resolveName-edit-a" -ArgList @('--json', 'update', $resolveId, '--content', "$resolveName current $stamp") -DataDir $DirA | Out-Null
    Invoke-Om -Name "$resolveName-edit-b" -ArgList @('--json', 'update', $resolveId, '--content', "$resolveName incoming $stamp") -DataDir $DirB | Out-Null
    Invoke-Om -Name "$resolveName-upload-a" -ArgList @('--json', 'sync') -DataDir $DirA | Out-Null
    Invoke-Om -Name "$resolveName-upload-b" -ArgList @('--json', 'sync') -DataDir $DirB | Out-Null
    $resolveConflicts = Invoke-Om -Name "$resolveName-conflict" -ArgList @('--json', 'sync-conflicts', '--id', $resolveId, '--refresh') -DataDir $DirB
    $resolveCandidates = @($resolveConflicts.Envelope.details | Where-Object { [string]$_.id -eq $resolveId -and [string]$_.state -eq 'pending' })
    Assert-Smoke "$resolveName-distinct-conflict" ($resolveConflicts.Ok -and $resolveCandidates.Count -eq 1 -and [string]$resolveCandidates[0].candidate.entry.content -ne [string]$resolveCandidates[0].current.value.entry.content)
    $candidate = $resolveCandidates[0]
    $expectedContent = switch ($resolveAction) {
        'keep-current' { [string]$candidate.current.value.entry.content }
        'take-incoming' { [string]$candidate.candidate.entry.content }
        'merge' { "$resolveName merged $stamp" }
    }
    $resolveArgs = @('--json', 'sync-resolve', '--epoch', ([string]$candidate.epoch), '--rev', ([string]$candidate.rev), '--head-rev', ([string]$candidate.current.rev), '--action', $resolveAction)
    if ($resolveAction -eq 'merge') { $resolveArgs += @('--content', $expectedContent) }
    $resolveApply = Invoke-Om -Name "$resolveName-apply" -ArgList $resolveArgs -DataDir $DirB
    Assert-Smoke "$resolveName-acknowledged" ($resolveApply.Ok -and $resolveApply.Envelope.summary.processed -eq $true -and [string]$resolveApply.Envelope.summary.action -eq $resolveAction.Replace('-', '_'))
    Invoke-Om -Name "$resolveName-converge-a" -ArgList @('--json', 'sync') -DataDir $DirA | Out-Null
    $resolveReadA = Invoke-Om -Name "$resolveName-readback-a" -ArgList @('--json', 'show', $resolveId) -DataDir $DirA
    $resolveReadB = Invoke-Om -Name "$resolveName-readback-b" -ArgList @('--json', 'show', $resolveId) -DataDir $DirB
    Assert-Smoke "$resolveName-content-converged" ($resolveReadA.Ok -and $resolveReadB.Ok -and [string]$resolveReadA.Envelope.details.entry.content -eq $expectedContent -and [string]$resolveReadB.Envelope.details.entry.content -eq $expectedContent)
    $processedConflicts = Invoke-Om -Name "$resolveName-processed-history" -ArgList @('--json', 'sync-conflicts', '--id', $resolveId, '--all') -DataDir $DirB
    Assert-Smoke "$resolveName-history-kept" ($processedConflicts.Ok -and @($processedConflicts.Envelope.details | Where-Object { $_.rev -eq $candidate.rev -and [string]$_.state -eq 'processed' -and [string]$_.resolution -eq $resolveAction.Replace('-', '_') }).Count -eq 1)
}

if ($dispId) {
    Invoke-Om -Name 'forget' -ArgList @('--json', 'forget', $dispId) -DataDir $DirA | Out-Null
    $forgotten = Invoke-Om -Name 'forget-show-refused' -ArgList @('--json', 'show', $dispId) -DataDir $DirA -AllowStatus @('fail')
    Assert-Smoke 'forget-hides-entry' ($forgotten.Ok -and $forgotten.Exit -eq 1)
    Invoke-Om -Name 'restore' -ArgList @('--json', 'restore', $dispId) -DataDir $DirA | Out-Null
    $restored = Invoke-Om -Name 'restore-show-visible' -ArgList @('--json', 'show', $dispId) -DataDir $DirA
    Assert-Smoke 'restore-preserves-content' ($restored.Ok -and [string]$restored.Envelope.details.entry.content -eq "disposable $marker")
    Invoke-Om -Name 'purge' -ArgList @('--json', 'purge', $dispId) -DataDir $DirA | Out-Null
    $purged = Invoke-Om -Name 'purge-show-refused' -ArgList @('--json', 'show', $dispId) -DataDir $DirA -AllowStatus @('fail')
    Assert-Smoke 'purge-removes-current-entry' ($purged.Ok -and $purged.Exit -eq 1)
}
$deviceBSession = Get-SmokeSession $DirB $user
$deviceBSid = [string]$deviceBSession.Value.session_id
Assert-Smoke 'session-secondary-id-present' ($deviceBSid -match '^[0-9a-f-]{36}$')
$realSessionList = Invoke-Om -Name 'session-list-secondary-real' -ArgList @('--json', 'session', 'list') -DataDir $DirA
Assert-Smoke 'session-secondary-listed' ($realSessionList.Ok -and ($realSessionList.Envelope.details | ConvertTo-Json -Depth 8) -like "*$deviceBSid*")
$realRevoke = Invoke-Om -Name 'session-revoke-secondary-real' -ArgList @('--json', 'session', 'revoke', $deviceBSid) -DataDir $DirA
Assert-Smoke 'session-revoke-secondary-confirmed' ($realRevoke.Ok -and $realRevoke.Envelope.details.revoked -eq $true -and [string]$realRevoke.Envelope.details.session_id -eq $deviceBSid)
$revokedSync = Invoke-Om -Name 'session-revoked-cloud-sync-denied' -ArgList @('--json', 'sync') -DataDir $DirB -AllowStatus @('fail')
Assert-Smoke 'session-revoked-access-denied' ($revokedSync.Ok -and $revokedSync.Exit -eq 1 -and ($revokedSync.Envelope.errors -join ' ') -match 'unauthorized|token rejected|401')
$revokedLocal = Invoke-Om -Name 'session-revoked-local-read-preserved' -ArgList @('--json', 'show', $id) -DataDir $DirB
Assert-Smoke 'session-revocation-preserves-local-decryption' ($revokedLocal.Ok -and [string]$revokedLocal.Envelope.details.entry.content -eq "merged $marker")
# A revoked owner session is marked personal read-only by the remote transport.
# Recover through the existing CLI setting, while team members remain unable to self-unlock.
$revokedConfig = Invoke-Om -Name 'session-revoked-agent-config' -ArgList @('--json', 'agent-config') -DataDir $DirB
Assert-Smoke 'session-revoked-personal-readonly-marked' ($revokedConfig.Ok -and $revokedConfig.Envelope.summary.readonly -eq $true -and $revokedConfig.Envelope.summary.readonly_team -ne $true)
$revokedStatus = Invoke-Om -Name 'session-revoked-device-status' -ArgList @('--json', 'status') -DataDir $DirB
$revokedWrite = Invoke-Om -Name 'session-revoked-local-write-refused' -ArgList @('--json', 'remember', "must-not-write-$marker", '--title', 'must-not-write', '--force') -DataDir $DirB -AllowStatus @('fail')
Assert-Smoke 'session-revoked-device-readonly-enforced' ($revokedStatus.Ok -and [string]$revokedStatus.Envelope.summary.workspace -eq 'readonly' -and $revokedWrite.Ok -and $revokedWrite.Exit -eq 1 -and ($revokedWrite.Envelope.errors -join ' ') -match 'read.only')
$ownerClear = Invoke-Om -Name 'session-owner-clear-personal-readonly' -ArgList @('--json', 'agent-config', '--set', 'readonly=false') -DataDir $DirB
Assert-Smoke 'session-owner-personal-readonly-cleared' ($ownerClear.Ok -and [string]$ownerClear.Envelope.summary.key -eq 'readonly' -and $ownerClear.Envelope.summary.value -eq $false)
$ownerConfig = Invoke-Om -Name 'session-owner-agent-config-readback' -ArgList @('--json', 'agent-config') -DataDir $DirB
Assert-Smoke 'session-owner-personal-readonly-readback' ($ownerConfig.Ok -and $ownerConfig.Envelope.summary.readonly -eq $false -and $ownerConfig.Envelope.summary.readonly_team -ne $true)
$ownerStatus = Invoke-Om -Name 'session-owner-device-mode-readback' -ArgList @('--json', 'status') -DataDir $DirB
Assert-Smoke 'session-owner-device-normal-restored' ($ownerStatus.Ok -and [string]$ownerStatus.Envelope.summary.workspace -eq 'normal')
Invoke-Om -Name 'logout' -ArgList @('--json', 'logout') -DataDir $DirB | Out-Null
$loginAgain = Invoke-Om -Name 'login-b-again' -ArgList @('--json', 'login', '--interactive', '--addr', $Server, '--user', $user, '--pass', $pass, '--super', $super) -DataDir $DirB -Secret -TimeoutSec 180
if (-not $loginAgain.Ok) { throw 're-login failed' }
$recallAgain = Invoke-Om -Name 'recall-after-relogin' -ArgList @('--json', 'recall', $marker, '--limit', '3') -DataDir $DirB -TimeoutSec 180 -AllowIndexWait
if ($recallAgain.Stdout -notlike "*$marker*") { throw 'the marker was not found after re-login' }
$syncAgain = Invoke-Om -Name 'sync-after-relogin' -ArgList @('--json', 'sync') -DataDir $DirB -TimeoutSec 180
if (-not $syncAgain.Ok) { throw 'sync failed after re-login' }
$superReset = Invoke-Om -Name 'super-reset' -ArgList @('--json', 'super-reset', '--super', $super) -DataDir $DirA -Secret -TimeoutSec 180
$newSuper = [string]$superReset.Envelope.summary.super
if ($superReset.Ok -and $newSuper) { $mainCloudAccount.Super = $newSuper }
$afterReset = Invoke-Om -Name 'super-reset-memory-readback' -ArgList @('--json', 'show', $id) -DataDir $DirA
Assert-Smoke 'super-reset-preserves-memory' ($superReset.Ok -and [bool]$newSuper -and $newSuper -ne $super -and $afterReset.Ok -and [string]$afterReset.Envelope.details.entry.content -eq "merged $marker")
$oldRecoveryDir = Join-Path $Root 'old-recovery'
Invoke-Om -Name 'old-recovery-config' -ArgList @('--json', 'config', '--addr', $Server, '--autosync', 'false') -DataDir $oldRecoveryDir | Out-Null
$oldRecovery = Invoke-Om -Name 'super-reset-old-code-refused' -ArgList @('--json', 'login', '--interactive', '--addr', $Server, '--user', $user, '--pass', $pass, '--super', $super) -DataDir $oldRecoveryDir -Secret -HostProfile -AllowStatus @('fail')
Assert-Smoke 'super-reset-old-code-rejected' ($oldRecovery.Ok -and $oldRecovery.Exit -eq 1 -and ($oldRecovery.Envelope.errors -join ' ') -match 'unwrap|decrypt')
$recoveryDir = Join-Path $Root 'new-recovery'
Invoke-Om -Name 'new-recovery-config' -ArgList @('--json', 'config', '--addr', $Server, '--autosync', 'false') -DataDir $recoveryDir | Out-Null
$newRecovery = Invoke-Om -Name 'super-reset-new-code-login' -ArgList @('--json', 'login', '--interactive', '--addr', $Server, '--user', $user, '--pass', $pass, '--super', $newSuper) -DataDir $recoveryDir -Secret -HostProfile
$newRecoverySync = Invoke-Om -Name 'super-reset-new-code-sync' -ArgList @('--json', 'sync') -DataDir $recoveryDir
$newRecoveryRead = Invoke-Om -Name 'super-reset-new-code-readback' -ArgList @('--json', 'show', $id) -DataDir $recoveryDir
Assert-Smoke 'super-reset-new-code-recovers-cloud-content' ($newRecovery.Ok -and $newRecoverySync.Ok -and $newRecoveryRead.Ok -and [string]$newRecoveryRead.Envelope.details.entry.content -eq "merged $marker")
$recoverySession = Get-SmokeSession $recoveryDir $user
$fullLogout = Invoke-Om -Name 'cloud-full-logout' -ArgList @('--json', 'logout', '--full') -DataDir $recoveryDir -HostProfile
Assert-Smoke 'cloud-full-logout-removes-session' ($fullLogout.Ok -and [string]$fullLogout.Envelope.summary.mode -eq 'full' -and -not (Test-Path -LiteralPath $recoverySession.Path))
$recoveredAfterFull = Invoke-Om -Name 'cloud-login-after-full-logout' -ArgList @('--json', 'login', '--interactive', '--addr', $Server, '--user', $user, '--pass', $pass, '--super', $newSuper) -DataDir $recoveryDir -Secret -HostProfile
$fullRead = Invoke-Om -Name 'cloud-full-logout-login-readback' -ArgList @('--json', 'show', $id) -DataDir $recoveryDir
Assert-Smoke 'cloud-full-logout-recovery-preserves-library' ($recoveredAfterFull.Ok -and $fullRead.Ok -and [string]$fullRead.Envelope.details.entry.content -eq "merged $marker")

# A separate disposable library exercises mismatched key material without
# risking the main sweep account's local library or exporting old ciphertext.
$resetDir = Join-Path $Root 'reset-vault'
Invoke-Om -Name 'reset-vault-config' -ArgList @('--json', 'config', '--addr', $Server, '--autosync', 'false') -DataDir $resetDir | Out-Null
Invoke-Om -Name 'reset-vault-baseline-login' -ArgList @('--json', 'login', '--interactive', '--addr', $Server, '--user', $user, '--pass', $pass, '--super', $newSuper) -DataDir $resetDir -Secret -HostProfile | Out-Null
$resetKeys = Invoke-Om -Name 'reset-vault-local-keygen' -ArgList @('--json', 'keygen', '--force') -DataDir $resetDir -Secret -HostProfile
$mismatched = Invoke-Om -Name 'reset-vault-old-local-write' -ArgList @('--json', 'remember', "reset-local-old-key-$stamp", '--title', "reset-local-$stamp", '--importance', 'important', '--force') -DataDir $resetDir
$mismatchedId = [string]$mismatched.Envelope.summary.id
Assert-Smoke 'reset-vault-mismatched-fixture-written' ($resetKeys.Ok -and [bool]$resetKeys.Envelope.summary.super -and $mismatched.Ok -and [bool]$mismatchedId)
$resetProfile = [string](Invoke-Om -Name 'reset-vault-selected-profile' -ArgList @('--json', 'config') -DataDir $resetDir).Envelope.summary.data_dir
$resetSession = Join-Path $resetProfile 'session.json'
# keygen clears identity; bind this fixture to the same remote identity to exercise the overwrite guard.
$resetIdentity = Get-Content -LiteralPath $resetSession -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
$resetIdentity['user'] = $user
$resetIdentity['addr'] = $Server
[IO.File]::WriteAllText($resetSession, ($resetIdentity | ConvertTo-Json -Depth 20) + "`n", [Text.UTF8Encoding]::new($false))
$beforeResetSession = (Get-FileHash -LiteralPath $resetSession -Algorithm SHA256).Hash
$previousResetSuper = $env:RSRS_SUPER
try {
    # Keep the disposable local key usable without storing its Super password in the session.
    $env:RSRS_SUPER = [string]$resetKeys.Envelope.summary.super
    $resetGuard = Invoke-Om -Name 'reset-vault-mismatch-refused' -ArgList @('--json', 'login', '--interactive', '--addr', $Server, '--user', $user, '--pass', $pass, '--super', $newSuper) -DataDir $resetDir -Secret -HostProfile -AllowStatus @('fail')
    Assert-Smoke 'reset-vault-mismatch-guard' ($resetGuard.Ok -and $resetGuard.Exit -eq 1 -and ($resetGuard.Envelope.errors -join ' ') -match 'different key material|destination belongs to another account')
    Assert-Smoke 'login-key-mismatch-original-session-preserved' ((Get-FileHash -LiteralPath $resetSession -Algorithm SHA256).Hash -ceq $beforeResetSession)
    $resetRead = Invoke-Om -Name 'login-key-mismatch-original-readback' -ArgList @('--json', 'show', $mismatchedId) -DataDir $resetDir
    Assert-Smoke 'login-key-mismatch-original-data-readable' ($resetRead.Ok -and [string]$resetRead.Envelope.details.entry.content -ceq "reset-local-old-key-$stamp")
} finally {
    if ($null -eq $previousResetSuper) { Remove-Item Env:RSRS_SUPER -ErrorAction SilentlyContinue }
    else { $env:RSRS_SUPER = $previousResetSuper }
}
Invoke-Om -Name 'sync-reset' -ArgList @('--json', 'sync-reset') -DataDir $DirA -TimeoutSec 180 -Note 'snapshot rebuild on a disposable account' | Out-Null

# Web opens the hosted dashboard; runtime lifecycle is a separate hidden command.
$dashboardDir = Join-Path $Root 'dashboard-launch'
$dashboard = Invoke-Om -Name 'web-dashboard-report' -ArgList @('--json', 'web', '--no-open') -DataDir $dashboardDir
Assert-Smoke 'web-dashboard-fixed-url' ($dashboard.Ok -and [string]$dashboard.Envelope.summary.url -ceq 'https://dash.rsrs.rs' -and $dashboard.Envelope.summary.opened -eq $false)
Assert-Smoke 'web-dashboard-no-runtime' (-not (Test-Path -LiteralPath (Join-Path $dashboardDir 'runtime/endpoint.json')))
$legacyWebRejected = $true
foreach ($flags in @(@('--internal'), @('--status'), @('--stop'), @('--port', '15169'), @('--host', '127.0.0.1'))) {
    $rejected = Invoke-Om -Name "web-reject-legacy-$($flags[0].TrimStart('-'))" -ArgList (@('web') + $flags) -DataDir $dashboardDir -ExpectExit @(1, 2) -Raw
    $legacyWebRejected = $legacyWebRejected -and $rejected.Ok
}
Assert-Smoke 'web-legacy-lifecycle-flags-rejected' ($legacyWebRejected -and -not (Test-Path -LiteralPath (Join-Path $dashboardDir 'runtime/endpoint.json')))
# A normal CLI call starts only the API runtime for the original fixture.
Invoke-Om -Name 'runtime-start-by-cli-status' -ArgList @('--json', 'status') -DataDir $DirA | Out-Null
$webStatus = Invoke-Om -Name 'runtime-status' -ArgList @('--json', '--runtime-internal', '--status') -DataDir $DirA -ExpectExit @(0, 2) -Raw
$url = ''
$endpointFile = Join-Path $DirA 'runtime\endpoint.json'
if (Test-Path $endpointFile) {
    $ep = Get-Content $endpointFile -Raw | ConvertFrom-Json
    $url = [string]$ep.url
    $runtimeUri = [Uri]$url
    if ($runtimeUri.Host -notin @('127.0.0.1', 'localhost', '::1')) { throw "Runtime endpoint is not loopback: $url" }
}
$tokenFile = Join-Path $DirA 'runtime\token'
$origin = $url
if ($origin -match '^(https?://[^/?]+)') { $origin = $Matches[1] }
$mcpUrl = ''
if ($origin) { $mcpUrl = ($origin.TrimEnd('/') + '/mcp') }
$mcpSse = ''
if ($origin) { $mcpSse = ($origin.TrimEnd('/') + '/sse') }
$mcpHeaders = @{}
Assert-Smoke 'runtime-endpoint-without-token' ([bool]$origin -and -not (Test-Path -LiteralPath $tokenFile))
function Invoke-LocalSmoke {
    param([string]$Name, [string]$Path, $Payload, [int]$ExpectedStatus = 200, [hashtable]$Headers = $mcpHeaders, [string]$Method = 'POST', [switch]$RawBody)
    $body = if ($RawBody) { [string]$Payload } else { $Payload | ConvertTo-Json -Compress -Depth 12 }
    $request = @{ Uri = "$origin$Path"; Method = $Method; Headers = $Headers; TimeoutSec = 90; SkipHttpErrorCheck = $true }
    if ($Method -ne 'GET') { $request.Body = $body; $request.ContentType = 'application/json; charset=utf-8' }
    $response = Invoke-WebRequest @request
    Assert-Smoke $Name ([int]$response.StatusCode -eq $ExpectedStatus)
    if ($ExpectedStatus -eq 200) { return ($response.Content | ConvertFrom-Json) }
}
$health = Invoke-LocalSmoke -Name 'runtime-http-health' -Path '/api/health' -Method GET
Assert-Smoke 'runtime-health-protocol-version' ([int]$health.v -eq 1 -and [string]$health.bin -eq $ExpectVersion)
$wrongToken = Invoke-LocalSmoke -Name 'runtime-http-loopback-ignores-token' -Path '/api/rpc' -Payload @{ v = 1; id = 'wrong-token'; method = 'runtime.status' } -Headers @{ Authorization = 'Bearer invalid-smoke-token' }
if ($wrongToken.ok -ne $true -or [string]$wrongToken.id -cne 'wrong-token' -or [string]$wrongToken.bin -cne $ExpectVersion) { throw 'Loopback RPC response identity failed.' }
Invoke-LocalSmoke -Name 'runtime-http-foreign-origin' -Path '/api/rpc' -Payload @{ v = 1; id = 'foreign-origin'; method = 'runtime.status' } -Headers @{ Origin = 'https://example.invalid' } -ExpectedStatus 403 | Out-Null
Invoke-LocalSmoke -Name 'runtime-http-malformed-json' -Path '/api/rpc' -Payload '{' -RawBody -ExpectedStatus 400 | Out-Null
Invoke-LocalSmoke -Name 'runtime-http-missing-command' -Path '/api/rpc' -Payload @{} -ExpectedStatus 400 | Out-Null
foreach ($removed in @(@('/', 'GET'), @('/index.html', 'GET'), @('/favicon.ico', 'GET'), @('/api/invoke', 'POST'), @('/api/task/start', 'POST'))) {
    Invoke-LocalSmoke -Name "runtime-removed-ui-$($removed[0] -replace '[^a-zA-Z0-9]', '-')" -Path $removed[0] -Method $removed[1] -Payload @{} -ExpectedStatus 404 | Out-Null
}
function Invoke-RuntimeCli([string]$Name, [string[]]$Arguments) {
    $response = Invoke-LocalSmoke -Name $Name -Path '/api/rpc' -Payload @{ v = 1; id = $Name; method = 'cli.exec'; args = @('--json') + $Arguments }
    Assert-Smoke "$Name-response" ($response.ok -eq $true -and [string]$response.id -ceq $Name -and [string]$response.bin -ceq $ExpectVersion -and $null -ne $response.envelope)
    return $response.envelope
}
$runtimeStatus = Invoke-RuntimeCli 'runtime-cli-status' @('status')
Assert-Smoke 'runtime-cli-status-approved-server' ([string]$runtimeStatus.summary.server_addr -ceq $Server -and $runtimeStatus.summary.unlocked -eq $true)
Assert-Smoke 'runtime-cli-workspace-mode-normal' ([string]$runtimeStatus.summary.workspace -ceq 'normal')
$runtimeConfig = Invoke-RuntimeCli 'runtime-cli-config' @('config')
Assert-Smoke 'runtime-cli-config-approved-server' ([string]$runtimeConfig.summary.addr -ceq $Server -and $runtimeConfig.summary.autosync -eq $false)
$runtimeAgent = Invoke-RuntimeCli 'runtime-cli-agent-config' @('agent-config')
Assert-Smoke 'runtime-cli-diary-mode-contract' ([string]$runtimeAgent.summary.diary_mode -in @('concise', 'verbose'))
Invoke-RuntimeCli 'runtime-cli-list' @('list', '--limit', '5') | Out-Null
Invoke-RuntimeCli 'runtime-cli-tree' @('tree', '--depth', '3') | Out-Null
Invoke-RuntimeCli 'runtime-cli-inject-targets' @('inject', '--targets') | Out-Null
Assert-Smoke 'runtime-cli-retired-rerank-rejected' ($retiredInstall.Ok -and -not (Test-Path -LiteralPath (Join-Path $Root 'models/bge-reranker-base')))
$runtimeCreated = Invoke-RuntimeCli 'runtime-cli-create' @('remember', "runtime-rpc-$stamp", '--title', "runtime-$stamp", '--importance', 'important', '--force', '--parent', $id)
$runtimeId = [string]$runtimeCreated.summary.id
Assert-Smoke 'runtime-cli-created-id' ([bool]$runtimeId)
Invoke-RuntimeCli 'runtime-cli-update' @('update', $runtimeId, '--content', "runtime-updated-$stamp", '--title', "runtime-updated-$stamp") | Out-Null
$runtimeRead = Invoke-RuntimeCli 'runtime-cli-show' @('show', $runtimeId)
Assert-Smoke 'runtime-cli-update-persisted' ([string]$runtimeRead.details.entry.content -ceq "runtime-updated-$stamp")
Invoke-RuntimeCli 'runtime-cli-attach' @('attach', $runtimeId, '--parent', $splitId) | Out-Null
$runtimeParent = Invoke-RuntimeCli 'runtime-cli-parent-readback' @('show', $runtimeId)
Assert-Smoke 'runtime-cli-parent-persisted' ([string]$runtimeParent.details.entry.parent_id -ceq $splitId)
Invoke-RuntimeCli 'runtime-cli-delete' @('forget', $runtimeId) | Out-Null
Invoke-RuntimeCli 'runtime-cli-restore' @('restore', $runtimeId) | Out-Null
$runtimeRestored = Invoke-RuntimeCli 'runtime-cli-restore-readback' @('show', $runtimeId)
Assert-Smoke 'runtime-cli-restore-preserved-content' ([string]$runtimeRestored.details.entry.content -ceq "runtime-updated-$stamp")
Invoke-RuntimeCli 'runtime-cli-purge' @('purge', $runtimeId) | Out-Null
$wantTools = @(
    'memory_status','memory_extract','memory_remember','memory_recall','memory_list','memory_show','memory_update',
    'memory_attach','memory_tree','memory_history','memory_diary','memory_chain','memory_query_log_mark',
    'memory_taxonomy','memory_diary_search','memory_diary_fragment'
)
if ($mcpUrl) {
    try {
        $sse = Invoke-WebRequest -Uri $mcpSse -Headers $mcpHeaders -UseBasicParsing -TimeoutSec 15
        $sseText = [string]$sse.Content
        Add-SweepRow 'mcp-http-sse' (($sse.StatusCode -eq 200) -and ($sseText -like '*event: endpoint*') -and ($sseText -like '*/mcp*')) $mcpSse
    } catch {
        Add-SweepRow 'mcp-http-sse' $false $_.Exception.Message
    }
    function Invoke-McpHttpRpc($Name, $Payload) {
        try {
            $body = $Payload | ConvertTo-Json -Compress -Depth 12
            $resp = Invoke-WebRequest -Uri $mcpUrl -Method POST -Headers $mcpHeaders -ContentType 'application/json; charset=utf-8' -Body $body -UseBasicParsing -TimeoutSec 90
            $parsed = $resp.Content | ConvertFrom-Json
            Add-SweepRow $Name ($resp.StatusCode -eq 200 -and $null -ne $parsed -and [string]$parsed.jsonrpc -eq '2.0' -and [string]$parsed.id -eq [string]$Payload.id) $mcpUrl
            return $parsed
        } catch {
            Add-SweepRow $Name $false $_.Exception.Message
            return $null
        }
    }
    $httpInit = Invoke-McpHttpRpc 'mcp-http-initialize' @{ jsonrpc='2.0'; id=1; method='initialize'; params=@{ protocolVersion='2025-03-26'; capabilities=@{}; clientInfo=@{ name='sweep'; version='0' } } }
    Add-SweepRow 'mcp-http-initialize-version' ($null -ne $httpInit -and [string]$httpInit.result.protocolVersion -eq '2025-03-26') ([string]$httpInit.result.protocolVersion)
    $httpList = Invoke-McpHttpRpc 'mcp-http-tools-list' @{ jsonrpc='2.0'; id=2; method='tools/list' }
    $httpNames = @()
    if ($httpList -and $httpList.result.tools) { $httpNames = @($httpList.result.tools | ForEach-Object { [string]$_.name }) }
    $missingHttp = @($wantTools | Where-Object { $httpNames -notcontains $_ })
    $unexpectedHttp = @($httpNames | Where-Object { $wantTools -cnotcontains $_ })
    Add-SweepRow 'mcp-http-tools-complete' ($missingHttp.Count -eq 0 -and $unexpectedHttp.Count -eq 0 -and $httpNames.Count -eq 16) ("have=$($httpNames.Count) missing=$($missingHttp -join ',')")
    Invoke-McpHttpRpc 'mcp-http-ping' @{ jsonrpc='2.0'; id=3; method='ping' } | Out-Null
}

$mcpStdinList = (@(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"sweep","version":"0"}}}'
    '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    '{"jsonrpc":"2.0","id":3,"method":"ping"}'
) -join "`n") + "`n"
$mcpListRun = Invoke-Om -Name 'mcp-stdio-initialize-list' -ArgList @('mcp') -DataDir $DirA -Raw -TimeoutSec 90 -StdinText $mcpStdinList -Note 'initialize + tools/list + ping'
$mcpInit = Get-JsonRpc $mcpListRun.Stdout 1
$mcpList = Get-JsonRpc $mcpListRun.Stdout 2
$mcpPing = Get-JsonRpc $mcpListRun.Stdout 3
Add-SweepRow 'mcp-stdio-initialize-version' ($null -ne $mcpInit -and [string]$mcpInit.result.protocolVersion -eq '2025-03-26') ([string]$mcpInit.result.protocolVersion)
$stdioNames = @()
if ($mcpList -and $mcpList.result.tools) { $stdioNames = @($mcpList.result.tools | ForEach-Object { [string]$_.name }) }
$missingStdio = @($wantTools | Where-Object { $stdioNames -notcontains $_ })
$unexpectedStdio = @($stdioNames | Where-Object { $wantTools -cnotcontains $_ })
Add-SweepRow 'mcp-stdio-tools-complete' ($missingStdio.Count -eq 0 -and $unexpectedStdio.Count -eq 0 -and $stdioNames.Count -eq 16) ("have=$($stdioNames.Count) missing=$($missingStdio -join ',')")
Add-SweepRow 'mcp-stdio-ping' ($null -ne $mcpPing -and $null -ne $mcpPing.result) 'ping'

$mcpMarker = "mcp-business-$stamp"
$statusTool = Invoke-McpStdioTool -Name 'mcp-stdio-status' -Tool 'memory_status' -DataDir $DirA
Add-SweepRow 'mcp-stdio-status-envelope' ($null -ne $statusTool.Envelope -and [string]$statusTool.Envelope.command -eq 'status') ([string]$statusTool.Envelope.command)
$taxTool = Invoke-McpStdioTool -Name 'mcp-stdio-taxonomy' -Tool 'memory_taxonomy' -DataDir $DirA
Add-SweepRow 'mcp-stdio-taxonomy-envelope' ($null -ne $taxTool.Envelope -and [string]$taxTool.Envelope.command -eq 'taxonomy') ([string]$taxTool.Envelope.command)
$rememberTool = Invoke-McpStdioTool -Name 'mcp-stdio-remember' -Tool 'memory_remember' -Arguments @{
    content = "$MARK_CAUSE Sweep the MCP surface. $MARK_ACTION Write marker $mcpMarker. $MARK_RESULT Used by the recall/show/update/attach/forget assertions."
    title = "mcp-sweep-marker"
    importance = 'important'
    parent = $TX_DEV
    force = $true
} -DataDir $DirA
$mcpId = ''
if ($rememberTool.Envelope -and $rememberTool.Envelope.summary.id) { $mcpId = [string]$rememberTool.Envelope.summary.id }
if (-not $mcpId -and $rememberTool.Envelope -and $rememberTool.Envelope.summary.entry_id) { $mcpId = [string]$rememberTool.Envelope.summary.entry_id }
if (-not $mcpId -and $rememberTool.Stdout -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') { $mcpId = $Matches[1] }
Add-SweepRow 'mcp-stdio-remember-id' ([bool]$mcpId) $mcpId
$recallTool = Invoke-McpStdioTool -Name 'mcp-stdio-recall' -Tool 'memory_recall' -Arguments @{ query = $mcpMarker; limit = 3 } -DataDir $DirA
Add-SweepRow 'mcp-stdio-recall-hit' ($recallTool.Run.Stdout -like "*$mcpMarker*") 'recall contains marker'
$listTool = Invoke-McpStdioTool -Name 'mcp-stdio-list' -Tool 'memory_list' -Arguments @{ limit = 5 } -DataDir $DirA
Add-SweepRow 'mcp-stdio-list-envelope' ($null -ne $listTool.Envelope -and [string]$listTool.Envelope.command -eq 'list') ([string]$listTool.Envelope.command)
if ($mcpId) {
    $showTool = Invoke-McpStdioTool -Name 'mcp-stdio-show' -Tool 'memory_show' -Arguments @{ id = $mcpId } -DataDir $DirA
    Add-SweepRow 'mcp-stdio-show-hit' ($showTool.Run.Stdout -like "*$mcpMarker*") 'show contains marker'
    $updTool = Invoke-McpStdioTool -Name 'mcp-stdio-update' -Tool 'memory_update' -Arguments @{ id = $mcpId; title = 'mcp-sweep-marker-updated' } -DataDir $DirA
    Add-SweepRow 'mcp-stdio-update-envelope' ($null -ne $updTool.Envelope -and [string]$updTool.Envelope.command -eq 'update') ([string]$updTool.Envelope.command)
    $parentPrefix = ''
    if ($listTool.Envelope -and $listTool.Envelope.items) {
        $parentPrefix = [string](@($listTool.Envelope.items | Where-Object { [string]$_.name -ne $mcpId.Substring(0, [Math]::Min(8, $mcpId.Length)) } | Select-Object -First 1).name)
    }
    if (-not $parentPrefix) { $parentPrefix = $mcpId }
    $attachTool = Invoke-McpStdioTool -Name 'mcp-stdio-attach' -Tool 'memory_attach' -Arguments @{ id = $mcpId; parent = $parentPrefix } -DataDir $DirA
    $attachOk = $null -ne $attachTool.Envelope -and [string]$attachTool.Envelope.command -eq 'attach' -and [string]$attachTool.Envelope.status -ne 'fail'
    Add-SweepRow 'mcp-stdio-attach-envelope' $attachOk ([string]$attachTool.Envelope.status + ' parent=' + $parentPrefix)
    $histTool = Invoke-McpStdioTool -Name 'mcp-stdio-history' -Tool 'memory_history' -Arguments @{ id = $mcpId; limit = 10 } -DataDir $DirA
    Add-SweepRow 'mcp-stdio-history-envelope' ($null -ne $histTool.Envelope -and [string]$histTool.Envelope.command -eq 'history') ([string]$histTool.Envelope.command)
    $chainTool = Invoke-McpStdioTool -Name 'mcp-stdio-chain' -Tool 'memory_chain' -Arguments @{ id = $mcpId; depth = 2 } -DataDir $DirA
    Add-SweepRow 'mcp-stdio-chain-envelope' ($null -ne $chainTool.Envelope -and [string]$chainTool.Envelope.command -eq 'chain') ([string]$chainTool.Envelope.command)
    $markTool = Invoke-McpStdioTool -Name 'mcp-stdio-query-log-mark' -Tool 'memory_query_log_mark' -Arguments @{ ids = $mcpId; good = $true } -DataDir $DirA
    Add-SweepRow 'mcp-stdio-query-log-mark-ran' ($null -ne $markTool.Rpc) ([string]$markTool.Envelope.status)
    foreach ($deniedTool in @('memory_forget','memory_restore')) {
        $denied = Invoke-McpStdioTool -Name "mcp-stdio-default-$deniedTool" -Tool $deniedTool -Arguments @{ id = $mcpId } -DataDir $DirA
        Assert-Smoke "mcp-stdio-default-$deniedTool-denied" ($denied.Rpc.result.isError -eq $true -and $null -eq $denied.Envelope)
    }
    $defaultStdioRead = Invoke-McpStdioTool -Name 'mcp-stdio-default-denial-readback' -Tool 'memory_show' -Arguments @{ id = $mcpId } -DataDir $DirA
    Assert-Smoke 'mcp-stdio-default-denial-preserved-content' ([string]$defaultStdioRead.Envelope.details.entry.content -like "*$mcpMarker*")
    $forgetTool = Invoke-McpStdioTool -Name 'mcp-stdio-forget' -Tool 'memory_forget' -Arguments @{ id = $mcpId } -DataDir $DirA -AllowDestructiveMcpFixture
    Add-SweepRow 'mcp-stdio-forget-envelope' ($null -ne $forgetTool.Envelope -and [string]$forgetTool.Envelope.command -eq 'forget') ([string]$forgetTool.Envelope.command)
    $restoreTool = Invoke-McpStdioTool -Name 'mcp-stdio-restore' -Tool 'memory_restore' -Arguments @{ id = $mcpId } -DataDir $DirA -AllowDestructiveMcpFixture
    Add-SweepRow 'mcp-stdio-restore-envelope' ($null -ne $restoreTool.Envelope -and [string]$restoreTool.Envelope.command -eq 'restore') ([string]$restoreTool.Envelope.command)
} else {
    foreach ($n in @('mcp-stdio-show-hit','mcp-stdio-update-envelope','mcp-stdio-attach-envelope','mcp-stdio-history-envelope','mcp-stdio-chain-envelope','mcp-stdio-query-log-mark-ran','mcp-stdio-forget-envelope','mcp-stdio-restore-envelope')) {
        Add-SweepRow $n $false 'no remember id'
    }
}
$treeTool = Invoke-McpStdioTool -Name 'mcp-stdio-tree' -Tool 'memory_tree' -Arguments @{ outline = $true } -DataDir $DirA
Add-SweepRow 'mcp-stdio-tree-envelope' ($null -ne $treeTool.Envelope -and [string]$treeTool.Envelope.command -eq 'tree') ([string]$treeTool.Envelope.command)
$diaryTool = Invoke-McpStdioTool -Name 'mcp-stdio-diary' -Tool 'memory_diary' -Arguments @{ limit = 5 } -DataDir $DirA
Add-SweepRow 'mcp-stdio-diary-envelope' ($null -ne $diaryTool.Envelope -and [string]$diaryTool.Envelope.command -eq 'diary') ([string]$diaryTool.Envelope.command)
$badTool = Invoke-McpStdioTool -Name 'mcp-stdio-unknown-tool' -Tool 'memory_nope' -DataDir $DirA
$badIsError = $false
if ($badTool.Rpc -and $badTool.Rpc.result) { $badIsError = [bool]$badTool.Rpc.result.isError }
Add-SweepRow 'mcp-stdio-unknown-is-error' $badIsError 'unknown tool'
$missingContent = Invoke-McpStdioTool -Name 'mcp-stdio-remember-missing' -Tool 'memory_remember' -Arguments @{ title = 'x' } -DataDir $DirA
$missingIsError = $false
if ($missingContent.Rpc -and $missingContent.Rpc.result) { $missingIsError = [bool]$missingContent.Rpc.result.isError }
Add-SweepRow 'mcp-stdio-remember-missing-is-error' $missingIsError 'missing content'

if ($mcpUrl -and $mcpId) {
    $httpRemember = Invoke-McpHttpRpc 'mcp-http-recall' @{
        jsonrpc = '2.0'; id = 10; method = 'tools/call'
        params = @{ name = 'memory_recall'; arguments = @{ query = $mcpMarker; limit = 3 } }
    }
    $httpText = ''
    if ($httpRemember -and $httpRemember.result -and $httpRemember.result.content) {
        $httpText = [string]$httpRemember.result.content[0].text
    }
    Add-SweepRow 'mcp-http-recall-hit' ($httpText -like "*$mcpMarker*") 'http recall contains marker'
}

function Invoke-McpHttpTool([string]$Name, [string]$Tool, [hashtable]$Arguments, [string]$Command) {
    $rpc = Invoke-McpHttpRpc $Name @{ jsonrpc = '2.0'; id = $script:Step; method = 'tools/call'; params = @{ name = $Tool; arguments = $Arguments } }
    $envelope = Get-McpToolEnvelope $rpc
    Assert-Smoke "$Name-envelope" ($null -ne $envelope -and [string]$envelope.command -eq $Command -and [string]$envelope.status -in @('ok', 'warn'))
    return $envelope
}
$httpMarker = "mcp-http-business-$stamp"
$httpCreate = Invoke-McpHttpTool 'mcp-http-remember' 'memory_remember' @{ content = $httpMarker; title = "http-$stamp"; importance = 'important'; force = $true; parent = $id } 'remember'
$httpId = [string]$httpCreate.summary.id
Assert-Smoke 'mcp-http-remember-created-id' ([bool]$httpId)
foreach ($tool in @(
    @{ name = 'memory_status'; args = @{}; command = 'status' },
    @{ name = 'memory_taxonomy'; args = @{}; command = 'taxonomy' },
    @{ name = 'memory_list'; args = @{ limit = 100 }; command = 'list' },
    @{ name = 'memory_tree'; args = @{ from = $id; depth = 3 }; command = 'tree' },
    @{ name = 'memory_diary'; args = @{ limit = 100 }; command = 'diary' },
    @{ name = 'memory_history'; args = @{ id = $httpId; limit = 10 }; command = 'history' },
    @{ name = 'memory_chain'; args = @{ id = $httpId; depth = 2 }; command = 'chain' }
)) {
    Invoke-McpHttpTool "mcp-http-$($tool.name)" $tool.name $tool.args $tool.command | Out-Null
}
$httpShow = Invoke-McpHttpTool 'mcp-http-show' 'memory_show' @{ id = $httpId } 'show'
Assert-Smoke 'mcp-http-show-content' ([string]$httpShow.details.entry.content -eq $httpMarker)
Invoke-McpHttpTool 'mcp-http-update' 'memory_update' @{ id = $httpId; title = "http-updated-$stamp" } 'update' | Out-Null
$httpUpdated = Invoke-McpHttpTool 'mcp-http-update-readback' 'memory_show' @{ id = $httpId } 'show'
Assert-Smoke 'mcp-http-update-title-persisted' ([string]$httpUpdated.details.entry.title -eq "http-updated-$stamp")
Invoke-McpHttpTool 'mcp-http-attach' 'memory_attach' @{ id = $httpId; parent = $splitId } 'attach' | Out-Null
$httpParent = Invoke-McpHttpTool 'mcp-http-attach-readback' 'memory_show' @{ id = $httpId } 'show'
Assert-Smoke 'mcp-http-parent-persisted' ([string]$httpParent.details.entry.parent_id -eq $splitId)
$httpRecall = Invoke-McpHttpTool 'mcp-http-business-recall' 'memory_recall' @{ query = $httpMarker; limit = 5 } 'recall'
Assert-Smoke 'mcp-http-business-recall-hit' (($httpRecall | ConvertTo-Json -Depth 12) -like "*$httpMarker*")
$httpMark = Invoke-McpHttpTool 'mcp-http-query-log-mark' 'memory_query_log_mark' @{ ids = $httpId; good = $true } 'query-log'
Assert-Smoke 'mcp-http-query-log-marked' ([int]$httpMark.summary.marked -gt 0)
foreach ($deniedTool in @('memory_forget','memory_restore')) {
    $denied = Invoke-McpHttpRpc "mcp-http-default-$deniedTool" @{ jsonrpc='2.0'; id=$script:Step; method='tools/call'; params=@{ name=$deniedTool; arguments=@{id=$httpId} } }
    Assert-Smoke "mcp-http-default-$deniedTool-denied" ($denied.result.isError -eq $true -and $null -eq (Get-McpToolEnvelope $denied))
}
$defaultHttpRead = Invoke-McpHttpTool 'mcp-http-default-denial-readback' 'memory_show' @{ id=$httpId } 'show'
Assert-Smoke 'mcp-http-default-denial-preserved-content' ([string]$defaultHttpRead.details.entry.content -eq $httpMarker)
function Update-McpFixtureEndpoint {
    Get-OwnedRuntimeHealth $DirA | Out-Null
    $endpoint = Get-Content -LiteralPath (Join-Path $DirA 'runtime/endpoint.json') -Raw | ConvertFrom-Json
    $uri = [Uri][string]$endpoint.url
    if ($uri.Scheme -ne 'http' -or $uri.Host -notin @('127.0.0.1','localhost','::1')) { throw 'MCP fixture endpoint is not loopback.' }
    $script:origin = $uri.GetLeftPart([UriPartial]::Authority)
    $script:mcpUrl = "$script:origin/mcp"
    $script:mcpSse = "$script:origin/sse"
}
try {
    Invoke-Om -Name 'mcp-http-stop-before-explicit-policy' -ArgList @('--runtime-internal','--stop') -DataDir $DirA -Raw | Out-Null
    Invoke-Om -Name 'mcp-http-start-explicit-policy' -ArgList @('--json','status') -DataDir $DirA -AllowDestructiveMcpFixture | Out-Null
    Update-McpFixtureEndpoint
    $limited = Invoke-McpHttpRpc 'mcp-http-explicit-tools-list' @{jsonrpc='2.0';id=$script:Step;method='tools/list'}
    $limitedNames = @($limited.result.tools | ForEach-Object { [string]$_.name })
    $limitedWant = @('memory_show','memory_forget','memory_restore')
    Assert-Smoke 'mcp-http-explicit-policy-limited' ($limitedNames.Count -eq 3 -and @($limitedWant | Where-Object { $limitedNames -cnotcontains $_ }).Count -eq 0 -and @($limitedNames | Where-Object { $limitedWant -cnotcontains $_ }).Count -eq 0)
    Invoke-McpHttpTool 'mcp-http-forget' 'memory_forget' @{ id = $httpId } 'forget' | Out-Null
    Invoke-McpHttpTool 'mcp-http-restore' 'memory_restore' @{ id = $httpId } 'restore' | Out-Null
    $httpRestored = Invoke-McpHttpTool 'mcp-http-restore-readback' 'memory_show' @{ id = $httpId } 'show'
    Assert-Smoke 'mcp-http-restore-content-persisted' ([string]$httpRestored.details.entry.content -eq $httpMarker)
} finally {
    Invoke-Om -Name 'mcp-http-stop-explicit-policy' -ArgList @('--runtime-internal','--stop') -DataDir $DirA -Raw | Out-Null
    Invoke-Om -Name 'mcp-http-restart-default-policy' -ArgList @('--json','status') -DataDir $DirA | Out-Null
    Update-McpFixtureEndpoint
}
$restoredPolicy = Invoke-McpHttpRpc 'mcp-http-restored-default-list' @{jsonrpc='2.0';id=$script:Step;method='tools/list'}
$restoredNames = @($restoredPolicy.result.tools | ForEach-Object { [string]$_.name })
Assert-Smoke 'mcp-http-default-policy-restored' ($restoredNames.Count -eq 16 -and @($wantTools | Where-Object {$restoredNames -cnotcontains $_}).Count -eq 0 -and @($restoredNames | Where-Object {$wantTools -cnotcontains $_}).Count -eq 0)
$unknownHttp = Invoke-McpHttpRpc 'mcp-http-unknown-tool' @{ jsonrpc = '2.0'; id = 90; method = 'tools/call'; params = @{ name = 'memory_nope'; arguments = @{} } }
Assert-Smoke 'mcp-http-unknown-tool-is-error' ($unknownHttp.result.isError -eq $true)
Invoke-LocalSmoke -Name 'mcp-http-malformed-json' -Path '/mcp' -Payload '{' -RawBody -ExpectedStatus 400 | Out-Null
Invoke-LocalSmoke -Name 'mcp-http-foreign-origin' -Path '/mcp' -Payload @{} -Headers @{ Origin = 'https://example.invalid' } -ExpectedStatus 403 | Out-Null

# MCP writes schedule background indexing; report serialization must not act as its synchronization.
$m3InstallTimeout = Wait-OwnedModelIdle $DirA 1200
$m3Install = Invoke-Om -Name 'model-install-m3' -ArgList @('--json', 'model', 'install-m3') -DataDir $DirA -TimeoutSec $m3InstallTimeout
Assert-Smoke 'model-m3-installed-without-activation' ($m3Install.Ok -and $m3Install.Envelope.summary.activated -eq $false -and (Test-Path -LiteralPath (Join-Path $Root 'models/bge-m3/onnx/model_quantized.onnx')))
$m3Probe = Invoke-Om -Name 'model-probe-m3' -ArgList @('--json', 'model', 'probe', '--model', 'm3', '--text', $marker) -DataDir $DirA -TimeoutSec 600
Assert-Smoke 'model-m3-probe-success' ($m3Probe.Ok -and [string]$m3Probe.Envelope.status -eq 'ok')
$activateM3 = Invoke-Om -Name 'model-activate-m3' -ArgList @('--json', 'model', 'activate', 'm3') -DataDir $DirA -TimeoutSec 900
$m3Recall = Invoke-Om -Name 'model-m3-recall-existing-content' -ArgList @('--json', 'recall', $marker, '--limit', '5') -DataDir $DirA -TimeoutSec 300
$m3MarkerHits = @($m3Recall.Envelope.details | Where-Object { [string]$_.entry.content -like "*$marker*" })
Assert-Smoke 'model-m3-index-and-recall' ($activateM3.Ok -and [string]$activateM3.Envelope.summary.model -eq 'm3' -and [int]$activateM3.Envelope.summary.indexed -ge 0 -and $m3Recall.Ok -and [string]$m3Recall.Envelope.summary.embedding_model -eq 'm3' -and $m3MarkerHits.Count -gt 0)
$activateLegacy = Invoke-Om -Name 'model-activate-legacy-rejected' -ArgList @('--json', 'model', 'activate', 'legacy') -DataDir $DirA -ExpectExit @(2) -Raw
$m3AfterReject = Invoke-Om -Name 'model-m3-recall-after-retired-request' -ArgList @('--json', 'recall', $marker, '--limit', '5') -DataDir $DirA -TimeoutSec 300
$preservedContent = Invoke-Om -Name 'model-show-preserved-content' -ArgList @('--json', 'show', $httpId) -DataDir $DirA
Assert-Smoke 'model-retired-request-preserves-content' ($activateLegacy.Ok -and $m3AfterReject.Ok -and [string]$m3AfterReject.Envelope.summary.embedding_model -eq 'm3' -and $preservedContent.Ok -and [string]$preservedContent.Envelope.details.entry.content -ceq $httpMarker)
$revealed = Invoke-Om -Name 'secret-reveal-isolated' -ArgList @('--json', 'secret', '--reveal') -DataDir $DirA -Secret -AllowStatus @('warn')
Assert-Smoke 'secret-reveal-current-recovery-code' ($revealed.Ok -and [string]$revealed.Envelope.details.secret -eq $newSuper)
Invoke-Om -Name 'model-reset-cpu' -ArgList @('--json', 'model', 'reset-cpu') -DataDir $DirA -HostProfile | Out-Null
$resetEngine = Invoke-Om -Name 'model-reset-cpu-readback' -ArgList @('--json', 'model', 'engine') -DataDir $DirA
Assert-Smoke 'model-reset-cpu-engine' ($resetEngine.Ok -and [string]$resetEngine.Envelope.summary.engine -eq 'cpu')
Invoke-Om -Name 'runtime-stop' -ArgList @('--json', '--runtime-internal', '--stop') -DataDir $DirA -ExpectExit @(0, 2) -Raw | Out-Null
Stop-OurRuntimes
$uninstallRerank = Invoke-Om -Name 'model-uninstall-rerank-rejected' -ArgList @('--direct', '--json', 'model', 'uninstall-rerank') -DataDir $DirA -ExpectExit @(2) -Raw
Assert-Smoke 'model-rerank-command-rejected' ($uninstallRerank.Ok)
$uninstallBge = Invoke-Om -Name 'model-uninstall' -ArgList @('--direct', '--json', 'model', 'uninstall') -DataDir $DirA
Assert-Smoke 'model-bge-removed' ($uninstallBge.Ok -and $uninstallBge.Envelope.summary.removed -eq $true -and -not (Test-Path -LiteralPath (Join-Path $Root 'models/bge-m3')))
foreach ($required in $script:Catalog.required_assertions) {
    if (-not @($Rows | Where-Object { $_.Name -ceq $required -and $_.Ok -and $_.Status -ceq 'ok' }).Count) {
        Add-SweepRow "missing-required-$required" $false 'required positive assertion was not observed'
    }
}
Invoke-CloudCleanup
Write-SweepReport -Force

$failed = @($Rows | Where-Object { -not $_.Ok })
$passed = @($Rows | Where-Object { $_.Ok -and $_.Status -notin @('fail', 'skip') })
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# CLI dev sweep $cliVersion") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("- time: $([DateTimeOffset]::UtcNow.ToString('o'))") | Out-Null
$lines.Add("- package: $Package") | Out-Null
$lines.Add("- version: $cliVersion") | Out-Null
$lines.Add("- server: $Server") | Out-Null
$lines.Add("- latest: $($tags.latest)") | Out-Null
$lines.Add("- directory: $resolvedRoot") | Out-Null
$lines.Add("- passed: $($passed.Count)  failed: $($failed.Count)") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("| step | command | exit | status | result | note |") | Out-Null
$lines.Add("| --- | --- | --- | --- | --- | --- |") | Out-Null
foreach ($row in $Rows) {
    $mark = if (-not $row.Ok) { 'FAIL' } elseif ($row.Status -eq 'fail') { 'EXPECTED_ERROR' } elseif ($row.Status -eq 'skip') { 'SKIP' } else { 'PASS' }
    $note = Get-SafeReportNote (($row.Note + ' ' + $row.Leak).Trim())
    $lines.Add("| $($row.Step) | $($row.Name) | $($row.Exit) | $($row.Status) | $mark | $note |") | Out-Null
}
[System.IO.File]::WriteAllText($ReportPath, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
Write-Host "REPORT $ReportPath"
Write-Host "PASS $($passed.Count) FAIL $($failed.Count)"
Stop-OurRuntimes
if (-not $script:CloudCleanup.passed) {
    Write-Host 'FAILED: disposable cloud account cleanup was not confirmed; see coverage.json.'
    exit 1
}
if ($failed.Count -gt 0) { exit 1 }
if (@($script:Catalog.required_remaining).Count -gt 0) {
    Write-Host 'INCOMPLETE: required functional coverage remains; see coverage.json.'
    exit 1
}
if (@($script:Catalog.supplemental_required).Count -gt 0 -and -not $DeferSupplemental) {
    Write-Host 'INCOMPLETE: supplemental suites must pass the combined release gate; see coverage.json.'
    exit 1
}
exit 0
