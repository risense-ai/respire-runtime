<# Actual Windows Task Scheduler sign-in action against a disposable off-mode profile.
   Never installs startup on a user's computer. Intended for the manual hosted CI job.
   No account, keyring, model download, password, elevation or persistent credential.
#>
param([Parameter(Mandatory = $true)][string]$Executable)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:STARTUP_TEST_HOSTED -ne 'true') {
    throw 'This fixture runs only in the explicitly selected GitHub-hosted Windows CI job'
}
if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    throw 'Windows Task Scheduler validation requires Windows'
}
$nativeExecutable = (Get-Item -LiteralPath $Executable -ErrorAction Stop).FullName
if ([IO.Path]::GetExtension($nativeExecutable) -ne '.exe') { throw 'Expected a native CLI executable' }
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('respire-startup-ci-' + [guid]::NewGuid().ToString('N'))
$fixtureHome = Join-Path $fixtureRoot 'home'
$profileRoot = Join-Path $fixtureHome '.rsrs'
$selectedProfile = Join-Path $profileRoot 'accounts/startup-fixture'
$nativeDirectory = Join-Path $profileRoot 'bin'
$statusFile = Join-Path $fixtureRoot 'startup-status.json'
$taskName = 'RespireStartupCI-' + [guid]::NewGuid().ToString('N')
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$registered = $false
$runtimeOwned = $false
$startupAttempted = $false
$runtimeStopped = $false
$startupAction = $null
$primaryFailure = $null
$validationPassed = $false
$utf8 = [Text.UTF8Encoding]::new($false)
New-Item -ItemType Directory -Path $selectedProfile -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $profileRoot 'client.json'),
    (@{data_dir = $selectedProfile; service_mode = 'off'} | ConvertTo-Json -Compress), $utf8)
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$runtimePort = $listener.LocalEndpoint.Port
$listener.Stop()
$healthUrl = "http://127.0.0.1:$runtimePort/api/health"
function Literal([string]$Value) { return "'" + $Value.Replace("'", "''") + "'" }
function EnvironmentPrefix {
    return @"
Get-ChildItem Env: | Where-Object { `$_.Name -match '^(RSRS_|RESPIRE_|ONEMEMORY_)' } | Remove-Item
`$env:HOME = $(Literal $fixtureHome)
`$env:USERPROFILE = $(Literal $fixtureHome)
`$env:RSRS_DATA_DIR = $(Literal $profileRoot)
`$env:RSRS_BIN_DIR = $(Literal $nativeDirectory)
`$env:RSRS_RPC_PORT = '$runtimePort'
`$env:RSRS_NO_AUTOSYNC = '1'
`$env:RSRS_UPDATE_CHECK = '0'
`$env:RUST_MIN_STACK = '16777216'
"@
}
$powershell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
function InvokeFixture([string]$Arguments) {
    $code = (EnvironmentPrefix) + "`n& " + (Literal $nativeExecutable) + ' ' + $Arguments + "`nexit `$LASTEXITCODE"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $result = & $powershell -NoProfile -NonInteractive -EncodedCommand $encoded
    $fixtureExit = $LASTEXITCODE
    return @{exit = $fixtureExit; output = ($result -join "`n")}
}
function FindFixtureTask {
    try { return Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop }
    catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { return $null }
        throw
    }
}
function ResolveTaskSid([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 512) { throw 'Task identity is missing or invalid' }
    try {
        if ($Value -match '^S-\d-') { return [Security.Principal.SecurityIdentifier]::new($Value).Value }
        return [Security.Principal.NTAccount]::new($Value).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch { throw 'Task identity could not be resolved to a verified Windows SID' }
}
function TaskOwnershipChecks($TaskObject) {
    $actions = @($TaskObject.Actions)
    $triggers = @($TaskObject.Triggers)
    $principalSid = ResolveTaskSid $TaskObject.Principal.UserId
    $triggerSid = if ($triggers.Count -eq 1) { ResolveTaskSid $triggers[0].UserId } else { '' }
    $actionPathMatches = $false
    if ($actions.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($actions[0].Execute)) {
        $actionPathMatches = [StringComparer]::OrdinalIgnoreCase.Equals(
            [IO.Path]::GetFullPath($actions[0].Execute), [IO.Path]::GetFullPath($powershell))
    }
    return [ordered]@{
        principal_sid = $principalSid -eq $identity.User.Value
        interactive = $TaskObject.Principal.LogonType -eq 'Interactive'
        limited = $TaskObject.Principal.RunLevel -eq 'Limited'
        one_action = $actions.Count -eq 1
        executable = $actionPathMatches
        arguments = $actions.Count -eq 1 -and $actions[0].Arguments -ceq $startupAction.Arguments
        one_trigger = $triggers.Count -eq 1
        logon_trigger = $triggers.Count -eq 1 -and $triggers[0].CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger'
        trigger_sid = $triggerSid -eq $identity.User.Value
    }
}
function RemoveFixtureTask {
    $currentTask = FindFixtureTask
    if ($null -eq $currentTask) { return }
    $checks = TaskOwnershipChecks $currentTask
    if ($checks.Values -contains $false) { throw 'Task ownership/action/trigger changed; refusing removal' }
    if ($currentTask.State -eq 'Running') {
        Stop-ScheduledTask -TaskName $taskName -TaskPath '\'
        $stopDeadline = [DateTime]::UtcNow.AddSeconds(10)
        while ((FindFixtureTask).State -eq 'Running' -and [DateTime]::UtcNow -lt $stopDeadline) {
            Start-Sleep -Milliseconds 100
        }
        if ((FindFixtureTask).State -eq 'Running') { throw 'Owned scheduled task did not stop; preserving fixture' }
    }
    Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false
    if ($null -ne (FindFixtureTask)) { throw 'Fixture task remained after removal' }
}
try {
    if ($null -ne (FindFixtureTask)) { throw 'Refusing to replace an existing task' }
    $startupCode = (EnvironmentPrefix) + "`n& " + (Literal $nativeExecutable) +
        ' status --json | Out-File -Encoding utf8 -LiteralPath ' + (Literal $statusFile) + "`nexit `$LASTEXITCODE"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($startupCode))
    $startupAction = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -EncodedCommand $encoded"
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.User.Value
    $principal = New-ScheduledTaskPrincipal -UserId $identity.User.Value -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $startupAction -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
    $registered = $true
    $task = FindFixtureTask
    $checks = TaskOwnershipChecks $task
    Write-Output (@{principal_form = $(if ($task.Principal.UserId -match '^S-\d-') {'sid'} else {'account-name'});
        trigger_form = $(if ($task.Triggers.UserId -match '^S-\d-') {'sid'} else {'account-name'});
        ownership_checks = $checks} | ConvertTo-Json -Depth 4 -Compress)
    if ($checks.Values -contains $false) { throw 'Scheduled task identity/action/trigger drifted' }
    # A case change in Base64 is a different command, even though Windows paths
    # and account names can be compared through their canonical identities.
    $base64Offset = $startupAction.Arguments.LastIndexOf(' ') + 1
    $changedArguments = $null
    for ($offset = $base64Offset; $offset -lt $startupAction.Arguments.Length; $offset++) {
        $letter = $startupAction.Arguments[$offset]
        if ([char]::IsLetter($letter)) {
            $replacement = if ([char]::IsUpper($letter)) { [char]::ToLowerInvariant($letter) } else { [char]::ToUpperInvariant($letter) }
            $changedArguments = $startupAction.Arguments.Substring(0, $offset) + $replacement + $startupAction.Arguments.Substring($offset + 1)
            break
        }
    }
    if ($null -eq $changedArguments) { throw 'Encoded command has no case-sensitive test character' }
    $changedTask = [pscustomobject]@{Principal = $task.Principal; Triggers = $task.Triggers;
        Actions = @([pscustomobject]@{Execute = $task.Actions.Execute; Arguments = $changedArguments})}
    if ((TaskOwnershipChecks $changedTask).arguments) { throw 'Case-changed encoded command was accepted' }
    $startupAttempted = $true
    Start-ScheduledTask -TaskName $taskName -TaskPath '\'
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    $health = $null
    $status = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        try { $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2 } catch { Start-Sleep -Milliseconds 100; continue }
        if ($health.server -ne 'respire' -or [IO.Path]::GetFullPath($health.data_dir) -ne [IO.Path]::GetFullPath($selectedProfile)) {
            throw 'Fixture port belongs to another runtime/profile; no lifecycle request sent'
        }
        $runtimeOwned = $true
        if (Test-Path -LiteralPath $statusFile) {
            try { $status = Get-Content -Raw -LiteralPath $statusFile | ConvertFrom-Json } catch { $status = $null }
            if ($null -ne $status) { break }
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $runtimeOwned -or $null -eq $status) { throw 'Scheduled host startup did not become ready' }
    if ($status.command -ne 'status' -or $status.status -notin @('ok', 'skip')) { throw 'Scheduled host command did not complete successfully' }
    $runtimePid = $health.pid
    $denied = InvokeFixture '--client-only --runtime-internal --stop --json'
    if ($denied.exit -eq 0 -or ($denied.output | ConvertFrom-Json).status -ne 'fail') { throw 'Client-only lifecycle command was accepted' }
    if ((Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2).pid -ne $runtimePid) { throw 'Client-only command changed runtime ownership' }
    $stop = InvokeFixture '--runtime-internal --stop --json'
    if ($stop.exit -ne 0) { throw 'Owned host runtime could not be stopped' }
    $runtimeOwned = $false
    $runtimeStopped = $true
    RemoveFixtureTask
    $registered = $false
    $validationPassed = $true
} catch {
    $primaryFailure = $_
    throw
} finally {
  try {
    if ($runtimeOwned) {
        try {
            $current = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
            if ($current.server -eq 'respire' -and [IO.Path]::GetFullPath($current.data_dir) -eq [IO.Path]::GetFullPath($selectedProfile)) {
                $cleanupStop = InvokeFixture '--runtime-internal --stop --json'
                if ($cleanupStop.exit -eq 0) { $runtimeOwned = $false; $runtimeStopped = $true }
            }
        } catch { Write-Warning 'Fixture runtime cleanup needs inspection; no unrelated process was killed' }
    }
    if ($registered -or $null -ne $startupAction) { RemoveFixtureTask }
    if (-not $startupAttempted -or $runtimeStopped) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
    else { Write-Warning 'Startup outcome uncertain; fixture files retained for inspection' }
  } catch {
    if ($null -eq $primaryFailure) { throw }
    Write-Warning ('Fixture cleanup also failed; preserving the original exception: ' + $_.Exception.Message)
  }
}
if ($validationPassed) {
    Write-Output (@{result = 'PASS'; profile = 'isolated synthetic off-mode'; sign_in_trigger = $true;
        limited_interactive_principal = $true; host_startup = $true; client_only_stop_denied = $true;
        task_removed = $true; runtime_stopped = $true; encoded_command_case_guard = $true;
        physical_reboot_tested = $false} | ConvertTo-Json -Compress)
}
