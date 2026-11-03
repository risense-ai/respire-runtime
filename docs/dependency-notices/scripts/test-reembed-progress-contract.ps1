# Exercise the actual sweep predicates without executing the account/network sweep.
param([string]$Sweep = (Join-Path $PSScriptRoot 'dev-release-sweep.ps1'))
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Sweep, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Sweep parse failed' }
$predicates = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$invalidProgress'
}, $true))
$diagnostics = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$script:ModelProgressEvidence.contract'
}, $true))
if ($predicates.Count -ne 1 -or $diagnostics.Count -ne 1) { throw 'Sweep progress validation assignments changed' }
$predicate = [scriptblock]::Create($predicates[0].Extent.Text)
$diagnostic = [scriptblock]::Create($diagnostics[0].Extent.Text)

function Test-Sample([hashtable]$Fields, [int]$Invalid, [string]$Counter = '') {
    $reembedTask = 'synthetic-progress-task'
    $reembed = [pscustomobject]@{ Ok = $true; Progress = @([pscustomobject]$Fields) }
    $script:ModelProgressEvidence = @{ completed_inactive = $true }
    . $predicate
    . $diagnostic
    if ($invalidProgress.Count -ne $Invalid -or $script:ModelProgressEvidence.contract.invalid_count -ne $Invalid) {
        throw 'Sweep incorrectly accepted or rejected progress sample'
    }
    if ($Counter -and $script:ModelProgressEvidence.contract[$Counter] -ne 1) { throw 'Sweep diagnostic disagrees with rejected sample' }
}

# The macOS failure observed the real index-load sample (done=0,total=null).
$sample = @{ id = 'synthetic-progress-task'; phase = 'index-load'; cancelled = $false; done = 0; total = $null }
foreach ($phase in @('load', 'index-load', 'index')) {
    $valid = $sample.Clone(); $valid.phase = $phase
    Test-Sample $valid 0
    $valid.done = [long]2; $valid.total = [long]2
    Test-Sample $valid 0
}
foreach ($phase in @('download', 'unrecognized', '', $null)) {
    $invalid = $sample.Clone(); $invalid.phase = $phase
    Test-Sample $invalid 1 'invalid_phase_count'
}
$invalid = $sample.Clone(); $invalid.id = 'another-task'
Test-Sample $invalid 1 'invalid_id_count'
$invalid = $sample.Clone(); $invalid.cancelled = $true
Test-Sample $invalid 1 'invalid_cancelled_count'
foreach ($done in @(-1, '0', $null)) {
    $invalid = $sample.Clone(); $invalid.done = $done
    Test-Sample $invalid 1 'invalid_done_count'
}
foreach ($total in @(-1, '0')) {
    $invalid = $sample.Clone(); $invalid.total = $total
    Test-Sample $invalid 1 'invalid_total_count'
}
$invalid = $sample.Clone(); $invalid.done = 2; $invalid.total = 1
Test-Sample $invalid 1 'invalid_total_count'
Write-Host 'PASS: real sweep accepts all three indexing phases and rejects invalid identity, cancellation and counters'
