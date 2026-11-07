# The generated 802.1X scripts on Windows PowerShell 5.1 (manual 3.1.5.12, decision 2.1.11.4): syntax and import only.
# Parses the scripts and looks their commands up; nothing here runs them, so no store, service or network changes.
# This proves nothing about 802.1X itself: that test needs real hardware (2.3.11.5).
param([Parameter(Mandatory = $true)][string]$Dir)
$ErrorActionPreference = "Stop"
$script:failed = 0

function Say($ok, $what) {
    if ($ok) { Write-Output "PASS $what" } else { Write-Output "FAIL $what"; $script:failed++ }
}

# Purpose: what is wrong with a script, as a list of strings: parse errors, commands that do not resolve, parameters
#          the command does not have, modules that do not load. Prints what each command resolved to.
function Get-Problems($path) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    foreach ($e in $errors) { "parse: line $($e.Extent.StartLineNumber): $($e.Message)" }
    if ($errors.Count -gt 0) { return }
    $found = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    if (@($found).Count -eq 0) { "no commands found: the check would have looked at nothing" }
    foreach ($call in $found) {
        $name = $call.GetCommandName()
        if (-not $name) { "line $($call.Extent.StartLineNumber): a command whose name is computed: $($call.Extent.Text)"; continue }
        $command = Get-Command -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $command) { "line $($call.Extent.StartLineNumber): $name does not resolve"; continue }
        [Console]::Out.WriteLine("  $name : $($command.CommandType) $($command.ModuleName)$(if ($command.CommandType -eq 'Application') { $command.Source })")
        if ($command.CommandType -eq "Application") { continue }
        foreach ($p in $call.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] }) {
            $hit = $command.Parameters.GetEnumerator() | Where-Object {
                $_.Key -like "$($p.ParameterName)*" -or ($_.Value.Aliases | Where-Object { $_ -eq $p.ParameterName }) }
            if (-not $hit) { "line $($call.Extent.StartLineNumber): $name has no parameter -$($p.ParameterName)" }
        }
        # the engine's own, always loaded, and a snap-in that Import-Module does not take
        if ($command.ModuleName -and $command.ModuleName -ne "Microsoft.PowerShell.Core") {
            try { Import-Module -Name $command.ModuleName -ErrorAction Stop }
            catch { "module $($command.ModuleName) of $name did not load: $_" }
        }
    }
}

$v = $PSVersionTable.PSVersion
Write-Output "PowerShell $v, edition $($PSVersionTable.PSEdition), on $((Get-CimInstance Win32_OperatingSystem).Caption)"
Say ($v.Major -eq 5 -and $v.Minor -eq 1 -and $PSVersionTable.PSEdition -eq "Desktop") "this really is Windows PowerShell 5.1"

foreach ($method in "tls", "ttls") {
    $path = Join-Path $Dir "fabric-8021x-$method.ps1"
    Write-Output "--- $path"
    $problems = @(Get-Problems $path)
    $problems | ForEach-Object { Write-Output "  $_" }
    Say ($problems.Count -eq 0) "${method}: parses with no errors, every command resolves with its parameters, every module loads"
}

# the check itself: each of these must be caught, or a pass above means nothing
foreach ($control in @(
        @("broken.ps1", "parse:", "a script that does not parse"),
        @("no-such-command.ps1", "does not resolve", "a command that does not exist"),
        @("no-such-parameter.ps1", "has no parameter", "a parameter the command does not have"))) {
    $problems = @(Get-Problems (Join-Path $Dir $control[0]))
    Say (($problems -join "`n").Contains($control[1])) "negative: $($control[2]) is caught"
}

Write-Output "$script:failed failed"
exit $(if ($script:failed) { 1 } else { 0 })
