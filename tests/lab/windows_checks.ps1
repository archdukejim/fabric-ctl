# -----------------------------------------------------------------------
# The Windows checks of 2.3.6.1.19 (W1-W4, W6-W9), run on a Windows member of a fabric site, in PowerShell as
# Administrator (manual 1.11.1.5, decision 2.1.11.7). W5 (PEAP as the machine, then a person) is read on the fabric
# host by tests/lab/dot1x.sh (WINDOWS_MACHINE=<this computer's name>).
#
#   powershell -ExecutionPolicy Bypass -File .\windows_checks.ps1 -Site lan -Domain lan.example -DcName dc1 `
#       [-Person alice] [-ExampleText hello]
#
# -Person: a person of the site signed in on this machine now (W6); -ExampleText: the value set on the fabric host
# with `fabricctl gpo set ExampleSetting ExampleText=<it>` (W7). Prints PASS / FAIL per check with what it saw;
# exits 1 when any check failed. It changes nothing but running gpupdate and w32tm's resync.
# Written 2026-10-12, NOT RUN (the owner's direction for 0.9; the Incus lab's Windows VM is not built: 2.3.11.4).
# -----------------------------------------------------------------------
param(
    [Parameter(Mandatory = $true)][string]$Site,
    [Parameter(Mandatory = $true)][string]$Domain,
    [Parameter(Mandatory = $true)][string]$DcName,
    [string]$Person = "",
    [string]$ExampleText = ""
)
$ErrorActionPreference = "Continue"
$script:Failed = 0

function Check([string]$Id, [string]$What, [bool]$Ok, [string]$Saw) {
    if ($Ok) { Write-Output "PASS $Id $What" }
    else { Write-Output "FAIL $Id $What  -> $Saw"; $script:Failed++ }
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "run this in PowerShell as Administrator"
    exit 2
}

# W1: policies arrive
gpupdate /force | Out-Null
$gp = (gpresult /r /scope computer) -join "`n"
Check "W1" "policies arrive: trust in fabric's root CA, $Site log-on rights, $Site Windows baseline" `
    (($gp -match "trust in fabric's root CA") -and ($gp -match "$Site log-on rights") -and `
     ($gp -match "$Site Windows baseline")) ($gp.Substring(0, [Math]::Min(600, $gp.Length)))

# W2: signed time from the DC
w32tm /resync /rediscover | Out-Null
$status = (w32tm /query /status) -join "`n"
$source = (w32tm /query /source) -join " "
$timeErrors = Get-WinEvent -LogName System -MaxEvents 30 -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -eq "Microsoft-Windows-Time-Service" -and $_.Message -match "unsigned|access" }
Check "W2" "time from the site's DC, signed" `
    (($source -match [regex]::Escape($DcName)) -and ($status -match "Stratum: [1-9]") -and -not $timeErrors) `
    "source=$source; $($timeErrors | Select-Object -First 1 -ExpandProperty Message)"

# W3: the baseline's settings
$sync = (Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -Name SyncForegroundPolicy -ErrorAction SilentlyContinue).SyncForegroundPolicy
$type = (Get-ItemProperty "HKLM:\Software\Policies\Microsoft\W32Time\Parameters" -Name Type `
    -ErrorAction SilentlyContinue).Type
Check "W3" "baseline settings: SyncForegroundPolicy 1, W32Time NT5DS" (($sync -eq 1) -and ($type -eq "NT5DS")) `
    "SyncForegroundPolicy=$sync Type=$type"

# W4: the 802.1X profile (with FreeRADIUS on and a group mapped; restart once)
$svc = (sc.exe qc dot3svc) -join "`n"
$profiles = (netsh lan show profiles) -join "`n"
Check "W4" "Wired AutoConfig starts automatically; a PEAP profile for radius.$Domain" `
    (($svc -match "AUTO_START") -and ($profiles -match "PEAP") -and ($profiles -match [regex]::Escape("radius.$Domain"))) `
    ($profiles.Substring(0, [Math]::Min(600, $profiles.Length)))

# W6: a domain person's first log-on (they are signed in on this machine)
if ($Person) {
    $groups = (whoami /groups) -join "`n"
    $me = (whoami)
    Check "W6" "$Person signed in; whoami /groups lists $Site-users" `
        (($me -match [regex]::Escape($Person)) -and ($groups -match [regex]::Escape("$Site-users"))) "whoami=$me"
} else {
    Write-Output "SKIP W6 (give -Person, run in that person's session)"
}

# W7: a policy from the ADMX editor
if ($ExampleText) {
    $ex = (Get-ItemProperty "HKLM:\Software\Policies\Example\Starter" -Name ExampleText `
        -ErrorAction SilentlyContinue).ExampleText
    Check "W7" "the ADMX policy arrived: ExampleText = $ExampleText" ($ex -eq $ExampleText) "ExampleText=$ex"
} else {
    Write-Output "SKIP W7 (set it on the fabric host first, then give -ExampleText)"
}

# W8: SYSVOL hidden, policy still applied (2.1.6.16)
$shares = (net view "\\$DcName" 2>&1) -join "`n"
Check "W8" "\\$DcName lists no SYSVOL or NETLOGON, and the site's GPOs still apply" `
    (($shares -notmatch "SYSVOL") -and ($shares -notmatch "NETLOGON") -and ($gp -match "$Site Windows baseline")) `
    ($shares.Substring(0, [Math]::Min(400, $shares.Length)))

# W9: the site's windows-admins role is a local administrator (2.1.9.13)
$admins = (net localgroup Administrators) -join "`n"
Check "W9" "$Site-windows-admins is in the local Administrators" ($admins -match [regex]::Escape("\$Site-windows-admins")) `
    ($admins.Substring(0, [Math]::Min(400, $admins.Length)))

Write-Output ""
if ($script:Failed) { Write-Output "$script:Failed check(s) failed"; exit 1 }
Write-Output "all checks passed"
exit 0
