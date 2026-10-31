<#
.SYNOPSIS
  The one step of fabric's Hyper-V lab that needs administrator rights on gaming-23, run once by the owner: the agent's
  account into Hyper-V Administrators, and the lab's internal switch with its host address 10.88.0.1 (gaming-23's way
  to SSH into the lab). No NetNat: Windows allows one per host and the owner's pve-lab-nat has it, so the router VM
  g23-vm-rtr-1 does the lab's NAT. Manual 3.1.5.2; decision 2.1.1.65.

.DESCRIPTION
  Run in an elevated PowerShell. Safe to run again: what exists is kept and reported. Everything else in the lab
  (VMs, private switches, installs, checkpoints) the agent does itself with Hyper-V Administrators' rights.
  -Undo removes what this script made (and a fabric-lab-nat, if an older run made one) (after the lab's VMs are gone: scripts/lab/remove_hyperv_lab.ps1).

.PARAMETER User
  The account the agent runs as (default: the account that started this PowerShell, before elevation it is the same
  for an administrator who elevates their own session).
#>
[CmdletBinding()]
param(
    [string]$User = "$env:USERDOMAIN\$env:USERNAME",
    [switch]$Undo
)
$ErrorActionPreference = 'Stop'
$Group = 'Hyper-V Administrators'
$Switch = 'fabric-lab'
$Nat = 'fabric-lab-nat'
$Prefix = '10.88.0'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this in an elevated PowerShell (Run as administrator).' }
if (-not (Get-Command New-VMSwitch -ErrorAction SilentlyContinue)) { throw 'Hyper-V is not enabled on this machine.' }

function Say($made, $what) { Write-Host ("  {0} {1}" -f ($(if ($made) { 'made' } else { 'kept' }), $what)) }

if ($Undo) {
    if (Get-NetNat -Name $Nat -ErrorAction SilentlyContinue) { Remove-NetNat -Name $Nat -Confirm:$false; Write-Host "  removed NAT $Nat" }
    if (Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue) { Remove-VMSwitch -Name $Switch -Force; Write-Host "  removed switch $Switch" }
    if (Get-LocalGroupMember -Group $Group -Member $User -ErrorAction SilentlyContinue) {
        Remove-LocalGroupMember -Group $Group -Member $User; Write-Host "  removed $User from $Group"
    }
    return
}

Write-Host "fabric lab, host side: $User in $Group; switch $Switch at $Prefix.1 (no NAT: the router VM does it)"
if (-not (Get-LocalGroupMember -Group $Group -Member $User -ErrorAction SilentlyContinue)) {
    Add-LocalGroupMember -Group $Group -Member $User; Say $true "$User in $Group (sign out and in for it to apply)"
} else { Say $false "$User in $Group" }

if (-not (Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $Switch -SwitchType Internal | Out-Null; Say $true "switch $Switch"
} else { Say $false "switch $Switch" }

$ifIndex = (Get-NetAdapter -Name "vEthernet ($Switch)").ifIndex
if (-not (Get-NetIPAddress -InterfaceIndex $ifIndex -IPAddress "$Prefix.1" -ErrorAction SilentlyContinue)) {
    New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress "$Prefix.1" -PrefixLength 24 | Out-Null
    Say $true "host address $Prefix.1"
} else { Say $false "host address $Prefix.1" }

Write-Host 'Done. Sign out of Windows and back in (so the group membership applies), then tell the agent.'
