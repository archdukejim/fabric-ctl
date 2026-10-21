<#
.SYNOPSIS
  Removes fabric's Hyper-V test lab: the VMs new_hyperv_lab.ps1 made (with their disks), its NAT, host address
  and switch. Manual 3.1.5.6.

.DESCRIPTION
  Run in an elevated PowerShell. It lists what it will remove and asks once; -Yes skips the question. It removes
  only the names new_hyperv_lab.ps1 uses, nothing else.
#>
[CmdletBinding()]
param(
    [string]$VmDir = 'D:\Hyper-V\fabric-lab',
    [switch]$Yes
)
$ErrorActionPreference = 'Stop'
$Switch = 'fabric-lab'
$Nat = 'fabric-lab-nat'
$Names = 'g23-vm-ub24-1', 'g23-vm-ub26-1', 'g23-vm-ub26-2', 'g23-vm-pve9-1', 'g23-vm-kub26-1',
         'g23-vm-ws25-1', 'g23-vm-w11-1'

$vms = Get-VM -ErrorAction SilentlyContinue | Where-Object { $Names -contains $_.Name }
Write-Host 'This removes:'
$vms | ForEach-Object { Write-Host "  VM $($_.Name) and its disks" }
if (Get-NetNat -Name $Nat -ErrorAction SilentlyContinue) { Write-Host "  NAT $Nat" }
if (Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue) { Write-Host "  switch $Switch (and its host address)" }
if (-not $Yes) {
    if ((Read-Host 'Remove all of this? (yes/no)') -ne 'yes') { Write-Host 'Nothing removed.'; return }
}
foreach ($vm in $vms) {
    if ($vm.State -ne 'Off') { Stop-VM -Name $vm.Name -TurnOff -Force }
    $disks = (Get-VMHardDiskDrive -VMName $vm.Name).Path
    Remove-VM -Name $vm.Name -Force
    $disks | Where-Object { $_ -and $_.StartsWith($VmDir) } | ForEach-Object { Remove-Item -Force $_ }
    Write-Host "  removed VM $($vm.Name)"
}
if (Get-NetNat -Name $Nat -ErrorAction SilentlyContinue) { Remove-NetNat -Name $Nat -Confirm:$false; Write-Host "  removed NAT $Nat" }
if (Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue) { Remove-VMSwitch -Name $Switch -Force; Write-Host "  removed switch $Switch" }
