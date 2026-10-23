<#
.SYNOPSIS
  Makes (or completes) fabric's Hyper-V test lab on gaming-23: the lab's VMs, each booting its installer ISO, the
  private switches and the extra NICs. Manual 3.1.5.2, 3.1.5.7; decisions 2.1.1.63, 2.1.1.64, 2.1.1.65.

.DESCRIPTION
  Needs only Hyper-V Administrators' rights, not an elevated PowerShell. It refuses, changing nothing, while the
  internal switch fabric-lab and its host address 10.88.0.1 (made once by the owner with prepare_host.ps1) are
  missing. Safe to run again: what exists is kept and reported; only what is missing is made. Every NIC gets the
  static MAC from lab_vms.json's scheme, so the unattended installs (install_vm.ps1) can match it. The lab's NAT is
  the router VM g23-vm-rtr-1 (its NIC wan on Hyper-V's Default Switch), not a NetNat on gaming-23.
  Remove everything it made with scripts/lab/remove_hyperv_lab.ps1.

.PARAMETER IsoDir
  The folder holding the installer ISOs (default D:\os\AMD64-x86).
.PARAMETER VmDir
  Where the VMs and their disks go (default D:\Hyper-V\fabric-lab).
.PARAMETER Only
  Make only these VMs (names from lab_vms.json); default all.
#>
[CmdletBinding()]
param(
    [string]$IsoDir = 'D:\os\AMD64-x86',
    [string]$VmDir = 'D:\Hyper-V\fabric-lab',
    [string[]]$Only = @()
)
$ErrorActionPreference = 'Stop'

$Lab = Get-Content -Raw (Join-Path $PSScriptRoot 'lab_vms.json') | ConvertFrom-Json
$Switch = 'fabric-lab'
$HostIp = $Lab.network.host

function Say($made, $what) { Write-Host ("  {0} {1}" -f ($(if ($made) { 'made' } else { 'kept' }), $what)) }
# 02-88-00-<last octet of the VM's address>-00-<n>: n 1 is the lab NIC, 2.. the extra NICs (lab_vms.json)
function Mac($vm, $n) { '028800{0:X2}00{1:X2}' -f [int]($vm.ip -split '\.')[3], [int]$n }

if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) { throw 'Hyper-V (its PowerShell module) is not enabled on this machine.' }
try { Get-VM -ErrorAction Stop | Out-Null } catch {
    throw "this account cannot use Hyper-V: it must be in gaming-23's Hyper-V Administrators group (prepare_host.ps1, then sign out and in). $_"
}
# what prepare_host.ps1 makes, the one step that needs administrator rights (3.1.5.2)
if (-not (Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue)) {
    throw "the internal switch $Switch is missing: the owner runs scripts\lab\prepare_host.ps1 as administrator first (manual 3.1.5.2). Nothing was changed."
}
$hostAddr = Get-NetIPAddress -IPAddress $HostIp -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -eq "vEthernet ($Switch)" }
if (-not $hostAddr) {
    throw "gaming-23 has no address $HostIp on vEthernet ($Switch): run prepare_host.ps1 again (manual 3.1.5.2). Nothing was changed."
}
if (-not (Get-VMSwitch -Name 'Default Switch' -ErrorAction SilentlyContinue)) {
    throw "Hyper-V's built-in 'Default Switch' is missing: the router's wan NIC needs it for the lab's internet. Nothing was changed."
}

# check every ISO before making anything, so a missing one changes nothing. With `powershell -File`, "-Only a,b"
# arrives as one string, so names are split on commas here.
$Only = @($Only | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$wanted = @(if ($Only.Count) { $Lab.vms | Where-Object { $Only -contains $_.name } } else { $Lab.vms })
if ($Only.Count -and $wanted.Count -ne $Only.Count) {
    throw "unknown VM name in -Only; known: $($Lab.vms.name -join ', ')"
}
foreach ($vm in $wanted) {
    $iso = Join-Path $IsoDir $vm.iso
    if (-not (Test-Path $iso)) { throw "missing ISO for $($vm.name): $iso (nothing was changed)" }
}

Write-Host "fabric lab: switch $Switch (host $HostIp); the router $($Lab.network.gateway) does the NAT"
New-Item -ItemType Directory -Force -Path $VmDir | Out-Null
foreach ($vm in $wanted) {
    if (Get-VM -Name $vm.name -ErrorAction SilentlyContinue) {
        Say $false "VM $($vm.name) (left as it is; remove it first to make it again)"; continue
    }
    $vhd = Join-Path $VmDir "$($vm.name).vhdx"
    New-VM -Name $vm.name -Generation 2 -MemoryStartupBytes ($vm.mem * 1GB) -SwitchName $Switch `
           -NewVHDPath $vhd -NewVHDSizeBytes ($vm.disk * 1GB) -Path $VmDir | Out-Null
    Set-VM -Name $vm.name -ProcessorCount $vm.cpu -StaticMemory -AutomaticCheckpointsEnabled $false `
           -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
    Get-VMNetworkAdapter -VMName $vm.name | Select-Object -First 1 |
        Set-VMNetworkAdapter -StaticMacAddress (Mac $vm 1) -DeviceNaming On
    if ($vm.kind -eq 'linux') {
        Set-VMFirmware -VMName $vm.name -SecureBootTemplate MicrosoftUEFICertificateAuthority
    } else {
        Set-VMKeyProtector -VMName $vm.name -NewLocalKeyProtector
        Enable-VMTPM -VMName $vm.name
    }
    $dvd = Add-VMDvdDrive -VMName $vm.name -Path (Join-Path $IsoDir $vm.iso) -Passthru
    Set-VMFirmware -VMName $vm.name -FirstBootDevice $dvd
    Enable-VMIntegrationService -VMName $vm.name -Name 'Guest Service Interface'
    Say $true "VM $($vm.name): $($vm.cpu) vCPU, $($vm.mem) GB, $($vm.disk) GB disk, address $($vm.ip)"
}
foreach ($name in $Lab.private_switches) {
    if (-not (Get-VMSwitch -Name $name -ErrorAction SilentlyContinue)) {
        New-VMSwitch -Name $name -SwitchType Private | Out-Null; Say $true "private switch $name"
    } else { Say $false "private switch $name" }
}
foreach ($nic in $Lab.nics) {
    $vm = $Lab.vms | Where-Object name -eq $nic.vm
    if (-not (Get-VM -Name $nic.vm -ErrorAction SilentlyContinue)) { continue }      # its VM not made (-Only)
    if (Get-VMNetworkAdapter -VMName $nic.vm -Name $nic.name -ErrorAction SilentlyContinue) {
        Say $false "NIC $($nic.name) on $($nic.vm)"; continue
    }
    Add-VMNetworkAdapter -VMName $nic.vm -Name $nic.name -SwitchName $nic.switch `
                         -StaticMacAddress (Mac $vm $nic.n) -DeviceNaming On
    switch ($nic.mode) {
        'trunk'  { Set-VMNetworkAdapterVlan -VMName $nic.vm -VMNetworkAdapterName $nic.name -Trunk `
                       -AllowedVlanIdList ($Lab.vlans -join ',') -NativeVlanId 0 }
        'access' { Set-VMNetworkAdapterVlan -VMName $nic.vm -VMNetworkAdapterName $nic.name -Access -VlanId $nic.vlan }
        'port'   { Set-VMNetworkAdapter -VMName $nic.vm -Name $nic.name -MacAddressSpoofing On }
    }
    Say $true "NIC $($nic.name) on $($nic.vm) ($($nic.switch), $($nic.mode))"
}
Write-Host 'Done. Next: scripts/lab/make_seeds.sh in WSL, then install_vm.ps1, the router first (manual 3.1.5.3).'
