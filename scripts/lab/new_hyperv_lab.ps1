<#
.SYNOPSIS
  Builds (or completes) fabric's Hyper-V test lab on gaming-23: an internal switch with NAT, and the lab's VMs,
  each booting its installer ISO. Manual 3.1.5; decision 2.1.1.63.

.DESCRIPTION
  Run in an elevated PowerShell. Safe to run again: what exists is kept and reported, never changed or removed;
  only what is missing is made. It changes nothing outside its own switch, NAT, host address and VMs.
  Remove everything it made with scripts/lab/remove_hyperv_lab.ps1.

.PARAMETER IsoDir
  The folder holding the installer ISOs (default D:\os\AMD64-x86).
.PARAMETER VmDir
  Where the VMs and their disks go (default D:\Hyper-V\fabric-lab).
.PARAMETER Only
  Make only these VMs (names from the table below); default all.
#>
[CmdletBinding()]
param(
    [string]$IsoDir = 'D:\os\AMD64-x86',
    [string]$VmDir = 'D:\Hyper-V\fabric-lab',
    [string[]]$Only = @()
)
$ErrorActionPreference = 'Stop'

$Switch = 'fabric-lab'
$Nat = 'fabric-lab-nat'
$Prefix = '10.88.0'          # the lab's /24; the host is .1 (manual 3.1.5.2)

# name, ISO, vCPUs, memory GB, disk GB, kind (linux | windows), its address (set in its installer, 3.1.5.3)
$Vms = @(
    @{ Name = 'g23-vm-ub24-1';  Iso = 'ubuntu-24.04.4-live-server-amd64.iso'; Cpu = 4; Mem = 8; Disk = 64; Kind = 'linux';   Ip = "$Prefix.10" }
    @{ Name = 'g23-vm-ub26-1';  Iso = 'ubuntu-26.04.1-live-server-amd64.iso'; Cpu = 4; Mem = 8; Disk = 64; Kind = 'linux';   Ip = "$Prefix.11" }
    @{ Name = 'g23-vm-ub26-2';  Iso = 'ubuntu-26.04.1-live-server-amd64.iso'; Cpu = 2; Mem = 2; Disk = 32; Kind = 'linux';   Ip = "$Prefix.21" }
    @{ Name = 'g23-vm-pve9-1';  Iso = 'proxmox-ve_9.1-1.iso';                 Cpu = 2; Mem = 4; Disk = 48; Kind = 'linux';   Ip = "$Prefix.22" }
    @{ Name = 'g23-vm-kub26-1'; Iso = 'kubuntu-26.04-desktop-amd64.iso';      Cpu = 2; Mem = 4; Disk = 48; Kind = 'linux';   Ip = "$Prefix.31" }
    @{ Name = 'g23-vm-ws25-1';  Iso = 'SERVER_EVAL_x64FRE_en-us.iso';         Cpu = 2; Mem = 4; Disk = 64; Kind = 'windows'; Ip = "$Prefix.41" }
    @{ Name = 'g23-vm-w11-1';   Iso = 'Win11_25H2_English_x64_v2.iso';        Cpu = 2; Mem = 4; Disk = 64; Kind = 'windows'; Ip = "$Prefix.42" }
)

function Say($ok, $what) { Write-Host ("  {0} {1}" -f ($(if ($ok) { 'made' } else { 'kept' }), $what)) }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this in an elevated PowerShell (Run as administrator).' }
if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) { throw 'Hyper-V is not enabled on this machine.' }

# check every ISO before making anything, so a missing one changes nothing. With `powershell -File`, "-Only a,b"
# arrives as one string, so names are split on commas here.
$Only = @($Only | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$wanted = @(if ($Only.Count) { $Vms | Where-Object { $Only -contains $_.Name } } else { $Vms })
if ($Only.Count -and $wanted.Count -ne $Only.Count) {
    throw "unknown VM name in -Only; known: $($Vms.Name -join ', ')"
}
foreach ($vm in $wanted) {
    $iso = Join-Path $IsoDir $vm.Iso
    if (-not (Test-Path $iso)) { throw "missing ISO for $($vm.Name): $iso (nothing was changed)" }
}

Write-Host "fabric lab: switch $Switch, network $Prefix.0/24 with NAT"
if (-not (Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $Switch -SwitchType Internal | Out-Null; Say $true "switch $Switch"
} else { Say $false "switch $Switch" }

$ifIndex = (Get-NetAdapter -Name "vEthernet ($Switch)").ifIndex
if (-not (Get-NetIPAddress -InterfaceIndex $ifIndex -IPAddress "$Prefix.1" -ErrorAction SilentlyContinue)) {
    New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress "$Prefix.1" -PrefixLength 24 | Out-Null
    Say $true "host address $Prefix.1"
} else { Say $false "host address $Prefix.1" }

$nat = Get-NetNat -ErrorAction SilentlyContinue
if (-not ($nat | Where-Object Name -eq $Nat)) {
    $clash = $nat | Where-Object { $_.InternalIPInterfaceAddressPrefix -eq "$Prefix.0/24" }
    if ($clash) { throw "another NAT ($($clash.Name)) already serves $Prefix.0/24" }
    New-NetNat -Name $Nat -InternalIPInterfaceAddressPrefix "$Prefix.0/24" | Out-Null; Say $true "NAT $Nat"
} else { Say $false "NAT $Nat" }

New-Item -ItemType Directory -Force -Path $VmDir | Out-Null
foreach ($vm in $wanted) {
    if (Get-VM -Name $vm.Name -ErrorAction SilentlyContinue) {
        Say $false "VM $($vm.Name) (left as it is; remove it first to make it again)"; continue
    }
    $vhd = Join-Path $VmDir "$($vm.Name).vhdx"
    New-VM -Name $vm.Name -Generation 2 -MemoryStartupBytes ($vm.Mem * 1GB) -SwitchName $Switch `
           -NewVHDPath $vhd -NewVHDSizeBytes ($vm.Disk * 1GB) -Path $VmDir | Out-Null
    Set-VM -Name $vm.Name -ProcessorCount $vm.Cpu -StaticMemory -AutomaticCheckpointsEnabled $false `
           -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
    if ($vm.Kind -eq 'linux') {
        Set-VMFirmware -VMName $vm.Name -SecureBootTemplate MicrosoftUEFICertificateAuthority
    } else {
        Set-VMKeyProtector -VMName $vm.Name -NewLocalKeyProtector
        Enable-VMTPM -VMName $vm.Name
    }
    $dvd = Add-VMDvdDrive -VMName $vm.Name -Path (Join-Path $IsoDir $vm.Iso) -Passthru
    Set-VMFirmware -VMName $vm.Name -FirstBootDevice $dvd
    Enable-VMIntegrationService -VMName $vm.Name -Name 'Guest Service Interface'
    Say $true "VM $($vm.Name): $($vm.Cpu) vCPU, $($vm.Mem) GB, $($vm.Disk) GB disk, address $($vm.Ip)"
}
Write-Host 'Done. Install each VM as manual 3.1.5.3 says, then 3.1.5.4 gives the agent its way in.'
