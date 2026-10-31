<#
.SYNOPSIS
  Installs one lab VM unattended: attaches the media make_seeds.sh wrote, starts it, presses a key for a Windows
  installer, waits until labadmin answers SSH with the lab key, ejects the media and takes the checkpoint `clean`.
  Manual 3.1.5.3; decision 2.1.1.65.

.DESCRIPTION
  Needs Hyper-V Administrators' rights (not an elevated PowerShell). Idempotent: a VM that already answers SSH with
  the lab key is left alone. The router g23-vm-rtr-1 is installed first: every other VM's installer reaches the
  internet through it, so this refuses another VM while the router does not answer and route.
  Media, by installer (lab_vms.json):
    ubuntu-server  first DVD: <seed>\<iso>-autoinstall.iso (GRUB boots `autoinstall ds=nocloud`); second: <seed>\<vm>.iso (CIDATA)
    proxmox        first DVD: <seed>\<vm>.iso (the ISO prepared with answer.toml)
    windows-*      first DVD: the original ISO; second: <seed>\<vm>.iso (autounattend.xml); Enter typed at boot

.PARAMETER Name
  The VM (a name from lab_vms.json).
.PARAMETER TimeoutMinutes
  How long to wait for SSH (default 90; a progress line every minute).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [string]$IsoDir = 'D:\os\AMD64-x86',
    [string]$SeedDir = 'D:\Hyper-V\fabric-lab\seed',
    [string]$Key = (Join-Path $env:USERPROFILE '.ssh\g23_lab'),
    [int]$TimeoutMinutes = 90
)
$ErrorActionPreference = 'Stop'
$Lab = Get-Content -Raw (Join-Path $PSScriptRoot 'lab_vms.json') | ConvertFrom-Json
$Router = 'g23-vm-rtr-1'
$KnownHosts = Join-Path $env:USERPROFILE 'fabric-lab\known_hosts'

$vm = $Lab.vms | Where-Object name -eq $Name
if (-not $vm) { throw "unknown VM $Name; known: $($Lab.vms.name -join ', ')" }
if (-not (Test-Path $Key)) { throw "no lab key at $Key" }
if (-not (Get-VM -Name $Name -ErrorAction SilentlyContinue)) { throw "VM $Name is not made yet: new_hyperv_lab.ps1 -Only $Name" }
New-Item -ItemType Directory -Force -Path (Split-Path $KnownHosts) | Out-Null

function Probe($ip) {
    # while installing: Ubuntu's live installer runs its own sshd at the same address with other host keys, so
    # the wait records no host key (a throwaway known_hosts); only labadmin with the lab key gets in, and that
    # account exists only on the installed system. The installed system's key is recorded once it answers.
    $ErrorActionPreference = 'Continue'
    $tmp = [IO.Path]::GetTempFileName()
    & ssh.exe -i $Key -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no `
              -o "UserKnownHostsFile=$tmp" "labadmin@$ip" hostname 2>$null | Out-Null
    $ok = $LASTEXITCODE -eq 0
    Remove-Item -Force $tmp
    return $ok
}

function Ssh($ip, $cmd) {
    # BatchMode: the key or nothing, never a password prompt; the lab's own known_hosts, so reinstalls never
    # touch the owner's. Windows PowerShell 5.1 turns a native command's stderr into an error under 'Stop', so a
    # refused try would throw here instead of returning nothing
    $ErrorActionPreference = 'Continue'
    $out = & ssh.exe -i $Key -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new `
                     -o "UserKnownHostsFile=$KnownHosts" "labadmin@$ip" $cmd 2>$null
    if ($LASTEXITCODE -eq 0) { return ($out -join "`n") } else { return $null }
}

if (Ssh $vm.ip 'hostname') { Write-Host "$Name already answers SSH at $($vm.ip): left as it is."; return }

if ($Name -ne $Router) {
    $rtr = $Lab.vms | Where-Object name -eq $Router
    $routes = Ssh $rtr.ip 'sudo -n nft list table inet fabric_lab >/dev/null && ping -c1 -W3 1.1.1.1 >/dev/null && echo ok'
    if ($routes -ne 'ok') {
        throw "the router $Router ($($rtr.ip)) does not answer SSH or route to the internet: install_vm.ps1 -Name $Router first (manual 3.1.5.3). Nothing was changed."
    }
}

# the media make_seeds.sh wrote
switch -Wildcard ($vm.installer) {
    'ubuntu-server' { $first = Join-Path $SeedDir (([IO.Path]::GetFileNameWithoutExtension($vm.iso)) + '-autoinstall.iso')
                      $second = Join-Path $SeedDir "$Name.iso" }
    'proxmox'       { $first = Join-Path $SeedDir "$Name.iso"; $second = $null }
    'windows-*'     { $first = Join-Path $IsoDir $vm.iso; $second = Join-Path $SeedDir "$Name.iso" }
    default         { throw "unknown installer $($vm.installer)" }
}
foreach ($p in @($first, $second) | Where-Object { $_ }) {
    if (-not (Test-Path $p)) { throw "missing ${p}: run scripts/lab/make_seeds.sh in WSL first (manual 3.1.5.3). Nothing was changed." }
}

$state = (Get-VM -Name $Name).State
if ($state -ne 'Off') { throw "$Name is $state, not answering SSH: stop it (or restore its checkpoint) before installing it again." }
$ErrorActionPreference = 'Continue'                               # as in Ssh: stderr must not throw
& ssh-keygen.exe -R $vm.ip -f $KnownHosts 2>$null | Out-Null      # a reinstall has new host keys
$ErrorActionPreference = 'Stop'

$dvds = @(Get-VMDvdDrive -VMName $Name)
Set-VMDvdDrive -VMName $Name -ControllerNumber $dvds[0].ControllerNumber -ControllerLocation $dvds[0].ControllerLocation -Path $first
if ($second) {
    if ($dvds.Count -lt 2) { Add-VMDvdDrive -VMName $Name -Path $second }
    else { Set-VMDvdDrive -VMName $Name -ControllerNumber $dvds[1].ControllerNumber -ControllerLocation $dvds[1].ControllerLocation -Path $second }
}
Set-VMFirmware -VMName $Name -FirstBootDevice (Get-VMDvdDrive -VMName $Name | Select-Object -First 1)
Write-Host "${Name}: installing from $first$(if ($second) { " with $second" })"
Start-VM -Name $Name
if ($vm.kind -eq 'windows') {
    & (Join-Path $PSScriptRoot 'send_key.ps1') -Name $Name
    # Setup restarts several times; from the disk each time, or the DVD's prompt times out into a PXE boot.
    # Hyper-V takes the boot order while the VM runs.
    Set-VMFirmware -VMName $Name -FirstBootDevice (Get-VMHardDiskDrive -VMName $Name | Select-Object -First 1)
}

$start = Get-Date
$nextNote = $start.AddMinutes(1)
while (-not (Probe $vm.ip)) {
    if ((Get-Date) -gt $start.AddMinutes($TimeoutMinutes)) {
        throw "$Name did not answer SSH at $($vm.ip) within $TimeoutMinutes minutes; its console shows why. The media stay attached."
    }
    if ((Get-Date) -ge $nextNote) {
        Write-Host ("  {0}: {1:N0} min, state {2}, waiting for SSH at {3}" -f $Name, ((Get-Date) - $start).TotalMinutes, (Get-VM -Name $Name).State, $vm.ip)
        $nextNote = $nextNote.AddMinutes(1)
    }
    Start-Sleep -Seconds 15
}
Write-Host ("$Name answers SSH after {0:N0} min" -f ((Get-Date) - $start).TotalMinutes)
$ErrorActionPreference = 'Continue'
& ssh-keygen.exe -R $vm.ip -f $KnownHosts 2>$null | Out-Null      # any key the installer's sshd left
$ErrorActionPreference = 'Stop'
if (-not (Ssh $vm.ip 'hostname')) { throw "$Name answered once but not with its host key recorded; check its console." }

# eject the media, keep the drives; boot from the disk from now on
Get-VMDvdDrive -VMName $Name | Set-VMDvdDrive -Path $null
Set-VMFirmware -VMName $Name -FirstBootDevice (Get-VMHardDiskDrive -VMName $Name | Select-Object -First 1)
Stop-VM -Name $Name                          # a clean shutdown, so the checkpoint is of a stopped machine
if (-not (Get-VMSnapshot -VMName $Name -Name clean -ErrorAction SilentlyContinue)) {
    Checkpoint-VM -Name $Name -SnapshotName clean
    Write-Host "${Name}: checkpoint clean taken"
}
if ($Name -eq $Router) { Start-VM -Name $Name; Write-Host "$Name started again: the other VMs install through it" }
