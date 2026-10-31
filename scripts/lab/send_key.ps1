<#
.SYNOPSIS
  Types a key into a Hyper-V VM's console through its Msvm_Keyboard (root\virtualization\v2), as a person at the
  console would. Manual 3.1.5.3: answers a Windows ISO's "Press any key to boot from CD or DVD".

.DESCRIPTION
  Needs Hyper-V Administrators' rights. Sends the key -Times times, -Every seconds apart (20 s by default), so
  one lands inside the prompt's few seconds. Returns quietly; throws if the VM or its keyboard is not found.

.PARAMETER Name
  The VM.
.PARAMETER KeyCode
  A Windows virtual-key code (default 0x0D, Enter).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [int]$KeyCode = 0x0D,
    # 20 s of presses: gaming-23's first lab run showed 8 presses over 12 s miss the prompt (it falls into PXE)
    [int]$Times = 40,
    [double]$Every = 0.5
)
$ErrorActionPreference = 'Stop'
$ns = 'root\virtualization\v2'
$vm = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$($Name -replace "'", "''")'"
if (-not $vm) { throw "no VM named $Name" }
$kb = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_Keyboard
if (-not $kb) { throw "$Name has no keyboard to type on (is it running?)" }
for ($i = 0; $i -lt $Times; $i++) {
    $r = Invoke-CimMethod -InputObject $kb -MethodName TypeKey -Arguments @{ keyCode = [uint32]$KeyCode }
    if ($r.ReturnValue -ne 0) { Write-Verbose "TypeKey returned $($r.ReturnValue)" }
    Start-Sleep -Milliseconds ([int]($Every * 1000))
}
