<#
.SYNOPSIS
  Starts the lab VMs one test campaign needs and stops the lab's others, so the lab never takes more of gaming-23
  than that campaign. Manual 3.1.5.8; decision 2.1.1.64.

.DESCRIPTION
  Run as an administrator or a member of Hyper-V Administrators. It starts and stops only the lab's own VMs
  (g23-vm-*), never another VM on gaming-23. -List shows each campaign's VMs and memory and changes nothing.

.PARAMETER Campaign
  domain-linux, domain-windows, two-sites, dhcp, joined, dot1x, ha, or none (stop the whole lab).
#>
[CmdletBinding()]
param(
    [ValidateSet('domain-linux', 'domain-windows', 'two-sites', 'dhcp', 'joined', 'dot1x', 'ha', 'none')]
    [string]$Campaign,
    [switch]$List
)
$ErrorActionPreference = 'Stop'

$Campaigns = [ordered]@{
    'domain-linux'   = 'g23-vm-rtr-1', 'g23-vm-ub24-1', 'g23-vm-ub26-2', 'g23-vm-pve9-1', 'g23-vm-kub26-1'
    'domain-windows' = 'g23-vm-rtr-1', 'g23-vm-ub24-1', 'g23-vm-ws25-1', 'g23-vm-w11-1'
    'two-sites'      = 'g23-vm-rtr-1', 'g23-vm-ub24-1', 'g23-vm-ub26-1', 'g23-vm-ub26-2'
    'dhcp'           = 'g23-vm-ub24-1', 'g23-vm-rtr-1', 'g23-vm-kub26-1', 'g23-vm-w11-1'
    'joined'         = 'g23-vm-rtr-1', 'g23-vm-ub24-1', 'g23-vm-ub26-2', 'g23-vm-ws25-1'
    'dot1x'          = 'g23-vm-ub24-1', 'g23-vm-rtr-1', 'g23-vm-auth-1', 'g23-vm-ub26-2', 'g23-vm-w11-1'
    'ha'             = 'g23-vm-rtr-1', 'g23-vm-ub24-1', 'g23-vm-ub24-2', 'g23-vm-ub26-1', 'g23-vm-ub26-2'
    'none'           = @()
}

# every campaign includes the router: it is the lab's gateway and NAT (2.1.1.65).
# each VM's memory as new_hyperv_lab.ps1 makes it, so -List shows a campaign's size before its VMs exist
$PlannedGB = @{ 'g23-vm-ub24-1' = 8; 'g23-vm-ub26-1' = 8; 'g23-vm-ub26-2' = 2; 'g23-vm-pve9-1' = 4; 'g23-vm-kub26-1' = 4
                'g23-vm-ws25-1' = 4; 'g23-vm-w11-1' = 4; 'g23-vm-rtr-1' = 2; 'g23-vm-auth-1' = 2; 'g23-vm-ub24-2' = 6 }

$lab = @(Get-VM -Name 'g23-vm-*' -ErrorAction SilentlyContinue)
function GB($names) {
    ($names | ForEach-Object {
        $vm = $lab | Where-Object Name -eq $_
        if ($vm) { $vm.MemoryStartup / 1GB } else { $PlannedGB[$_] }
    } | Measure-Object -Sum).Sum
}

if ($List -or -not $Campaign) {
    foreach ($c in $Campaigns.Keys) {
        $missing = $Campaigns[$c] | Where-Object { $lab.Name -notcontains $_ }
        $note = if ($missing) { "  (not made yet: $($missing -join ', '))" } else { '' }
        Write-Host ("{0,-15} {1,3} GB  {2}{3}" -f $c, (GB $Campaigns[$c]), ($Campaigns[$c] -join ', '), $note)
    }
    return
}

$want = $Campaigns[$Campaign]
$missing = $want | Where-Object { $lab.Name -notcontains $_ }
if ($missing) { throw "campaign $Campaign needs VMs not made yet: $($missing -join ', ') (new_hyperv_lab.ps1 -Only ...)" }

foreach ($vm in $lab | Where-Object { $want -notcontains $_.Name -and $_.State -eq 'Running' }) {
    Stop-VM -Name $vm.Name; Write-Host "  stopped $($vm.Name)"
}
foreach ($vm in $lab | Where-Object { $want -contains $_.Name -and $_.State -ne 'Running' }) {
    Start-VM -Name $vm.Name; Write-Host "  started $($vm.Name)"
}
Write-Host ("campaign {0}: {1} GB of lab VMs running" -f $Campaign, (GB $want))
