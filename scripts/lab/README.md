# scripts/lab

The Hyper-V test lab on gaming-23 (manual 3.1.5, decision 2.1.1.63). Both run in an elevated PowerShell on gaming-23.

| Script | What |
|---|---|
| `new_hyperv_lab.ps1` | Makes the lab's internal switch, its NAT and host address, and its seven VMs; keeps what exists |
| `remove_hyperv_lab.ps1` | Removes exactly what `new_hyperv_lab.ps1` makes, after asking |
