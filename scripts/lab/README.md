# scripts/lab

The Hyper-V test lab on gaming-23 (manual 3.1.5, decisions 2.1.1.63 to 2.1.1.65). Only `prepare_host.ps1` needs an
elevated PowerShell; the others need Hyper-V Administrators' rights (or run in WSL).

| File | What |
|---|---|
| `lab_vms.json` | The lab's inventory: VMs, installers, addresses, NICs and their switches; read by the scripts below |
| `prepare_host.ps1` | The owner's one admin step: the account into Hyper-V Administrators, the switch `fabric-lab`, host address `10.88.0.1` (no NAT) |
| `new_hyperv_lab.ps1` | Makes the lab's VMs (static MACs), private switches and extra NICs; refuses until `prepare_host.ps1` has run; keeps what exists |
| `make_seeds.sh` | In WSL: writes every VM's unattended-install media into `D:\Hyper-V\fabric-lab\seed` (runs `seeds/make_seeds.py`) |
| `seeds/make_seeds.py` | The generator's entry point: routes each VM to its installer's writer |
| `seeds/lab_inventory.py` | Reads `lab_vms.json`; each NIC's MAC |
| `seeds/lab_secret.py` | Generates a lab-only password once into an owner-only file in `%USERPROFILE%\fabric-lab` |
| `seeds/build_iso.py` | xorriso: data ISOs, extracting from and remastering an ISO |
| `seeds/ubuntu_seed.py` | Ubuntu Server autoinstall: the CIDATA seed and the `autoinstall ds=nocloud` installer copy |
| `seeds/router_files.py` | The router's netplan, nftables NAT, forwarding and disabled DHCP relay |
| `seeds/windows_seed.py` | Windows: `autounattend.xml` and the first sign-in's `setup.ps1` on an answer ISO |
| `seeds/proxmox_seed.py` | Proxmox VE: the ISO prepared with `answer.toml` and a first-boot hook |
| `install_vm.ps1` | Installs one VM unattended (the router first), waits for SSH, ejects the media, takes `clean` |
| `send_key.ps1` | Types a key into a VM's console through Hyper-V's `Msvm_Keyboard` (a Windows ISO's boot prompt) |
| `remove_hyperv_lab.ps1` | Removes exactly what `new_hyperv_lab.ps1` makes (and a `fabric-lab-nat` if one exists), after asking |
| `start_lab.ps1` | Starts one test campaign's VMs (always with the router) and stops the lab's others (manual 3.1.5.8) |
| `install_dev_build.sh` | From Git Bash: a branch's `.deb` and an unattended setup on a lab VM; the first admin's password generated there (manual 3.1.5.9) |
