# scripts/lab/seeds

The lab seed generator run by `../make_seeds.sh` (manual 3.1.5.3). One line per file:

| File | What |
|---|---|
| `make_seeds.py` | Entry point: routes each VM to its installer's writer |
| `lab_inventory.py` | Reads `../lab_vms.json`; each NIC's MAC |
| `lab_secret.py` | A lab-only password, generated once into an owner-only file |
| `build_iso.py` | xorriso: data ISOs, extract, remaster |
| `ubuntu_seed.py` | Ubuntu Server autoinstall seed and installer copy |
| `router_files.py` | The router's netplan, nftables NAT, forwarding, disabled relay |
| `windows_seed.py` | Windows answer ISO: `autounattend.xml`, `setup.ps1` |
| `proxmox_seed.py` | Proxmox VE ISO prepared with `answer.toml` |
