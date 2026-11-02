# tests/lab

Suites on real machines, never the house's LAN: the first Hyper-V test machines (manual 2.3.1.9.6) and gaming-23's
lab of campaigns (manual 3.1.5).

| File | What |
|---|---|
| `dhcp.sh` | 0.8's DHCP beyond the host's LAN (manual 1.10.3.8, the gate for 0.8), on the first Hyper-V machines: fabric serving its second interface; real Ubuntu clients get a lease from the pool, fabric's DNS and a route to `host_ip`, their name and PTR, fabric's pages by name; a reservation; a guest subnet DNS only; off and on again from `fabricctl dhcp`; doctor |
| `dhcp_vars.yaml` | fabric's settings for the lab's `dhcp` campaign (manual 3.1.5.10): the root DC on `g23-vm-ub24-1`, Kea on its NIC `lab`, VLAN 10's subnet relayed by the router |
| `dhcp_campaign.sh` | The lab's `dhcp` campaign (manual 3.1.5.10, 1.10.4.39), from Git Bash: the plan from the CLI, ping-check, both clients leased through the router's relay with their names and PTRs, a reservation, a name set by hand, an option, a scan, the plan poll, the CLI's refusals, then the console checks |
| `dhcp_console.py` | The campaign's console checks, as root on the fabric VM: the Directory Administrator's VLAN, Sync now, scan and option through Networks and DHCP options with Apply; a person with `dhcp:write` and no networks grant refused at hold; an auditor shown no form |
| `console_session.py` | A person's console session driven like a browser (Keycloak's sign-in, CSRF, Apply and its Review), for `dhcp_console.py` |
| `joined_campaign.sh` | The lab's `joined` campaign (manual 3.1.5.11, decision 2.1.1.48), from Git Bash: the fabric host's own join, a Linux member (ub26-2) and a Windows member (ws25-1) checked after each of fabric's own changes: an upgrade from the floor, every image updated and rolled back, a restart and a reboot, a restore from an export, a move to a new address, the host renamed. Written 2026-10-31, not run yet |
| `joined_vars.yaml` | fabric's settings for the `joined` campaign: the dhcp campaign's, so Keycloak, the console and Kea's images are updated and rolled back with the rest |
