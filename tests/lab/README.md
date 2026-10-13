# tests/lab

Suites on the lab's virtual machines (Hyper-V, manual 2.3.1.9.6; for 802.1X the Incus cluster, 2.3.11.4): real machines on an isolated switch, no router, never the house's LAN.

| File | What |
|---|---|
| `dhcp.sh` | DHCP beyond the host's LAN (manual 1.10.3.8, the gate for 0.8): fabric serving its second interface; real Ubuntu clients get a lease from the pool, fabric's DNS and a route to `host_ip`, their name and PTR, fabric's pages by name; a reservation; a guest subnet DNS only; off and on again from `fabricctl dhcp`; doctor |
| `dot1x.sh` | 802.1X end to end (manual 1.11.1.5, 2.1.11.7; the Incus lab of 2.3.11.4): a hostapd authenticator and an Ubuntu supplicant against fabric's FreeRADIUS: EAP-TLS on its role's VLAN (and a lease there), accounting as a session, CoA refused for a generic authenticator, a disabled device, EAP-TTLS with a right and a wrong password, a port with no supplicant, MAB by permission; W5 from the decisions. Written, not run |
| `dot1x_fixture.py` | `dot1x.sh`'s fixture on the fabric host: lab roles, devices and a device certificate made with fabric's own functions; removed again |
| `windows_checks.ps1` | The Windows checks W1-W4 and W6-W9 of 2.3.6.1.19, on a Windows member as Administrator: PASS / FAIL per check with what it saw. Written, not run |
