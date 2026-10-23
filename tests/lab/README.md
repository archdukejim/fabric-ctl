# tests/lab

Suites on real machines, never the house's LAN: the first Hyper-V test machines (manual 2.3.1.9.6) and gaming-23's
lab of campaigns (manual 3.1.5).

| File | What |
|---|---|
| `dhcp.sh` | 0.8's DHCP beyond the host's LAN (manual 1.10.3.8, the gate for 0.8), on the first Hyper-V machines: fabric serving its second interface; real Ubuntu clients get a lease from the pool, fabric's DNS and a route to `host_ip`, their name and PTR, fabric's pages by name; a reservation; a guest subnet DNS only; off and on again from `fabricctl dhcp`; doctor |
| `dhcp_vars.yaml` | fabric's settings for the lab's `dhcp` campaign (manual 3.1.5.10): the root DC on `g23-vm-ub24-1`, Kea on its NIC `lab`, VLAN 10's subnet relayed by the router |
