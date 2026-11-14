# fabriclib/security

| File | What |
|---|---|
| `apply_docker_firewall.py` | Rebuild the `DOCKER-USER` chain so a published port is reached only from the networks the site's access rules allow its service (and `security.firewall_allow`); RADIUS clients only to UDP 1812/1813; IPv6 none. Run at setup and at boot by `fabric-firewall.service`. |
| `apply_ping_rules.py` | Ping answered only from the networks the access rules allow `ping`: ufw's `before.rules` echo-request line replaced by fabric's block, IPv6's left out, the files kept for uninstall. |
| `refresh_firewall.py` | Setup's firewall step after a DHCP change from the console or `fabricctl dhcp`, the `ports` group approved by the change (manual 1.10.3.5) |
| `firewall_rules.py` | The networks and interfaces the host firewall opens (SSH, NTP, DHCP), for the setup step and its consent question |
| `ufw_rule.py` | The words of one ufw rule fabric adds (SSH, NTP, DHCP), and the files recording what it opened |
| `hardened_daemon_settings.py` | Docker's `daemon.json` now and with fabric's hardening merged in |
| `ssh_ports.py` | The ports this host's SSH daemon listens on (`sshd -T`; 22 without sshd), which the firewall opens |
| `signin_layers.py` | The sign-in layers (second factors, the web console's client certificate), their order, and the rows status shows |
| `set_signin_layer.py` | Change one layer in vars.yaml: raises, or a lowering only when asked for; lowered layers recorded; audited |
| `apply_signin.py` | Make a sign-in change take effect: the apply, then Keycloak's configuration |
| `run_security_command.py` | `fabricctl security`: status, raise, lower (the layer's name typed back), Kerberos on or off |
| `check_signin_lowering.py` | Setup never lowers a sign-in layer of an existing install (a --file that would is refused) |
| `ufw_active.py` | Whether ufw is on: as before fabric first turned it on (recorded), or now — for the firewall question and a decline with ufw on (2.1.2.12) |
| `host_own_rules.py` | The host's own ufw rules: what ufw lists as added, less fabric's (records and planned) |
