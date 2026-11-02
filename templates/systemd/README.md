# jinja/systemd

Host systemd units, rendered or copied by `deploy.py` to `/etc/systemd/system/`.

| File | What |
|---|---|
| `wrapper.service.j2` | One unit per installed service (nginx, bind9, stepca, postgres, keycloak, fabric-web, openbao, fluentbit, kea, freeradius, samba, adguard, bind9-resolver): `docker compose up` of `/opt/<folder>/docker-compose.yml`, part of `fabric.target`, waits for the container to be healthy, optional ExecCondition/ExecStartPost (OpenBao unlock) → `<service>.service` |
| `fabric-certs.service`, `fabric-certs.timer` | `fabricctl certs --scheduled` every night (03:30, spread over half an hour): renews the service certificates that are due and records the run (manual 2.1.5.4); copied as is by `deploy/install_timers.py`, enabled |
| (every timer's `.service`) | `ExecCondition`: a run while `fabric-setup.service` is active or `fabric.target` is not is skipped, not failed, since the stack it needs may not be there yet (2.3.1.32 finding 18) |
| `fabric.target` | Groups every fabric unit (`systemctl start/stop/restart fabric.target`), copied as is → `fabric.target` |
| `fabric-agent.service.j2` | The root `fabric-agent` (`lib/agent/server.py`): the web UI's privileged API on a unix socket only; only with `install_webui` → `fabric-agent.service` |
| `fabric-federation.service.j2` | The root `fabric-federation` (`lib/federation/server.py`): the federation endpoint on a unix socket mounted into nginx; only with `federation_endpoint` → `fabric-federation.service` |
| `fabric-db-rotate.service` | Runs `fabricctl vault rotate-db --scheduled` (2.1.7.4) |
| `fabric-db-rotate.timer` | Monthly, the 1st at night, spread over half an hour; a missed run at the next boot |
| `fabric-dns-lists.service`, `fabric-dns-lists.timer` | `fabricctl dns-filter lists --scheduled` every night (04:15, spread over half an hour): the DNS filter's lists fetched, converted, the changed ones reloaded (manual 1.12.2.10); installed only while `dns_filter` is `bind` |
| `fabric-dns-log.service`, `fabric-dns-log.timer` | `fabricctl dns-filter ingest --scheduled` every 5 minutes: the resolver's new log lines read into the query log in Postgres, then what is past its time purged (manual 1.12.2.13); installed only while the resolver and Postgres (`install_keycloak`) are on |
| `fabric-machines.service`, `fabric-machines.timer` | `fabricctl domain sort-machines --scheduled` hourly: Windows machines that joined themselves moved into OU=servers or OU=desktops by their OS, once each (manual 1.6.13.3) |
| `fabric-dhcp-names.service`, `fabric-dhcp-names.timer` | `fabricctl dhcp clean-names --scheduled` hourly (10 minutes after boot, then every hour): DHCP names left behind in `dhcp.<domain>` for addresses named by hand deleted, the cleanup alone, not an apply (manual 1.10.4.20, 2.1.10.22); installed only while Kea (`install_kea`) is on |
| `fabric-plan-watch.service`, `fabric-plan-watch.timer` | `fabricctl ipam watch --scheduled` every 30 s (30 s after boot): when the DC's USN moved and what Kea is rendered from changed, Kea alone re-rendered and restarted (and the firewall when the served subnets changed), never a full apply (manual 1.10.4.26, 2.1.10.24); installed only while Kea (`install_kea`) is on |
| `fabric-host-managed.service`, `fabric-host-managed.timer` | `fabricctl domain host-managed --scheduled` hourly: this fabric host's own management (Kerberos for SSH, the domain's names from fabric's DNS) applied or removed as its account's `fabric-managed` membership says (manual 1.6.11.11) |
| `fabric-grants.service`, `fabric-grants.timer` | `fabricctl domain grant sync --scheduled` every 5 minutes: the grants compiled again for changes made outside fabric (RSAT, `samba-tool`, a join); only the root's writable DC compiles, any other says so and changes nothing (manual 1.6.13.4) |
| `fabric-local-admin.service`, `fabric-local-admin.timer` | `fabricctl local-admin check --scheduled` hourly: this host's local-admin seen used in the journal and wtmp, its password rotated after use (waiting while OpenBao is locked), the domain's SSH switch applied to sshd (manual 1.7.1.4.4, 1.7.1.4.6) |
