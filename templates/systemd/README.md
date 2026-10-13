# jinja/systemd

Host systemd units, rendered or copied by `deploy.py` to `/etc/systemd/system/`.

| File | What |
|---|---|
| `wrapper.service.j2` | One unit per installed service (nginx, bind9, stepca, postgres, keycloak, fabric-web, openbao, fluentbit, kea, freeradius, samba, adguard, bind9-resolver): `docker compose up` of `/opt/<folder>/docker-compose.yml`, part of `fabric.target`, waits for the container to be healthy, optional ExecCondition/ExecStartPost (OpenBao unlock) → `<service>.service` |
| `fabric-certs.service`, `fabric-certs.timer` | `fabricctl certs --scheduled` every night (03:30, spread over half an hour): renews the service certificates that are due and records the run (manual 2.1.5.4); copied as is by `deploy/install_timers.py`, enabled |
| `fabric.target` | Groups every fabric unit (`systemctl start/stop/restart fabric.target`), copied as is → `fabric.target` |
| `fabric-agent.service.j2` | The root `fabric-agent` (`lib/agent/server.py`): the web UI's privileged API on a unix socket only; only with `install_webui` → `fabric-agent.service` |
| `fabric-federation.service.j2` | The root `fabric-federation` (`lib/federation/server.py`): the federation endpoint on a unix socket mounted into nginx; only with `federation_endpoint` → `fabric-federation.service` |
| `fabric-db-rotate.service` | Runs `fabricctl vault rotate-db --scheduled` (2.1.7.4) |
| `fabric-db-rotate.timer` | Monthly, the 1st at night, spread over half an hour; a missed run at the next boot |
| `fabric-dns-lists.service`, `fabric-dns-lists.timer` | `fabricctl dns-filter lists --scheduled` every night (04:15, spread over half an hour): the DNS filter's lists fetched, converted, the changed ones reloaded (manual 1.12.2.10); installed only while `dns_filter` is `bind` |
| `fabric-dns-log.service`, `fabric-dns-log.timer` | `fabricctl dns-filter ingest --scheduled` every 5 minutes: the resolver's new log lines read into the query log in Postgres, then what is past its time purged (manual 1.12.2.13); installed only while the resolver and Postgres (`install_keycloak`) are on |
| `fabric-machines.service`, `fabric-machines.timer` | `fabricctl domain sort-machines --scheduled` hourly: Windows machines that joined themselves moved into their site's OU=windows, once each (manual 1.6.11.5) |
| `fabric-dhcp-names.service`, `fabric-dhcp-names.timer` | `fabricctl dhcp clean-names --scheduled` hourly (10 minutes after boot, then every hour): DHCP names left behind in `dhcp.<domain>` for addresses named by hand deleted, the cleanup alone, not an apply (manual 1.10.4.20, 2.1.10.22); installed only while Kea (`install_kea`) is on |
| `fabric-plan-watch.service`, `fabric-plan-watch.timer` | `fabricctl ipam watch --scheduled` every 30 s (30 s after boot): when the DC's USN moved and what Kea is rendered from changed, Kea alone re-rendered and restarted (and the firewall when the served subnets changed), never a full apply (manual 1.10.4.26, 2.1.10.24); installed only while Kea (`install_kea`) is on |
