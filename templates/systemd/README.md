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
| `fabric-machines.service`, `fabric-machines.timer` | `fabricctl domain sort-machines --scheduled` hourly: Windows machines that joined themselves moved into OU=servers or OU=desktops by their OS, once each (manual 1.6.13.3) |
| `fabric-host-managed.service`, `fabric-host-managed.timer` | `fabricctl domain host-managed --scheduled` hourly: this fabric host's own management (Kerberos for SSH, the domain's names from fabric's DNS) applied or removed as its account's `fabric-managed` membership says (manual 1.6.11.11) |
| `fabric-grants.service`, `fabric-grants.timer` | `fabricctl domain grant sync --scheduled` every 5 minutes: the grants compiled again for changes made outside fabric (RSAT, `samba-tool`, a join); only the root's writable DC compiles, any other says so and changes nothing (manual 1.6.13.4) |
