# jinja/systemd

Host systemd units, rendered or copied by `deploy.py` to `/etc/systemd/system/`.

| File | What |
|---|---|
| `wrapper.service.j2` | One unit per installed service (nginx, bind9, stepca, postgres, keycloak, fabric-web, openbao, fluentbit, kea, freeradius, samba, adguard, bind9-resolver): `docker compose up` of `/opt/<folder>/docker-compose.yml`, part of `fabric.target`, waits for the container to be healthy, optional ExecCondition/ExecStartPost (OpenBao unlock) → `<service>.service` |
| `fabric-certs.service`, `fabric-certs.timer` | `fabricctl certs --scheduled` every night (03:30, spread over half an hour): renews the service certificates that are due and records the run (manual 2.1.5.4); copied as is by `deploy/install_timers.py`, enabled |
| `fabric.target` | Groups every fabric unit (`systemctl start/stop/restart fabric.target`), copied as is → `fabric.target` |
| `fabric-agent.service.j2` | The root `fabric-agent` (`lib/agent/server.py`): the web UI's privileged API on a unix socket only; only with `install_webui` → `fabric-agent.service` |
| `fabric-federation.service.j2` | The root `fabric-federation` (`lib/federation/server.py`): the federation endpoint on a unix socket mounted into nginx; only with `federation_endpoint` → `fabric-federation.service` |
| `fabric-scep-hook.service.j2` | The root `fabric-scep-hook` (`lib/scephook/server.py`): Step-CA's SCEP webhooks on a unix socket mounted into nginx (manual 1.5.3.3); only with the web console (`install_webui`) → `fabric-scep-hook.service` |
| `fabric-db-rotate.service` | Runs `fabricctl vault rotate-db --scheduled` (2.1.7.4) |
| `fabric-db-rotate.timer` | Monthly, the 1st at night, spread over half an hour; a missed run at the next boot |
| `fabric-dns-lists.service`, `fabric-dns-lists.timer` | `fabricctl dns-filter lists --scheduled` every night (04:15, spread over half an hour): the DNS filter's lists fetched, converted, the changed ones reloaded (manual 1.12.2.10); installed only while `dns_filter` is `bind` |
| `fabric-dns-log.service`, `fabric-dns-log.timer` | `fabricctl dns-filter ingest --scheduled` every 5 minutes: the resolver's new log lines read into the query log in Postgres, then what is past its time purged (manual 1.12.2.13); installed only while the resolver and Postgres (`install_keycloak`) are on |
| `fabric-machines.service`, `fabric-machines.timer` | `fabricctl domain sort-machines --scheduled` hourly: Windows machines that joined themselves moved into their site's OU=windows, once each (manual 1.6.11.5) |
| `fabric-dhcp-names.service`, `fabric-dhcp-names.timer` | `fabricctl dhcp clean-names --scheduled` hourly (10 minutes after boot, then every hour): DHCP names left behind in `dhcp.<domain>` for addresses named by hand deleted, the cleanup alone, not an apply (manual 1.10.4.20, 2.1.10.22); installed only while Kea (`install_kea`) is on |
| `fabric-plan-watch.service`, `fabric-plan-watch.timer` | `fabricctl ipam watch --scheduled` every 30 s (30 s after boot): when the DC's USN moved and what Kea is rendered from changed, Kea alone re-rendered and restarted (and the firewall when the served subnets changed), never a full apply (manual 1.10.4.26, 2.1.10.24); installed only while Kea (`install_kea`) is on |
| `fabric-host-managed.service`, `fabric-host-managed.timer` | `fabricctl domain host-managed --scheduled` hourly: this fabric host's own management (Kerberos for SSH, the domain's names from fabric's DNS) applied or removed as its account's `<site>-fabric-machines` membership says (manual 1.6.11.11) |
| `fabric-rodc-cache.service`, `fabric-rodc-cache.timer` | `fabricctl domain rodc-cache --scheduled` hourly, only at a site whose DC is read-only: the site's people and machines kept in `<site>-rodc-cache` and cached at the read-only DC (manual 1.6.11.14, 2.1.6.55) |
| `fabric-ssh-hosts.service`, `fabric-ssh-hosts.timer` | `fabricctl domain ssh-hosts --scheduled` hourly (15 minutes after boot): while SSH certificates are on, the managed machines' published host keys signed by OpenBao's host CA (30 days, renewed with 10 left) and written back to their accounts, and this host's own certificate and its trust of the host CA applied; while off, this host's part removed (manual 1.6.11.9.8, 2.1.7.13) |
