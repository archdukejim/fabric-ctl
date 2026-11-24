# jinja/bind9/config

BIND configuration, rendered by `deploy.py` to `/opt/bind9/config/<name>`
(bind-owned, 0640; `named.conf.keys` 0600), mounted read-only at `/etc/bind`
in the container. A change triggers `rndc reconfig` or a restart.

| File | What |
|---|---|
| `named.conf.j2` | Main file: includes the parts below in order (ACLs, keys, TLS, options, logs, zones); with split DNS (2.1.4.16, 2.1.4.17) the zones and the AD zone in a default view, then a view per subnet with answers of its own (its RPZ, every zone shared with in-view) → `named.conf` |
| `named.conf.acl.j2` | One `acl` per entry of `bind_acls` → `named.conf.acl` |
| `named.conf.keys.j2` | TSIG keys: every key in `tsig_keys`, with DHCP DDNS the `kea-ddns` key, and one `fed-<site>` key per federation link; secrets from fabric's secrets → `named.conf.keys` |
| `named.conf.options.j2` | Listeners (53, and the DoH port behind nginx), no recursion, no DNSSEC validation → `named.conf.options` |
| `named.conf.tls.j2` | The `http dns-over-https` endpoint (`/dns-query`) the plain-HTTP DoH listener uses (nginx terminates TLS), and a `tls my-tls-settings` profile (`/etc/bind9/ssl`) that no listener references → `named.conf.tls` |
| `named.conf.logs.j2` | Logging channels to stderr (the container log, journald) → `named.conf.logs` |
| `named.conf.zones.j2` | Every forward zone in `dns`, the reverse zones, the DHCP subzone; `update-policy` grants per TSIG key; federation: transfers of this site's zone to linked sites (their key), NOTIFY to them, and a secondary copy of each linked site's zone → `named.conf.zones` |
| `rndc.key.j2` | The rndc key (`rndc_secret`) → `rndc.key` |
