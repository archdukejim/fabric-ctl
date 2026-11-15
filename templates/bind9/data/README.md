# jinja/bind9/data

Zone file templates, rendered by `deploy.py` once per zone into
`/opt/bind9/data/` (mounted at `/var/lib/bind`). A zone whose records changed
(serial ignored) is swapped under the running BIND (`reload_zone`: freeze,
swap, thaw, checked by serial).

| File | What |
|---|---|
| `zone.j2` | A forward zone from `dns` in vars.yaml (SOA, NS, records; NS + glue for federation sites below this domain) → `db.<zone>` |
| `split.rpz.j2` | A VLAN's own answers (2.1.4.16): its records as RPZ local data, answered in its view → `db.split-<vlan>.rpz` |
| `reverse-zone.j2` | A reverse zone with PTRs derived from the forward A records (`fabriclib/dns/reverse_zones.py`) → `db.<c>.<b>.<a>.in-addr.arpa` |
