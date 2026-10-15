# fabriclib/dns_filter/common

Helpers shared by the DNS filter's files (manual [1.12.2](../../../../docs/volume_1_description_and_architecture/1.12.2-bind-resolver.md#11221-status),
[1.12.3](../../../../docs/volume_1_description_and_architecture/1.12.3-adguard-behind-bind.md#11231-status)).

| File | What |
|---|---|
| `filter_zones.py` | fabric's own zones: forwarded to this site's BIND and never filtered |
| `list_id.py` | A list's id, from its URL (stable when lists are reordered or renamed): its copy's file name |
| `list_zone.py` | The zone name the query log gives a list's block (`<id>.list.rpz`) |
| `list_memory.py` | The memory rule: the ticked lists' estimate and peak against AdGuard's limit |
| `adguard_paths.py` | AdGuard Home's folders and fabric's files beside them (state, catalogue, render digest) |
| `adguard_api.py` | AdGuard Home's API as fabric-agent's account |
| `adguard_password.py` | That account's password, from fabric's secrets |
| `adguard_desired.py` | What AdGuard should hold, from the vars: lists, rules, groups, upstreams |
| `resolver_paths.py` | The resolver's folders and files under the deploy base |
| `dnslog_psql.py` | SQL for the query log through psql in the Postgres container (local socket, SQL on stdin) |
| `resolver_rndc.py` | Run rndc in the resolver's container, with its own control key |
| `rule_names.py` | One allow or block setting checked and normalised; what a name may be (`NAME_RE`) |
| `filter_target.py` | Where a change goes: everyone's settings or one client group's |
| `safe_search.py` | Safe search's table (engines, names, enforced answers) for the zones and the console |
