# fabriclib/dns_filter

The DNS filter: a BIND resolver answering clients (its views, the owner's rules, safe search; design
[1.12.2](../../../docs/volume_1_description_and_architecture/1.12.2-bind-resolver.md#11221-status)), and AdGuard Home
behind it matching the lists (design
[1.12.3](../../../docs/volume_1_description_and_architecture/1.12.3-adguard-behind-bind.md#11231-status), decision
2.1.12.6).

| File | What |
|---|---|
| `update_lists.py` | fabric's copies of the lists (the site's and the catalogue's) for AdGuard; a truncated or failed download keeps the last copy; each list's state |
| `deploy_resolver.py` | Deploy step: the resolver's folders, configuration (each view forwarding to AdGuard, a group's over DoT with its ClientID), the rules zones (fabric's, the owner's, each group's, safe search), control key |
| `deploy_adguard.py` | Deploy step: AdGuard Home's file rendered; what its API sets made through it, a restart only for the rest |
| `sync_adguard.py` | Make the running AdGuard match the vars through its API: lists, rules, groups as clients, upstreams |
| `apply_dns_filter.py` | A console change made in seconds: the resolver reloaded, AdGuard synced; nothing restarts |
| `resolver_views.py` | Each group's view: its match-clients (the most specific address wins), rules zone and safe search |
| `flush_published_names.py` | The filtering resolver forgets the names fabric just published (`rndc flushname`/`flushtree`, 2.1.10.46); a failure said, never raised |
| `check_filter_settings.py` | Refuse resolver settings that cannot work: lists, allows and blocks, upstreams, safe search, groups |
| `check_filter_groups.py` | Refuse client groups that cannot work: names, clients, safe search, rules; groups have no lists |
| `expand_group_clients.py` | A group's `dhcp:`, `device:` and `vlan:` clients turned into addresses from Kea's settings on every apply (manual 1.10.3.7) |
| `ensure_dnslog_db.py` | The query log's database in fabric's Postgres: its own role and database, its tables |
| `ingest_dns_log.py` | Read the resolver's new log lines into the query log, mark rewrites and AdGuard's blocks, recompute the statistics, purge |
| `read_query_log.py` | Search the query log (client, name, blocked only), read up to the moment first |
| `dns_filter_stats.py` | The statistics: the last 24 hours, the last 7 days, per list and rules zone, the most blocked names |
| `filter_overview.py` | The DNS filter for the web console: every list as a checkbox with its copy's state and memory, the rules, the groups, safe search and the sites it covers, the statistics |
| `set_filter_list.py` | Tick, untick or add a list (vars.yaml); a tick past AdGuard's memory limit is refused |
| `remove_filter_list.py` | Take a list off the site (vars.yaml) |
| `add_filter_rule.py` | Allow or block a name and every name below it, for everyone or a group; a name in the other rule moves |
| `remove_filter_rule.py` | Take a name out of the allows or blocks, everyone's or a group's |
| `set_filter_group.py` | Add a client group, or change its addresses and subnets |
| `remove_filter_group.py` | Remove a client group: its clients are answered as everyone |
| `set_safe_search.py` | Strict safe search on or off, YouTube strict or moderate, for everyone or a group |
| `set_filter_upstreams.py` | AdGuard's DoT upstreams (address and certificate name pairs), at least one |
| `fetch_catalogue.py` | AdGuard's list catalogue, read from its registry and kept for the web console |
| `refresh_lists.py` | The lists job: fetch the lists and the catalogue, sync AdGuard, have it reread what changed |
| `start_list_fetch.py` | Start the lists job now (fabric-agent has no internet) |
| `show_filter_status.py` | Each list's state, the resolver's and AdGuard's, for `fabricctl dns-filter status` |
| `run_dns_filter_command.py` | `fabricctl dns-filter lists \| status \| apply \| log \| stats \| ingest` |
| `resolver_tls_pending.py` | Whether the DNS name's certificate arrived after the resolver was rendered (setup renders once more) |
| `common/` | Helpers shared by these files |
