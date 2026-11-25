# fabriclib/dns/split

Split DNS by zone (decisions 2.1.4.16, 2.1.4.18; manual [1.4.1.13](../../../../docs/volume_1_description_and_architecture/1.4.1-dns-architecture.md#14113-a-zones-networks-and-split-tabs-0102)): a zone answers every network or some (its `networks`), and a split gives some of its networks a tab of records of their own (its `splits`); both are answered through RPZ in the resolver's views and in BIND's own.

| File | What |
|---|---|
| `zone_networks.py` | The networks a zone answers: its `networks`, or every network |
| `offered_subnets.py` | The networks a zone or split may name: the host's LAN first, then the site's plan's |
| `norm_subnet.py` | A subnet written as its network, or "" |
| `split_checks.py` | The checks the changes share: the DNS filter on, a forward zone, networks as ticked, a split's networks free |
| `split_home.py` | Where a tab's records live: the zone, or one of its splits (refusing a stale one) |
| `own_in_split.py` | Refuses one of fabric's own names in a split (they answer in every tab) |
| `set_zone_networks.py` | A zone's networks set: every network, or some (never the site's own domain, nor a zone holding another) |
| `add_split.py` | A new split: its networks, and a copy of the All networks tab less fabric's own names |
| `update_split.py` | A split's networks changed, its records kept |
| `remove_split.py` | A split removed with its records |
| `split_answers.py` | The networks with answers of their own, the most specific first, and the rest: each one's view and RPZ names and local data (a split's differences with their PTRs; a mapped zone hidden elsewhere) |
| `split_needs_filter.py` | Refuses a mapped or split zone while the DNS filter is off (the AD zone is answered only through the resolver) |
