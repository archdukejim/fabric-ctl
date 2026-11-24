# fabriclib/dns/split

Split DNS by subnet (decisions 2.1.4.16, 2.1.4.17; manual [1.4.1.12](../../../../docs/volume_1_description_and_architecture/1.4.1-dns-architecture.md#14112-a-records-subnets-0102)): a record names the subnets whose clients get it (the host's LAN by default), or every subnet; it answers those subnets' clients alone, in the resolver's views and in BIND's own.

| File | What |
|---|---|
| `record_subnets.py` | A record's subnets as typed, checked: the host's LAN by default (every subnet with the DNS filter off), each offered, a forward zone, the filter on, no CNAME clash for a subnet in common |
| `offered_subnets.py` | The subnets a record may name: the host's LAN first, then the site's plan's |
| `reach.py` | Whom a record answers: its subnets, or every subnet (no `subnets`) |
| `norm_subnet.py` | A subnet written as its network, or "" |
| `split_answers.py` | The subnets with answers of their own, the most specific first: each one's view and RPZ names, its records and their PTRs as the RPZ's local data |
| `split_needs_filter.py` | Refuses a record for some subnets while the DNS filter is off (the AD zone is answered only through the resolver) |
| `default_records.py` | A zone's records as every subnet gets them: those for some subnets left out |
