# tests/dns/split

Split DNS by subnet (decisions 2.1.4.16, 2.1.4.17; manual [1.4.1.12](../../../docs/volume_1_description_and_architecture/1.4.1-dns-architecture.md#14112-a-records-subnets-0102)): pure logic and renders, no container. All run in the `zone` suite.

| File | What |
|---|---|
| `split_answers_test.py` | Split DNS rendered (`dns/split`, 2.1.4.17): the subnets with answers of their own, the most specific first, and their RPZ data with each A record's PTR, kept out of the reverse zones; the zone without them; BIND's views (the default view first: signed requests, this host, fabric's containers; each subnet's sharing every zone with in-view and answering from its RPZ) and nothing changed without them; the resolver's views in order (a group's clients in such a subnet, the groups, the subnets, everyone). In the `zone` suite |
| `record_subnets_test.py` | A record's subnets as typed (`dns/split/record_subnets`, 2.1.4.17): the host's LAN by default, every subnet a choice (the default with the filter off), several kept sorted, an edit keeping its own; refused: none, every subnet beside a subnet, not a subnet, one not offered, a reverse zone, the DNS filter off, a CNAME clash for a subnet in common. The subnets offered. In the `zone` suite |
| `split_needs_filter_test.py` | Split DNS needs the DNS filter (`dns/split/split_needs_filter`, 2.1.4.17): refused with the filter off and a record for some subnets, naming the records; a change checked before it is saved. In the `zone` suite |
