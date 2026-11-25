# tests/dns/split

Split DNS by zone (decisions 2.1.4.16, 2.1.4.18; manual [1.4.1.13](../../../docs/volume_1_description_and_architecture/1.4.1-dns-architecture.md#14113-a-zones-networks-and-split-tabs-0102)): pure logic and renders, no container. All run in the `zone` suite.

| File | What |
|---|---|
| `split_answers_test.py` | Split DNS rendered (`dns/split/split_answers`, 2.1.4.18): the networks with answers of their own, the most specific first, and their RPZ data (a split's differences with PTRs, a mapped zone hidden elsewhere, fabric's own names untouched), the rest's; a split's records in no reverse zone; BIND's views (the default view's match with a split only and with a zone mapped, each network's sharing every zone with in-view, everyone's with the rest's RPZ) and nothing changed without them; the resolver's views in order with the rest's RPZ in the groups' and everyone's. In the `zone` suite |
| `zone_networks_test.py` | A zone's networks and splits changed (`set_zone_networks`, `add_split`, `update_split`, `remove_split`, a record in a split's tab), the settings held in memory: each positive, and each refusal saying why and changing nothing. In the `zone` suite |
| `split_needs_filter_test.py` | Split DNS needs the DNS filter (`dns/split/split_needs_filter`, 2.1.4.18): refused with the filter off and a zone mapped or split, naming the zones; a change checked before it is saved. In the `zone` suite |
