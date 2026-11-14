# tests/dns/split

Split DNS (decision 2.1.4.16, manual [1.4.1.11](../../../docs/volume_1_description_and_architecture/1.4.1-dns-architecture.md#14111-a-vlans-own-answers-split-horizon-dns-0100)): pure logic and renders, no container. Both run in the `zone` suite.

| File | What |
|---|---|
| `split_answers_test.py` | Split DNS rendered (`dns/split`, 2.1.4.16): the VLANs with answers of their own and their RPZ data, the zone without them, BIND's views (the default view first: signed requests, this host, fabric's containers; each VLAN's sharing every zone with in-view and answering from its RPZ) and nothing changed without them, the resolver's views in order (a group's clients in such a VLAN, the groups, the VLANs, everyone). In the `zone` suite |
| `record_vlan_test.py` | A record's VLAN as typed (`dns/split/record_vlan`, 2.1.4.16): a VLAN of the plan kept as its reference; refused: not a VLAN, one the plan has not, a reverse zone, a CNAME clash for that VLAN. In the `zone` suite |
