# fabriclib/dns/split

Split DNS (decision 2.1.4.16, manual [1.4.1.11](../../../../docs/volume_1_description_and_architecture/1.4.1-dns-architecture.md#14111-a-vlans-own-answers-split-horizon-dns-0100)): a record given to one VLAN of the site answers that VLAN's clients alone, in the resolver's views and in BIND's own.

| File | What |
|---|---|
| `record_vlan.py` | A record's VLAN as typed, checked: a VLAN of the site's plan, a forward zone, no CNAME clash for that VLAN |
| `split_answers.py` | The VLANs with answers of their own: each one's subnets, its view and RPZ names, its records as the RPZ's local data |
| `default_records.py` | A zone's records as everyone gets them: a VLAN's own left out |
