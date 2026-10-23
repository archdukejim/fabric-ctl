# fabriclib/ipam

The address manager (manual 1.10.4): every site's VLANs, subnets, ranges and addresses, one plan kept in the domain
(its `OU=networks`, each entry named with its site; the site's record and the domain's option set in
`CN=fabric,CN=System`, 1.10.4.32, 1.10.4.33). Ported onto 0.8.0's directory area by area (1.10.4.41). The rules
are pure functions checked before anything is written.

| File | What |
|---|---|
| `check_vlan.py` | A VLAN checked: ID 1-4094 and name, each unique in the site; purpose, notes, access |
| `check_subnet.py` | A subnet checked: an IPv4 network, its gateway, relay, no overlap in the domain without a reason |
| `check_range.py` | A range checked: kind, inside its subnet, no overlap; a dhcp range holds only reservations |
| `check_address.py` | An address checked: one claim each, only reservations in a dhcp range, MAC and DNS name rules; warnings |
| `check_block.py` | A site's number checked: 1-255, no other site's |
| `suggestions.py` | What fabric suggests: a VLAN's subnet, the split of a /24, a site's number |
| [common/](common/) | Helpers the address manager's commands share |
