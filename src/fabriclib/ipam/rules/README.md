# fabriclib/ipam/rules

A site's access rules (manual 1.10.4.48, decisions 2.1.10.53 to 2.1.10.60): which of its networks reach which of
fabric's services. Written like firewall rules, first match wins, `any deny` implied last; one answer
(`service_sources`) that every layer of enforcement is built from. Pure but for the changes, which go through
`ipam/common/edit_plan` as every plan change does.

| File | What |
|---|---|
| `constants.py` | The services with their ports, the actions, a fresh site's rule, what the host's VLAN must keep |
| `rule_networks.py` | The networks a rule can name: each VLAN's subnets, the host's VLAN, every network the site knows |
| `network_names.py` | The words that name one network in a rule's source |
| `decide_rule.py` | What the rules decide for one network and one service: the first match, or the implied deny |
| `service_sources.py` | The networks each service answers under the site's rules |
| `access_sources.py` | That answer as the settings hold it (an apply's), else from the plan last read |
| `access_denied.py` | For each service, the site's networks it does not answer (BIND's and the resolver's `blackhole`) |
| `access_web_allow.py` | The addresses nginx answers: the rules' `web`, this host, its containers, `firewall_allow`, the federation's peers |
| `dhcp_allowed.py` | The DHCP subnets Kea serves under the rules (a VLAN not allowed dhcp is left out, so Kea stays silent) |
| `effective_rules.py` | The rules a site is enforced by: those kept, or those it would be given |
| `seed_rules.py` | The rules a site has before any are kept: a fresh site's one, an upgraded site's that keep what it reached |
| `seed_site_rules.py` | An upgraded site's rules written once, at its first apply |
| `check_rule.py` | One rule as typed, checked |
| `rule_number.py` | A rule's number as typed, checked against the list |
| `check_cut_off.py` | Whether a list leaves the host's VLAN without SSH or the console |
| `rule_warnings.py` | What a list allows that is likely a mistake |
| `change_rules.py` | One change to the rules: checked, then the whole list written through edit_plan |
| `add_rule.py`, `remove_rule.py`, `move_rule.py` | A rule added, removed, moved |
| `show_rules.py` | The rules as `fabricctl ipam rule` prints them |
| `rules_view.py` | The rules as the console's Access rules page shows them |
