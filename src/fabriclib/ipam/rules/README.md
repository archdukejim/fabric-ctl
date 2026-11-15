# fabriclib/ipam/rules

A site's access table (manual 1.10.4.48.10, decision 2.1.10.63): for each of its VLANs, the other sites and outside,
each of fabric's services allowed or not. One answer (`service_sources`) that every layer of enforcement is built
from. Pure but for the changes, which go through `ipam/common/edit_plan` as every plan change does.

| File | What |
|---|---|
| `constants.py` | The services with their ports, the networks other than VLANs, the actions, what the host's VLAN must keep |
| `rule_networks.py` | The site's networks: each VLAN's subnets, the host's VLAN, the site's, the other sites', every address |
| `network_in.py` | Whether a network lies inside an allow list (`any`'s list is 0.0.0.0/0 less the denied) |
| `access_table.py` | The table a site is enforced by: its defaults, with the rows kept or an upgraded site's seed |
| `service_sources.py` | The networks each service answers under the table |
| `access_sources.py` | That answer as the settings hold it (an apply's), else from the plan last read |
| `access_denied.py` | For each service, the site's networks it does not answer (BIND's and the resolver's `blackhole`) |
| `access_web_allow.py` | The addresses nginx answers: the table's `web`, this host, its containers, `firewall_allow`, the peers |
| `dhcp_allowed.py` | The DHCP subnets Kea serves under the table (a VLAN not allowed dhcp is left out, so Kea stays silent) |
| `seed_site_access.py` | An upgraded site's table written once, at its first apply |
| `check_cut_off.py` | Whether a table leaves the host's VLAN without SSH or the console |
| `access_warnings.py` | What a table allows that is likely a mistake |
| `change_access_rows.py` | One network's services changed: checked, then the rows to keep |
| `set_access.py` | That change written through edit_plan, audited |
| `show_access.py` | The table as `fabricctl ipam access` prints it |
| `access_view.py` | The table as the console's Access page shows it, a tab per network |
