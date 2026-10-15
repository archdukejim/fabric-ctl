# fabriclib/setup/advanced

Setup's menu of every setting (manual 1.2.9.11.3, decision 2.1.2.19): from the start's [A]dvanced or the plan's [M]enu.
Each item asks with guided mode's question and checks.

| File | What |
|---|---|
| `setup_menu.py` | The menu: its three parts, a number asks one item, [P]roceed once the required items have values, [Q]uit |
| `menu_items.py` | The items with their values as shown now, and what each asks |
| `ask_network.py` | The network item: this host's address, the subnet and the gateway, checked together |
| `ask_first_admin_item.py` | The first admin item: the user name and, when setup creates them, the password |
| `ask_ca_lifetime.py` | The CA root's lifetime in years; refused once the CA exists |
| `ask_part.py` | An optional part on or off (DHCP, 802.1X, log forwarding, the DNS filter), asking what turning it on needs |
| `ask_dhcp_settings.py` | What turning DHCP on needs: interface, subnet, pool and router, checked as `fabricctl dhcp on` does |
| `ask_log_target.py` | Where log forwarding sends the logs: a syslog server or an Elasticsearch URL |
| `ask_memory.py` | How many GB fabric may use; refused when the memory plan does not fit |
| `ask_host_change.py` | A recommended host change on or off, with what declining means and what needs it |
| `common/` | Helpers shared by the items: the yes/no question, the optional parts |
