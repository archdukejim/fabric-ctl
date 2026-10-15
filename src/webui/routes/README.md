# src/webui/routes

Every page (GET) and action (POST) behind the gates; each takes the request handler for send / redirect / deny.

| File | What |
|---|---|
| `bind9_page.py` | Render the BIND9 tab: forward zone records, generated reverse zones or TSIG keys. |
| `directory_page.py` | Render the Directory tab: devices, one device, roles, one role, or people. |
| `directory_post.py` | Devices, device roles and people: each form maps to one fabric-agent call. |
| `get_page.py` | Route a signed-in GET to its page. |
| `openbao_page.py` | Render the OpenBao tab: status, unlock methods and their add/rotate/remove forms, secrets, disk encryption. |
| `post_action.py` | Route a signed-in, CSRF-checked POST to its action. |
| `dns_filter_page.py` | The DNS filter tab: overview, lists, rules, the query log (dns:querylog), settings |
| `dns_filter_post.py` | The DNS filter tab's changes: lists, rules (also Allow / Block from the query log), upstreams, fetch now |
| `networks_scan_page.py` | The scan page (`/networks/scan`): the subnets this site's DHCP serves, to scan one (its own page, for the Networks tab) |
| `networks_scan_post.py` | The scan and "make it a reservation?": scan a subnet and show what answered; record an address it found; ask a site below to scan; set whether a site below may scan locally |
| `networks_sync_post.py` | Sync now: the plan poll at once and BIND's records, back to the Networks tab with what it did |
| `kea_post.py` | The Kea tab's changes: reservations, subnets (name, VLAN, notes, pools), options, client classes |
| `options_page.py` | The DHCP options page (`/kea/options`): option sets, presets, a target's effective options with their sources |
| `options_post.py` | The DHCP options page's changes: options, classes, definitions, netboot, who edits the organisation's |
| `radius_post.py` | RADIUS clients: add, new shared secret, remove — saved and applied at once; a secret is shown once on its own page, never in a URL. |
| `saved_and_applied.py` | Run a change that fabric-agent saves and applies at once, and go back to its tab with the outcome. |
| `stepca_page.py` | Render the Step-CA tab for one sub-view, with the CA summary, linkable devices and the issued list where needed. |
| `stepca_post.py` | Manual PKI: each Step-CA form maps to one fabric-agent operation. |
| `tsig_post.py` | TSIG keys: create, rotate, delete (Apply publishes them to BIND9). |
| `vault_post.py` | Change the vault's unlock methods: rotate the key, test or remove a method, or add a USB stick, security key or KMIP HSM — each one fabric-agent call after a recent sign-in and the host name typed as confirmation. |
| `zone_post.py` | DNS records: add one to a zone, or delete one (published by the next Apply). |
| `landing_post.py` | The landing page's links: link a record of the site's zone from it, or stop (published by the next Apply). |
| `zones_post.py` | DNS zones: add one, or remove one with its records (served or dropped in seconds, no Apply). |
| `__init__.py` | Empty; makes it a package |
| `security_post.py` | The Security page's changes: a recent sign-in, the admin's own certificate before turning it on, then the agent |
| `overview_post.py` | The Overview's jobs: Run doctor, and update or roll back one service's image; then the job's page |
| `networks_page.py` | The Networks tab: a site's VLANs and subnet maps, one subnet's address table, a search, the CSV export |
| `networks_post.py` | The Networks tab's changes: the site's number, VLANs, subnets, ranges, addresses; back to the tab with the outcome |
| `settings_page.py` | The setup wizard's pages: a step filled in with today's settings; the settings file's download |
| `settings_post.py` | The setup wizard's forms: Back and Next, the plan (typed or imported), Apply after a recent sign-in, Dismiss |
| `finish_setting_up.py` | The wizard on the Overview: Finish setting up until it is finished, and the first Overview of a sign-in opening it |
