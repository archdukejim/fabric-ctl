# src/webui/devpreview

The dev preview (`devserver.py`): the real pages over in-memory sample data; no sign-in, nothing saved. Never part of the production server.

| File | What |
|---|---|
| `dev_get_page.py` | Render the real pages (src/webui/views) with sample or in-memory data: /, /bind9, /stepca, /openbao, /directory, /kea, /dns-filter, /freeradius, /audit, /static/app.css, and /preview/denied (what a refused sign-in looks like). No sign-in, no client certificate, no fabric-agent. |
| `dev_handler.py` | One dev-preview request: the real pages over in-memory sample data; no sign-in, nothing saved. |
| `dev_post_action.py` | Act out every form post in memory only (DNS records, TSIG keys, apply, PKI, vault, devices, roles, people, DHCP reservations, subnets, options and classes, RADIUS clients and groups) and show the same result page or redirect as production. Nothing is saved, signed or applied; secrets and passwords shown are fake or throwaway. |
| `dev_post_directory.py` | People, devices and roles acted out in memory, with the real fabriclib rules when available. |
| `dev_post_dns.py` | TSIG keys, zones and zone records acted out in memory (secrets are fresh random throwaways). |
| `dev_post_dns_filter.py` | The DNS filter tab's changes (lists, rules, upstreams) on the sample data |
| `dev_post_dhcp.py` | The Kea tab's changes (reservations, subnets, options, classes) on the sample data |
| `dev_post_network.py` | RADIUS groups and clients, acted out on the sample data in memory. |
| `dev_post_enrol.py` | Step-CA → Enrol a device, acted out in memory: a .p12 result with a throwaway password, withdrawing a sample profile. |
| `dev_post_ssh.py` | The SSH page, acted out in memory: on and off, a placeholder certificate for an Ed25519 key. |
| `dev_state.py` | In-memory sample data; nothing leaves this process. |
| `fabric_rules.py` | fabriclib's real rules when the dev preview runs from a checkout (devserver.py puts src on the path); the webui image carries only src/webui/, so without them the preview shows sample data and skips the directory forms. |
| `sample_data.py` | The dev preview's sample data: what a small home install looks like (nothing here is real). |
| `sample_radius_guides.py` | The FreeRADIUS setup guides as fabric-agent fills them in, built from the sample RADIUS data and the dev preview's own throwaway CA (SAMPLE_ROOT_PEM). Sample only; nothing is read from a host. |
| `sample_result.py` | A fake PKI result for the sign/issue/convert result page, shaped like fabric-agent's reply. |
| `__init__.py` | Empty; makes it a package |
| `dev_networks_page.py` | The Networks tab over the sample address plan (drawn by fabriclib's networks_view from a checkout), and its CSV export |
| `dev_post_networks.py` | The Networks tab's changes on the sample plan in memory: the site's number, VLANs, addresses |
| `sample_networks.py` | The sample address plan: a top site with a house below it, and this site's leases |
