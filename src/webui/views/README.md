# src/webui/views

Every page (Jinja2 templates in ../templates, autoescaped, no inline script or style) and the stylesheet; hides tabs, menus and forms the person has no permission for. `from webui import views` imports them all.

| File | What |
|---|---|
| `apply_result.py` | The page after Apply: whether it worked and its output. |
| `audit.py` | The audit log page, newest first. |
| `b64.py` | Base64-encode a text for a data: download link. |
| `bind9.py` | The BIND9 tab: forward zone records and the add form, generated reverse zones, or TSIG keys. |
| `changes.py` | A page's Review (manual 1.8.6.5): its pending changes, was and becomes, the queue, results shown once. |
| `constants.py` | What the pages show: the navigation (`NAV`), sections, sub-menus, the permissions that show them. |
| `nav_menu.py` | The navigation down the left for one person: the entries they may see, each linked to its first page they may see, the page shown's entry open. |
| `continue_page.py` | The 'Signed in' page that moves on to the target with a meta refresh and a link. |
| `css.py` | The whole stylesheet (static/webui-app/app.css), served as /static/app.css (light and dark colour schemes). |
| `directory.py` | The Directory tab: devices, one device, roles, one role, or people and groups. |
| `error_page.py` | The error page: status, message and a 'Sign in again' link. |
| `freeradius.py` | The FreeRADIUS tab: overview (server, people groups, RADIUS clients, recent decisions) or a setup guide for switches or Windows. |
| `dns_filter.py` | The DNS filter tab: statistics, lists and AdGuard's catalogue, rules, the query log, upstreams |
| `kea.py` | The Kea tab: subnets, reservations with add/remove forms, and leases — or how to turn DHCP on. |
| `openbao.py` | The OpenBao tab: status, unlock methods (with add, rotate and remove views), secrets, disk encryption guide. |
| `overview.py` | The Overview entry's pages: Health (a tile per service with a light and a link to its page), Doctor, Updates. |
| `person_result.py` | The page that shows a person's one-time password once, after creating them or resetting their sign-in. |
| `pki_result.py` | The result page after signing, issuing or converting a certificate: details and every format as a download. |
| `radius_secret.py` | The page that shows a RADIUS client's shared secret once, after adding it or making a new one. |
| `render_page.py` | Render one template in the frame (top bar, navigation, the message of the last action), hiding the pages, sub-menus and forms the signed-in person has no permission for. |
| `stepca.py` | The Step-CA tab: CA details, sign a CSR, new key + certificate, inspect, convert, or the issued list. |
| `tsig_result.py` | The page that shows a TSIG key's secret and RFC2136 client settings once. |
| `__init__.py` | Imports every function of this folder, so callers keep `module.function` |
| `machine_result.py` | The page that shows a pre-created machine's one-time join password once. |
| `federation.py` | The Federation tab: sites, replication, conflicts, limits, the address plan. |
| `security.py` | The Security page: the sign-in layers and their raises |
| `job_page.py` | A background job's page: doctor's checks or what an image change did; refreshes itself while it runs |
| `settings.py` | The setup wizard: one step (optional parts, memory, passwords and sign-in, the upstreams, review), the rest carried hidden; the console-only settings read only |
| `settings_plan.py` | A plan of the setup wizard: each change old to new, the parts and memory, what an import ignored; Apply |
