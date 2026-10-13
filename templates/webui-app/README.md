# templates/webui-app

The page templates (Jinja2, rendered by `views/render_page.py` with autoescape; no inline script or style, so pages work under the strict Content-Security-Policy). `base.html` is the frame every page extends.

| File | What |
|---|---|
| `apply.html` | The apply page |
| `audit.html` | The audit page |
| `base.html` | The frame: header, tabs (only those the person may see), footer |
| `bind9.html` | The bind9 page |
| `continue.html` | The continue page |
| `directory.html` | The directory page |
| `directory_macros.html` | Macros for the device and role forms |
| `error.html` | The error page |
| `freeradius.html` | The freeradius page |
| `dns_filter.html` | The DNS filter tab |
| `kea.html` | The kea page |
| `ipam_scan.html` | The scan page: scan a subnet this site's DHCP serves, and record what answers but nobody recorded (for the Networks tab) |
| `dhcp_options.html` | The DHCP options page under the Kea tab (`/kea/options`, manual 1.10.4.24.6): the organisation's and the site's option sets, subnets and reservations with their options and netboot presets, a target's effective options with their sources |
| `openbao.html` | The openbao page |
| `overview.html` | The overview page |
| `person_result.html` | The person result page |
| `pki_result.html` | The pki result page |
| `radius_secret.html` | The radius secret page |
| `stepca.html` | The stepca page |
| `tsig_result.html` | The tsig result page |
| `machine_result.html` | A pre-created machine's one-time join password |
| `federation.html` | The Federation tab |
| `security.html` | The Security page (sign-in layers, raises, Kerberos on/off; lowering shown as the host command) |
| `job.html` | A background job (doctor, an image update), with a meta refresh while it runs |
| `networks.html` | The Networks tab: sites and their numbers, VLANs with their subnets' bar maps, one subnet's ranges, address table and options with their sources, a search, the forms |
