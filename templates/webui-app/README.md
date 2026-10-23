# templates/webui-app

The page templates (Jinja2, rendered by `views/render_page.py` with autoescape; no inline script or style, so pages work under the strict Content-Security-Policy). `base.html` is the frame every page extends.

| File | What |
|---|---|
| `apply.html` | The apply page |
| `audit.html` | The audit page |
| `base.html` | The frame: the top bar, the navigation down the left (only the entries and pages the person may see), the message of the last action |
| `pattern.html` | The page pattern's macros (manual 1.8.6.3): a status light, the actions bar, an empty state, a detail page's facts, a list |
| `bind9.html` | The bind9 page |
| `changes.html` | A page's Review: pending changes, Apply and Discard, the queue, one-time results |
| `continue.html` | The continue page |
| `directory.html` | The directory page |
| `directory_macros.html` | Macros for the device and role forms |
| `error.html` | The error page |
| `freeradius.html` | The freeradius page |
| `dns_filter.html` | The DNS filter tab |
| `kea.html` | The kea page |
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
| `job.html` | A background job (doctor, an image update, the setup wizard's apply), with a meta refresh while it runs |
| `settings.html` | The setup wizard: one step at a time with the others carried hidden, the console-only settings read only, Export, Import, Dismiss |
| `settings_plan.html` | A plan of the setup wizard: the changes old to new, the parts and the memory plan, what was ignored; Apply |
