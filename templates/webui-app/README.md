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
| `account.html` | My account: details, the password form, sign-in factors, certificates and devices; Groups I manage |
| `continue.html` | The continue page |
| `directory.html` | The Directory's Overview; 802.1X's devices and roles |
| `groups.html` | Directory · Groups: the list, a group's page, Create group |
| `access.html` | Directory · Access: the grants, a grant's page, Add grant |
| `ous.html` | Directory · OUs: the tree, an OU's page |
| `computers.html` | Directory · Computers: the list, a computer's page, Add computer, Machine groups, a keytab command |
| `policies.html` | Directory · Policies: the password policy, Group Policy, the sudo rules |
| `people.html` | Directory · People: the list, a person's page, Add person |
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
| `federation.html` | The Federation tab |
| `security.html` | The Security page (sign-in layers, raises, Kerberos on/off; lowering shown as the host command) |
| `job.html` | A background job (doctor, an image update, the setup wizard's apply), with a meta refresh while it runs |
| `settings.html` | The setup wizard: one step at a time with the others carried hidden, the console-only settings read only, Export, Import, Dismiss |
| `settings_plan.html` | A plan of the setup wizard: the changes old to new, the parts and the memory plan, what was ignored; Apply |
