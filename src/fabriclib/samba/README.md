# fabriclib/samba

The optional Windows domain: a Samba AD domain controller on the host's address (manual 1.6.5, 1.6.3). The DC
itself is a container (`templates/samba`, `packaging/images/samba`); what converges the domain runs inside it
(`src/containers/samba`).

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `deploy_samba.py` | The DC's files under `<deploy_base>/samba`: root-only folders, the Administrator's password file, the converge code |
| `write_bind_dlz.py` | What BIND includes for the AD zone: Samba's DLZ module and the update keytab, once the domain exists (empty before) |
| `suggested_ad_domain.py` | The AD domain setup suggests: a sibling at the top of the organisation's name (2.1.6.11) |
| `suggested_dc_name.py` | The DC's name setup suggests: `dc-<hostname>`, cut to 15 characters (2.1.6.45) |
| `dc_name_problem.py` | Why a name cannot be the DC's: one label of 1-15 characters, not only digits, not the domain's NetBIOS name |
| `domain_dc_names.py` | The domain's computer names, its DCs apart, read inside this site's DC (a joining site's DC name checked) |
| `id_range.py` | This site's uid/gid block (the root's from `posix_id_start`, `posix_id_block` long; a joined site's from its parent) |
| `sso_spns.py` | The HTTP SPNs of the site's Kerberos sign-in account (none without Keycloak or Kerberos, or at a read-only DC) |
| `converge_domain.py` | The wanted state handed to the converge code inside the running DC; what changed (after every start and apply) |
| `domain_status.py` | What `fabricctl domain status` shows: the DC, whether it runs, its roles, the policy in force |
| `set_domain_password_policy.py` | Change the password policy in the settings (checked whole, audited); the next apply writes it |
| `run_domain_command.py` | `fabricctl domain status`, `password-policy`, `add-machine` and `logon show / set / clear` (routing only) |
| `logon_ou_path.py` | An OU's path below the site's OU as a log-on policy names it (`site` for the site's OU) |
| `check_logon_policies.py` | The setting `logon_policies` checked and normalised: OU paths, group names, the site's machines always covered (1.6.11.4) |
| `set_logon_policy.py` | Who may sign in to one OU's machines, saved (groups checked in the domain; the first edit keeps today's rights as the site OU's; audited) |
| `clear_logon_policy.py` | One OU's log-on policy removed (it takes its parent's; never leaving the site's machines without one; audited) |
| `logon_overview.py` | Who may sign in, per OU: `logon show`, domain status, the web console's Machines section |
| `host_logon_default.py` | The log-on policy of the site's OU=fabric-hosts while the setting names none: the fabric admins (2.1.6.53) |
| `writable_server.py` | The DC a write to the domain goes to: this site's, or a read-only DC's writable partner (`ad_join_server`); refused with none known (2.1.6.52, 2.1.10.23) |
| `allow_rodc_cache.py` | At a site whose DC is read-only: puts `<site>-rodc-cache` on that DC's password replication allow list, at the writable DC (2.1.6.52) |
| `sync_rodc_cache.py` | At a site whose DC is read-only: the DC's lists checked (the cache group allowed, the denied list whole), `<site>-rodc-cache` kept at the writable DC (the site's people groups nested, its machines members), the site's own accounts preloaded (2.1.6.55) |
| `gpo_request.py` | One ADMX-editor operation inside the DC (`gpo_tool.py`), the request on stdin |
| `run_gpo_command.py` | `fabricctl gpo load / templates / list / show / set / clear / starter` |
| `domain_overview.py` | The Directory tab's domain section: the DC, the policy, this site's machines |
| `gpo_overview.py` | The Group Policy section: templates, the admin settings GPO, a policy search |
| `set_gpo_policy.py` | Set a policy in the site's admin settings GPO (audited; CLI and web UI) |
| `clear_gpo_policy.py` | Put a policy back to Not configured (audited; CLI and web UI) |
| `run_converge.py` | Hand a wanted state to the converge code inside a DC (stdin) |
| `prepare_site.py` | At the root, before answering a join: the new site converged in the domain, and its join account |
| `finish_join.py` | After this site's DC joined: its join account deleted at the root |
| `replication_status.py` | This DC's inbound replication per partition, read from its own `repsFrom` inside the DC |
| `domain_sites.py` | Every site in the domain, read inside this site's DC (the next id block a join hands out; a site moving here) |
| `list_conflicts.py` | AD's `CNF:` objects: names made on two DCs while apart |
| `check_password_policy.py` | The password policy as AD takes it (ranges, minimum age below maximum, lockout at least its window); setup asks again at once, deploy refuses |
| `password_meets_policy.py` | Why the domain would refuse a password a person chose (length, AD's complexity): setup asks again at once (2.1.6.33) |
| `read_policy_changes.py` | The password-policy values a console request carries, typed as the command's options (2.1.2.22) |
| `summarize_roles.py` | The domain-wide (FSMO) roles named plainly: all held here, or which another controller holds (2.1.2.22) |
