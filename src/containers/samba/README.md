# src/containers/samba

Code that runs inside the Samba AD domain controller (manual 1.6.5.15, S1.3), copied to `<deploy_base>/samba/converge`
and mounted read-only. `converge.py` runs as root inside the DC on its own database (no credentials, no network);
`directory_op.py` signs in over loopback LDAP as the site's agent account, so AD's limits apply to it.

| File | What |
|---|---|
| `converge.py` | The entry point: the wanted state as JSON on stdin, every part in order, what changed as JSON |
| `open_samdb.py` | The DC's database opened locally as the system (optionally allowing schema changes) |
| `repair_role_owners.py` | The roles this DC holds named by its current DN (a renamed AD site left the old text, 1.6.5.24) |
| `ensure_schema.py` | fabric's and sudo's attributes and classes in AD's schema, added once (OIDs AD accepts, Q3) |
| `ensure_layout.py` | `OU=sites`, the site's OU tree, `OU=organisation` at the root site; new users and computers into it |
| `ensure_groups.py` | `<site>-users`, `<site>-admins` (gids from the site's block), `<site>-rodc-cache` (the accounts a read-only DC caches, 2.1.6.52); at the root site fabric's groups (`ldap_groups`, their gids), Domain Users as `users` (5000), `fabric-break-glass` |
| `ensure_site_info.py` | The site's uid/gid block on its OU (2.1.6.17) and a mark per fixed range (2.1.6.46) |
| `alloc_id.py` | The next number of a site's block for one use (from its range), taken with one conditional change (never twice) |
| `ensure_sso_account.py` | The site's `fabric-sso` account: Keycloak's Kerberos SPNs, AES only, its keytab exported to `/data/sso.keytab` |
| `ensure_service_accounts.py` | The site's `fabric-agent`, `fabric-keycloak`, `fabric-radius` accounts; a password set only when it no longer signs in |
| `directory_op.py` | fabric-agent's entry point: one directory operation, signed in as the site's agent account (not the system) |
| `directory_ops.py` | The operations fabric-agent may ask for |
| `site_info.py` | Operation `site_info`: a site's OU, id block and its ranges' marks |
| `ensure_site_acl.py` | The site's admins and agent: full control of their site's OU, nothing on its service accounts (Q4); Keycloak: the site's people; below the root, the site denied what the sites above decide for it (its local scans, a scan request in its plan) |
| `ensure_ad_site.py` | The AD site of this fabric site and its subnets from the address plan |
| `set_password_policy.py` | The admin's password policy on the domain object (2.1.6.13) |
| `ensure_gpo.py` | One of fabric's GPOs created, linked, its SYSVOL files written, its version bumped on change |
| `root_ca_policy.py` | The Registry.pol that makes fabric's root CA a trusted root on Windows (Q13) |
| `logon_rights_policy.py` | The GptTmpl.inf granting log-on to a site's machines, at the keyboard and remotely (2.1.6.14, Q16, 1.6.11.4) |
| `ensure_logon_policies.py` | Who may sign in to the site's machines: one log-on GPO per OU of `logon_policies` (or, null, the site's legacy one), the ones no longer wanted removed; OU=fabric-hosts always has one, the fabric admins by default (1.6.11.4, 2.1.6.53) |
| `legacy_logon_groups.py` | The groups a site grants log-on to while it has no per-OU policies (as before 0.9, 2.1.6.44) |
| `logon_groups.py` | Operation `logon_groups`: which named groups do not exist, and the site's legacy log-on groups (the editor's first edit) |
| `find_gpo.py` | A GPO found by its display name |
| `remove_gpo.py` | One of fabric's GPOs unlinked everywhere, its container and SYSVOL folder deleted |
| `list_people.py` | Operation `list_people`: people and groups under OU=sites (service accounts left out) |
| `create_person.py` | Operation `create_person`: a person in the site's OU=people, a uid from its block, in `<site>-users`, must change their password |
| `get_person.py` | Operation `get_person`: where a person lives and their groups |
| `is_fabric_admin.py` | Whether a person is a fabric admin: a member, nested too, of `fabric-admins` or `<site>-fabric-admins` (who may get an SSH certificate, manual 1.6.11.9) |
| `reset_password.py` | Operation `reset_password`: a new one-time password, the account unlocked |
| `add_group_member.py` | Operation `add_group_member`: a person in a group, once |
| `remove_group_member.py` | Operation `remove_group_member`: a person out of a group, once |
| `paths.py` | The DNs of `OU=sites`, a site's OU and its `OU=devices` |
| `read_devices.py` | Operation `read_devices`: the site's devices and the roles it may use (its own and the organisation's) |
| `save_device.py` | Operation `save_device`: a device created or replaced in the site's `OU=devices`, its roles by name |
| `remove_device.py` | Operation `remove_device`: a device deleted |
| `link_device_cert.py` | Operation `link_device_cert`: a certificate fingerprint recorded on a device or forgotten |
| `save_role.py` | Operation `save_role`: a device role (a group with `fabricRole`) in the site's or the organisation's `OU=device-roles` |
| `remove_role.py` | Operation `remove_role`: a role deleted, refused while devices carry it |
| `share_winbind.py` | winbind's privileged pipe in FreeRADIUS's group (root, 0750), for PEAP through `ntlm_auth` |
| `ensure_networks.py` | The site's networks as `fabricNetwork` entries in its OU=networks (the address plan), kept to match |
| `read_networks.py` | Operation `read_networks`: the address plan, every site's networks in one search |
| `read_plan.py` | Operation `read_plan`: the address manager's plan, one site's or every site's, and every site's number |
| `write_plan.py` | Operation `write_plan`: checked changes to a site's plan (VLANs, subnets, ranges, addresses, its number, whether a site below may scan locally) |
| `read_scan_requests.py` | Operation `read_scan_requests`: the scan requests in a site's plan, their answers and whether a site above made each (2.1.10.30) |
| `write_scan_request.py` | Operation `write_scan_request`: a scan request added by a site above, answered or removed by the branch (2.1.10.30) |
| `schema_guid.py` | An attribute's or class's schemaIDGUID, as an access entry names it |
| `ensure_org_options.py` | At the top site: the organisation's DHCP options entry, the group `fabric-dhcp-org-editors` and its access to it |
| `read_usn.py` | Print the DC's highest committed USN (an anonymous root DSE read): the plan poll's first step |
| `plan_cidrs.py` | The networks of the site's plan subnets, for its AD site |
| `create_machine.py` | Operation `create_machine`: a machine pre-created in the site's OU=machines with a one-time join password |
| `sort_windows_machines.py` | Operation `sort_windows_machines`: Windows machines that joined themselves into OU=machines moved into OU=windows, those moved before skipped (manual 1.6.11.5) |
| `sync_rodc_cache.py` | Operation `sync_rodc_cache`: `<site>-rodc-cache` holding exactly the site's `<site>-users` and `<site>-admins` (nested) and its computer accounts, anything else taken out; returns the site's own accounts it reaches (to preload) and any other account reached (reported) (2.1.6.55, manual 1.6.11.14) |
| `adopt_linux_machines.py` | Operation `adopt_linux_machines`: Linux machines joined into OU=linux with an admin's password made members of <site>-fabric-machines, once, unless their join said unmanaged (manual 1.6.11.6) |
| `ensure_sudo_rule.py` | The site's default sudo rule: its admins and the admin group may run anything on its machines (2.1.9.13) |
| `host_groups.py` | Host groups and fabric's sudo rules (1.6.11.7): their names, marks, a host group's machines as sudo host names, the site's rules |
| `list_host_groups.py` | Operation `list_host_groups`: the site's `<site>-hosts-<name>` groups, their machines and the sudo rules naming each |
| `create_host_group.py` | Operation `create_host_group`: a host group in the site's OU=groups |
| `remove_host_group.py` | Operation `remove_host_group`: a host group deleted, refused while a sudo rule names it |
| `set_host_group_member.py` | Operation `set_host_group_member`: a machine of the site in or out of a host group, the sudo rules' hosts refreshed |
| `list_sudo_rules.py` | Operation `list_sudo_rules`: the rules in the site's OU=sudoers, each fabric's editor's, the site default or an admin's own |
| `add_sudo_rule.py` | Operation `add_sudo_rule`: a sudo rule of fabric's editor (ALL commands to everyone refused) |
| `remove_sudo_rule.py` | Operation `remove_sudo_rule`: one of the editor's rules deleted (never the site default, never an admin's own) |
| `refresh_sudo_hosts.py` | The editor's rules on a host group name its machines' short and DNS names as sudoHost (after a member change, at convergence) |
| `windows_baseline_policy.py` | The site's Windows baseline: wait for the network at log-on, the domain's time, Wired AutoConfig and the 802.1X profile (start-up script) |
| `gpo_tool.py` | fabric's ADMX editor's entry point: one operation (load, templates, policies, show, set, clear) as JSON |
| `admx_store.py` | The domain's central store: templates saved, and every policy they define read as Windows' editor reads them |
| `policy_entries.py` | What a policy writes to the registry (enabled with its elements, disabled), and which values are its own |
| `admin_gpo.py` | The site's `fabric: <site> admin settings` GPO: what it sets, and writing it |
| `list_machines.py` | Operation `list_machines`: the site's computer accounts (Windows and Linux, and its fabric host) with state and last logon |
| `find_machine.py` | A machine of the site by its name, in its OU=machines or OU=fabric-hosts (for set_machine, remove_machine, place_fabric_host) |
| `place_fabric_host.py` | Operation `place_fabric_host`: the site's fabric host's account moved into OU=fabric-hosts, made a member of <site>-fabric-machines (and <site>-rodc-cache at a read-only DC's site, 2.1.6.52), marked as the fabric host (manual 1.6.11.11) |
| `list_ssh_hosts.py` | Operation `list_ssh_hosts`: the site's computer accounts with their SSH host keys and certificates, managed or not, enabled or not (manual 1.6.11.9.8) |
| `prepare_ssh_hosts.py` | Operation `prepare_ssh_hosts`: the auxiliary class `fabricSshHost` on each managed, enabled machine, so it can publish its host keys (1.6.11.9.7) |
| `set_ssh_host.py` | Operation `set_ssh_host`: a machine's host certificates written back by fabric (and the fabric host's own host keys), each value checked (1.6.11.9.8) |
| `set_machine.py` | Operation `set_machine`: disable a machine, or enable it again |
| `remove_machine.py` | Operation `remove_machine`: a machine removed from the domain |
| `find_person.py` | A person of the site by user name, in its own OU=people (for set_person and remove_person) |
| `set_person.py` | Operation `set_person`: disable a person, or enable them again |
| `remove_person.py` | Operation `remove_person`: a person removed from the domain |
| `ensure_join_account.py` | At the root: the temporary account a new site's DC joins with (Domain Admins, expires in an hour) |
| `ensure_site_link.py` | A site's AD site link to its parent (cost 100, 15 minutes, change notification) |
| `set_gpo_acl.py` | One GPO folder's file ACLs from its AD object (a site's DC lacks the domain's other GPO folders) |
| `read_replication.py` | This DC's inbound replication per partition, from its own `repsFrom` (works at a read-only DC too) |
| `pull_sysvol.py` | The GPO folders this DC does not own, copied over SMB from the DC that owns each (run every 5 minutes by the entrypoint) |
| `id_layout.py` | The fixed ranges inside a site's id block (offsets by kind), and the check that a block is a site's: a million ids from a multiple of a million (2.1.6.46) |
| `read_dc_names.py` | The domain's computer names, its DCs apart (a parent refuses a joining site's DC a name in use, 2.1.6.45) |
| `read_sites.py` | Every site in the domain: its name, where its OU sits and its uid/gid block (a parent hands out a free block, and recognises a site moving under it) |
| `site_roles.py` | The five roles that administer a site, each its own group (2.1.9.13); the site's rodc-cache group's name (2.1.6.52) |
| `acl_entries.py` | Access entries added once (compared parsed, object entries by their attribute) and a principal's SID |
| `remove_ipv6_records.py` | The AD zones on IPv4 only (2.1.6.29): every AAAA record removed (the DC listens on IPv4) |
