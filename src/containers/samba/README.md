# src/containers/samba

Code that runs inside the Samba AD domain controller (manual 1.6.5.15, S1.3), copied to `<deploy_base>/samba/converge`
and mounted read-only. `converge.py` runs as root inside the DC on its own database (no credentials, no network);
`directory_op.py` signs in over loopback LDAP as the DC's agent account, so AD's limits apply to it.

| File | What |
|---|---|
| `converge.py` | The entry point: the wanted state as JSON on stdin, every part in order, what changed as JSON |
| `open_samdb.py` | The DC's database opened locally as the system (optionally allowing schema changes) |
| `repair_role_owners.py` | The roles this DC holds named by its current DN (a renamed AD site left the old text, 1.6.5.24) |
| `ensure_schema.py` | fabric's and sudo's attributes and classes in AD's schema, added once (OIDs AD accepts, Q3) |
| `ensure_layout.py` | The directory's folders (OU=people, OU=service-accounts, OU=groups with OU=fabric, OU=machines with one OU per type, OU=fabric-hosts, OU=devices, OU=device-roles, OU=networks, OU=sudoers) and `CN=fabric,CN=System`; AD's default containers point at OU=people and OU=machines (1.6.13.2) |
| `ensure_groups.py` | The domain's groups (1.6.13.3): fabric-managed, directory-admins, dc-hosts, the tiers' admin groups, the machine types' groups, `site-<name>` per site, `rodc-cache-<dc>` for a read-only DC (2.1.6.52); fabric's `ldap_groups`, Domain Users as `users` (5000), `fabric-break-glass` |
| `alloc_id.py` | The next number of a range for one use, from this DC's own range first, then its site's other DCs' (2.1.6.63), taken with one conditional change (never twice) |
| `ensure_sso_account.py` | The site's `fabric-sso-<site>` account in OU=service-accounts: Keycloak's Kerberos SPNs, AES only, its keytab exported to `/data/sso.keytab` |
| `ensure_service_accounts.py` | The DC's `fabric-agent-<dc>`, `fabric-keycloak-<dc>`, `fabric-radius-<dc>` in OU=service-accounts (2.1.6.82); a password set only when it no longer signs in |
| `directory_op.py` | fabric-agent's entry point: one directory operation, signed in as the DC's agent account (not the system); the request's DC passed to an operation that takes one |
| `directory_ops.py` | The operations fabric-agent may ask for |
| `ensure_ad_site.py` | The AD site of this fabric site and its subnets from the address plan |
| `set_password_policy.py` | The admin's password policy on the domain object (2.1.6.13) |
| `ensure_gpo.py` | One of fabric's GPOs created, linked, its SYSVOL files written, its version bumped on change |
| `root_ca_policy.py` | The Registry.pol that makes fabric's root CA a trusted root on Windows (Q13) |
| `find_gpo.py` | A GPO found by its display name |
| `list_people.py` | Operation `list_people`: the people in OU=people and the groups in OU=groups |
| `create_person.py` | Operation `create_person`: a person in OU=people, a uid from the DC's range, in their site's `site-<name>`, must change their password |
| `get_person.py` | Operation `get_person`: where a person lives and their groups |
| `reset_password.py` | Operation `reset_password`: a new one-time password, the account unlocked |
| `add_group_member.py` | Operation `add_group_member`: a person in a group, once |
| `remove_group_member.py` | Operation `remove_group_member`: a person out of a group, once |
| `paths.py` | The DNs of the directory's folders, a machine type's OU, `CN=fabric,CN=System` and a DC's record |
| `read_devices.py` | Operation `read_devices`: the domain's devices and the roles they may use |
| `save_device.py` | Operation `save_device`: a device created or replaced in `OU=devices`, its roles by name |
| `remove_device.py` | Operation `remove_device`: a device deleted |
| `link_device_cert.py` | Operation `link_device_cert`: a certificate fingerprint recorded on a device or forgotten |
| `save_role.py` | Operation `save_role`: a device role (a group with `fabricRole`) in `OU=device-roles` |
| `remove_role.py` | Operation `remove_role`: a role deleted, refused while devices carry it |
| `share_winbind.py` | winbind's privileged pipe in FreeRADIUS's group (root, 0750), for PEAP through `ntlm_auth` |
| `ensure_networks.py` | The site's networks as `fabricNetwork` entries (`<site>/<name>`, marked with the site) in OU=networks (the address plan), kept to match |
| `read_networks.py` | Operation `read_networks`: the address plan, every site's networks in one search |
| `create_machine.py` | Operation `create_machine`: a machine pre-created in its type's OU under OU=machines (or OU=machines itself) with a one-time join password, in its type's and its site's groups and fabric-managed |
| `sort_windows_machines.py` | Operation `sort_windows_machines`: Windows machines that joined themselves into OU=machines moved into OU=servers or OU=desktops by their operatingSystem, those moved before skipped (manual 1.6.13.3) |
| `adopt_linux_machines.py` | Operation `adopt_linux_machines`: Linux machines of the site's group joined with an admin's password made members of fabric-managed, once, unless their join said unmanaged (manual 1.6.11.6) |
| `host_groups.py` | Host groups and fabric's sudo rules (1.6.11.7): their names (`hosts-<name>`), marks, a host group's machines as sudo host names, the domain's rules |
| `list_host_groups.py` | Operation `list_host_groups`: the domain's `hosts-<name>` groups, their machines and the sudo rules naming each |
| `create_host_group.py` | Operation `create_host_group`: a host group in OU=groups |
| `remove_host_group.py` | Operation `remove_host_group`: a host group deleted, refused while a sudo rule names it |
| `set_host_group_member.py` | Operation `set_host_group_member`: a machine in or out of a host group, the sudo rules' hosts refreshed |
| `list_sudo_rules.py` | Operation `list_sudo_rules`: the rules in OU=sudoers, each fabric's editor's or an admin's own |
| `add_sudo_rule.py` | Operation `add_sudo_rule`: a sudo rule of fabric's editor (ALL commands to everyone refused) |
| `remove_sudo_rule.py` | Operation `remove_sudo_rule`: one of the editor's rules deleted (never an admin's own) |
| `refresh_sudo_hosts.py` | The editor's rules on a host group name its machines' short and DNS names as sudoHost (after a member change, at convergence) |
| `windows_baseline_policy.py` | The site's Windows baseline, linked at OU=machines: wait for the network at log-on, the domain's time, Wired AutoConfig and the 802.1X profile (start-up script) |
| `gpo_tool.py` | fabric's ADMX editor's entry point: one operation (load, templates, policies, show, set, clear) as JSON |
| `admx_store.py` | The domain's central store: templates saved, and every policy they define read as Windows' editor reads them |
| `policy_entries.py` | What a policy writes to the registry (enabled with its elements, disabled), and which values are its own |
| `admin_gpo.py` | The site's `fabric: <site> admin settings` GPO, linked at OU=machines: what it sets, and writing it |
| `list_machines.py` | Operation `list_machines`: the domain's computer accounts (in OU=machines and OU=fabric-hosts) with their type, state and last logon |
| `find_machine.py` | A machine by its name, in OU=machines or OU=fabric-hosts (for set_machine, remove_machine, place_fabric_host) |
| `place_fabric_host.py` | Operation `place_fabric_host`: the site's fabric host's account moved into OU=fabric-hosts, made a member of fabric-managed and dc-hosts (and `rodc-cache-<dc>` at a read-only DC, 2.1.6.52), marked as the fabric host (manual 1.6.11.11) |
| `set_machine.py` | Operation `set_machine`: disable a machine, or enable it again |
| `remove_machine.py` | Operation `remove_machine`: a machine removed from the domain |
| `find_person.py` | A person by user name, in OU=people (for set_person and remove_person) |
| `set_person.py` | Operation `set_person`: disable a person, or enable them again |
| `remove_person.py` | Operation `remove_person`: a person removed from the domain |
| `ensure_join_account.py` | At the root: the temporary account a new site's DC joins with (Domain Admins, expires in an hour) |
| `ensure_site_link.py` | A site's AD site link to its parent (cost 100, 15 minutes, change notification) |
| `set_gpo_acl.py` | One GPO folder's file ACLs from its AD object (a site's DC lacks the domain's other GPO folders) |
| `read_replication.py` | This DC's inbound replication per partition, from its own `repsFrom` (works at a read-only DC too) |
| `pull_sysvol.py` | The GPO folders this DC does not own, copied over SMB from the DC that owns each (run every 5 minutes by the entrypoint) |
| `id_layout.py` | A DC's id range from its name (dc-NNNN: N x 1000000, 2.1.6.63), the fixed ranges inside it (offsets by kind), and the check that a range is a DC's |
| `read_dc_names.py` | The domain's computer names, its DCs and their records apart (a parent gives a joining site's DC the lowest free name, 2.1.6.65) |
| `read_sites.py` | Every DC's record in the domain: its name, its site and its id range |
| `acl_entries.py` | Access entries added once (compared parsed, object entries by their attribute) and a principal's SID |
| `remove_ipv6_records.py` | The AD zones on IPv4 only (2.1.6.29): every AAAA record removed (the DC listens on IPv4) |
| `ensure_dc_record.py` | The DC's record in `CN=dcs,CN=fabric,CN=System` (2.1.6.79): its site, its id range and a mark per fixed range; a read-only DC's is written by the writable DC |
| `dc_info.py` | Operation `dc_info`: a DC's record: its site, id range and its ranges' marks |
| `group_names.py` | The names of the domain's groups (1.6.13.3): the fixed ones, `site-<name>`, `machines-<type>`, `rodc-cache-<dc>` |
| `ensure_directory_acl.py` | directory-admins' rights (2.1.6.81): full control and GPO links on OU=people, OU=service-accounts, OU=machines and OU=groups, denied on fabric's accounts, the tiers' groups and OU=fabric; the agents' and Keycloak's rights |
| `protect_top_tier.py` | The top tier kept out of directory-admins' reach: the protected accounts and groups (AdminSDHolder) never inherit from the folders (2.1.6.81) |
| `ensure_top_tier.py` | Run as root from fabric-ctl: the first admin made a member of Enterprise, Schema and Domain Admins (2.1.6.81), JSON on stdin |
