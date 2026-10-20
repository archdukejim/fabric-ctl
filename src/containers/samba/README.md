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
| `ensure_tier_policies.py` | The tiers' fine-grained password policies: fabric-admin's (precedence 1) and the Directory Administrators' on directory-admins (precedence 2), 2.1.6.71 |
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
| `list_sudo_rules.py` | Operation `list_sudo_rules`: the rules in OU=sudoers, each fabric's editor's, a grant's or an admin's own |
| `add_sudo_rule.py` | Operation `add_sudo_rule`: a sudo rule of fabric's editor (ALL commands to everyone refused) |
| `remove_sudo_rule.py` | Operation `remove_sudo_rule`: one of the editor's rules deleted (never an admin's own) |
| `refresh_sudo_hosts.py` | The editor's rules on a host group, and the grants' rules on their computed where group, name its machines' short and DNS names as sudoHost (after a member change, at a compile, at convergence) |
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
| `ensure_top_tier.py` | An account made a member of Enterprise, Schema and Domain Admins, the top tier's denies written at once (2.1.6.68) |
| `ensure_enterprise_admin.py` | Run as root from fabric-ctl: `fabric-admin`, the Enterprise Admin, made once in OU=people with the generated password (JSON on stdin) and put in AD's top tier (2.1.6.69) |
| `reset_break_glass.py` | Run as root from fabric-ctl (`fabricctl admin reset-break-glass`): `fabric-admin`'s new generated password set (JSON on stdin) and the account unlocked; a disabled account reported, never enabled (2.1.6.75) |
| `grant_names.py` | The grants' vocabulary (1.6.13.4, 1.6.13.5): the name rule, the rights by category, the computed groups' and GPOs' names, the shipped grants and the templates |
| `grant_store.py` | The grant store in `CN=grants,CN=fabric,CN=System`: one `msDS-App-Configuration` per grant, its JSON in `msDS-Settings`; the compiler's record of the sets |
| `check_grant.py` | A grant as it may be stored, or why not (its name, who and where, the tiers' groups and the DC hosts refused, the rights, sudo of every command for everyone) |
| `grant_members.py` | A group's people and computers (nesting and primary groups followed); those no grant reaches (the top tier, fabric's accounts, the DC hosts); a grant's reach |
| `ensure_computed_group.py` | A computed group in OU=fabric,OU=groups with exactly its members (a POSIX one for sudo); the computed groups there |
| `access_policy.py` | A set's (or the fallback's) security template: sign-in at the keyboard and remotely, local administrators, always with Administrators and `local-admin` |
| `set_gpo_filter.py` | A GPO's security filtering as GPMC sets it: one group applies it, or every machine |
| `order_gpo_links.py` | One GPO's link put first in an OU's `gPLink` (the lowest precedence): the fallback (2.1.6.87) |
| `remove_gpo.py` | One of fabric's GPOs unlinked everywhere and deleted with its SYSVOL folder (a set no longer wanted) |
| `ensure_grant_sudo.py` | One `sudoRole` per grant with sudo (`grant-<name>`, `%grant-<name>-who`), its hosts its where group's machines |
| `compile_grants.py` | The grants compiled: computed groups, the sets of machines with one GPO each, the fallback first, the sudo rules (at the root's writable DC) |
| `explain_grants.py` | Which grants reach a person (and on a machine), and why; what they may do there |
| `ship_grants.py` | The grants a fresh install ships (1.6.13.5), made once at the root |
| `grants_tool.py` | The grants' entry point (as root, like gpo_tool): list, show, add, set, remove, compile, explain |
| `authorize_action.py` | fabric-agent's check (1.6.12.17): the caller's tier, the grants' people and machines rights, a group's two levels; refused with why |
| `group_kind.py` | A group's kind: AD's, a tier's, a bundle's, fabric's, filled, computed, a machine group, an admin's own |
| `group_store.py` | A group's managers and controls in `CN=groups,CN=fabric,CN=System` (one `msDS-App-Configuration` per group, by objectGUID) |
| `group_uses.py` | Where a group is used: grants, sudo rules, other groups' managers |
| `list_groups.py` / `group_scope.py` / `managed_groups.py` | The groups and kinds; one group's two levels; the groups a person manages |
| `create_group.py` / `remove_group.py` / `set_group_managers.py` | An admin's own group made (with a gid), deleted (unused only), its managers set |
| `ou_paths.py` | OUs by path; where an admin's own may go; fabric's fixed OUs |
| `list_ous.py` / `create_ou.py` / `rename_ou.py` / `delete_ou.py` | The OU tree; an admin's own OU made, renamed, deleted (empty only) |
| `move_machine.py` / `set_machine_type.py` / `set_machine_site.py` | A computer's folder, type group, site groups |
| `list_spns.py` | Every SPN and its account, duplicates flagged |
| `edit_person.py` / `unlock_person.py` | A person's display name and e-mail; a lockout cleared |
| `change_own_password.py` | A person's own password: bound as them over NTLM, the change theirs (stdin only) |
