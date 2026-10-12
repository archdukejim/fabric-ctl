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
| `ensure_groups.py` | `<site>-users`, `<site>-admins` (gids from the site's block); at the root site fabric's groups (`ldap_groups`, their gids), Domain Users as `users` (5000), `fabric-break-glass` |
| `ensure_site_info.py` | The site's uid/gid block and its high-water mark on its OU (2.1.6.17); a laid-out block's mark per range (2.1.6.46) |
| `alloc_id.py` | The next number of a site's block for one use (its range, or an older block's one run), taken with one conditional change (never twice) |
| `ensure_sso_account.py` | The site's `fabric-sso` account: Keycloak's Kerberos SPNs, AES only, its keytab exported to `/data/sso.keytab` |
| `ensure_service_accounts.py` | The site's `fabric-agent`, `fabric-keycloak`, `fabric-radius` accounts; a password set only when it no longer signs in |
| `directory_op.py` | fabric-agent's entry point: one directory operation, signed in as the site's agent account (not the system) |
| `directory_ops.py` | The operations fabric-agent may ask for |
| `site_info.py` | Operation `site_info`: a site's OU, id block and its ranges' marks |
| `ensure_site_acl.py` | The site's admins and agent: full control of their site's OU, nothing on its service accounts (Q4); Keycloak: the site's people |
| `ensure_ad_site.py` | The AD site of this fabric site and its subnets from the address plan |
| `set_password_policy.py` | The admin's password policy on the domain object (2.1.6.13) |
| `ensure_gpo.py` | One of fabric's GPOs created, linked, its SYSVOL files written, its version bumped on change |
| `root_ca_policy.py` | The Registry.pol that makes fabric's root CA a trusted root on Windows (Q13) |
| `logon_rights_policy.py` | The GptTmpl.inf granting log-on to a site's machines (2.1.6.14, Q16) |
| `list_people.py` | Operation `list_people`: people and groups under OU=sites (service accounts left out) |
| `create_person.py` | Operation `create_person`: a person in the site's OU=people, a uid from its block, in `<site>-users`, must change their password |
| `get_person.py` | Operation `get_person`: where a person lives and their groups |
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
| `create_machine.py` | Operation `create_machine`: a machine pre-created in the site's OU=machines with a one-time join password |
| `ensure_sudo_rule.py` | The site's default sudo rule: its admins and the admin group may run anything on its machines (2.1.9.13) |
| `windows_baseline_policy.py` | The site's Windows baseline: wait for the network at log-on, the domain's time, Wired AutoConfig and the 802.1X profile (start-up script) |
| `gpo_tool.py` | fabric's ADMX editor's entry point: one operation (load, templates, policies, show, set, clear) as JSON |
| `admx_store.py` | The domain's central store: templates saved, and every policy they define read as Windows' editor reads them |
| `policy_entries.py` | What a policy writes to the registry (enabled with its elements, disabled), and which values are its own |
| `admin_gpo.py` | The site's `fabric: <site> admin settings` GPO: what it sets, and writing it |
| `list_machines.py` | Operation `list_machines`: the site's computer accounts (Windows and Linux) with state and last logon |
| `find_machine.py` | A machine of the site by its name (for set_machine and remove_machine) |
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
| `id_layout.py` | The fixed ranges inside a site's id block (offsets by kind) and whether a block is laid out in them (2.1.6.46) |
| `read_dc_names.py` | The domain's computer names, its DCs apart (a parent refuses a joining site's DC a name in use, 2.1.6.45) |
| `read_sites.py` | Every site in the domain: its name, where its OU sits and its uid/gid block (a parent hands out a free block, and recognises a site moving under it) |
| `site_roles.py` | The five roles that administer a site, each its own group (2.1.9.13) |
| `acl_entries.py` | Access entries added once (compared parsed, object entries by their attribute) and a principal's SID |
| `remove_ipv6_records.py` | The AD zones on IPv4 only (2.1.6.29): every AAAA record removed (the DC listens on IPv4) |
