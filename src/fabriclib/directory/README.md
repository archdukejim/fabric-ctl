# fabriclib/directory

fabric's directory on Samba AD (manual 1.6.3, 1.6.5.16): what fabric-agent, setup and the web UI ask of it. Every
operation runs inside the DC (`src/containers/samba/directory_op.py`), signed in as this site's `fabric-agent`
account, so AD's per-site limits apply to it.

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `run_op.py` | Run one directory operation as the site's agent account; refusals as messages safe to show |
| `list_people.py` | The People page: every person and group (never a password) and the Keycloak console link |
| `create_person.py` | A new person in this site (POSIX identity from its block, `<site>-users`, a one-time password) |
| `reset_sign_in.py` | A new one-time password in AD; TOTP removed and sessions ended in Keycloak (fabric groups: admins only) |
| `set_person_enabled.py` | Disable a person of this site (sign-in refused, sessions ended), or enable them again (audited) |
| `remove_person.py` | Remove a person of this site (the user name typed back): account, Keycloak user, their certificates revoked (audited) |
| `set_person_group.py` | Put a person in a group or take them out (fabric groups: admins only; audited) |
| `run_people_command.py` | `fabricctl people`: routes to the people functions |
| `ensure_admin.py` | Setup's first admin: made once, kept in the web UI's admin group |
| `people_password.py` | A one-time password the domain's policy accepts |
| `constants.py` | Device types, the permission vocabulary (what it grants, what enforces it), name rules, the default device roles |
| `device_overview.py` | Devices (with effective access), roles and the vocabulary from one directory read |
| `list_devices.py` | Devices with their roles, effective permissions and VLAN |
| `list_roles.py` | Device roles by priority, with their member devices |
| `add_device.py` | Add a device naming its roles (audited) |
| `update_device.py` | Change a device's type, MACs, owner, description, enabled flag and roles (audited) |
| `remove_device.py` | Delete a device (audited) |
| `require_device.py` | Refuse unless a device exists (before issuing a certificate for it) |
| `link_device_cert.py` | Record or forget a certificate fingerprint on a device (audited) |
| `add_role.py` | Create a device role: permissions, VLAN, priority (audited) |
| `update_role.py` | Change a role's permissions, VLAN, priority, description (audited) |
| `remove_role.py` | Delete a role — refused while devices are in it (audited) |
| `common/` | Helpers shared by the device and role operations (see its README) |
| `ensure_default_device_roles.py` | Create fabric's default device roles once, in the organisation's `OU=device-roles` (a marker file keeps a deleted one from coming back) |
| `add_machine.py` | A machine pre-created in this site with a one-time join password (`fabricctl domain add-machine`) |
| `sort_machines.py` | Windows machines that joined themselves moved into OU=windows, once each, recorded in config/machines-sorted.json (`fabricctl domain sort-machines`, the fabric-machines timer) |
| `list_machines.py` | This site's machines in the domain (the Directory tab's Machines) |
| `set_machine_enabled.py` | Disable a machine of this site, or enable it again (audited) |
| `remove_machine.py` | Remove a machine of this site from the domain (audited) |
| `place_fabric_host.py` | The fabric host's own account made the site's fabric host: OU=fabric-hosts, <site>-fabric-machines (audited, manual 1.6.11.11) |
| `list_host_groups.py` | This site's host groups (`<site>-hosts-<name>`), their machines and the sudo rules naming each (1.6.11.7) |
| `create_host_group.py` | A new host group in this site's OU=groups (audited) |
| `remove_host_group.py` | Delete a host group, refused while a sudo rule names it (audited) |
| `set_host_group_member.py` | Put one of this site's machines in a host group or take it out; the sudo rules on it follow (audited) |
| `run_machines_command.py` | `fabricctl machines`: routes to the host group functions |
| `list_sudo_rules.py` | This site's sudo rules: fabric's editor's, the site default, admins' own (read-only) |
| `add_sudo_rule.py` | A sudo rule: who, which commands, as whom, on which host group; ALL commands to everyone refused (audited) |
| `remove_sudo_rule.py` | Remove one of fabric's editor-made sudo rules; never the site default or an admin's own (audited) |
| `run_sudo_command.py` | `fabricctl sudo`: routes to the sudo rule functions |
| `is_fabric_admin.py` | Whether a person is a fabric admin (`fabric-admins` or `<site>-fabric-admins`, nested too): who may get an SSH certificate (1.6.11.9) |
