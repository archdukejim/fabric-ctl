# src/webui/agentclient

The fabric-agent API client: one file per agent route (JSON over the agent's unix socket, the person's ID token per thread); `from webui import agentclient as actions` imports them all.

| File | What |
|---|---|
| `add_radius_client.py` | Add a RADIUS client (switch or access point); saved and applied at once. Agent route: POST /v1/radius/clients (radius:admin), timeout 960 s. |
| `add_record.py` | Add one DNS record to a zone in vars.yaml (published by the next apply). Agent route: POST /v1/zones/<key>/records (dns:write). |
| `add_zone.py` | Add a forward zone; BIND and the DNS filter serve it within seconds. Agent route: POST /v1/zones (dns:write), timeout 960 s. |
| `remove_zone.py` | Remove a forward zone with its records (its name typed again). Agent route: POST /v1/zones/<key>/delete (dns:write), timeout 960 s. |
| `add_reservation.py` | Reserve an IP for a MAC; the agent saves it and applies at once (Kea reloads with it). Agent route: POST /v1/dhcp/reservations (dhcp:write), timeout 960 s. |
| `set_dhcp_on.py` | Turn DHCP on or off; saved, applied, the host firewall brought in line |
| `add_subnet.py` | Add a DHCP subnet (name, VLAN record, router, pools, notes); saved and applied |
| `update_subnet.py` | Change a DHCP subnet's name, VLAN, router, notes or pools |
| `remove_subnet.py` | Remove a DHCP subnet (refused with active leases unless forced) |
| `set_option.py` | Set a DHCP option for every subnet, a subnet, a client class or a reservation |
| `unset_option.py` | Remove a DHCP option the admin set |
| `add_client_class.py` | Add a DHCP client class (Kea expression, network-boot fields) |
| `remove_client_class.py` | Remove a DHCP client class |
| `scannable_subnets.py` | The subnets the console may scan (this site's DHCP subnets, at most a /22). Agent route: GET /v1/ipam/scan (dhcp:read). |
| `scan_subnet.py` | Scan one subnet now: what answers, what nobody recorded. Agent route: POST /v1/ipam/scan (dhcp:write), timeout 180 s. |
| `record_found_address.py` | Record an address a scan found: a reservation for its MAC, or a static address; applied at once. Agent route: POST /v1/ipam/scan/record (dhcp:write), timeout 300 s. |
| `apply_changes.py` | Render and apply the configuration (as `fabricctl --apply`) on the host. Agent route: POST /v1/apply (dns:write), timeout 960 s. |
| `audit.py` | Write a login event to the audit log, best effort so an agent outage never blocks a denial. Agent route: POST /v1/events (session). |
| `ca_summary.py` | The CA certificates, where devices fetch them, and the signing limits, for the Step-CA page. Agent route: GET /v1/pki/ca (pki:read). |
| `host_changes.py` | What fabric may change on this host, by group (approved, declined with what that leaves unmanaged). Agent route: GET /v1/host-changes (status:read). |
| `connection.py` | Make every later agent call from this thread carry `token`, which fabric-agent verifies and checks permissions against. |
| `constants.py` | (constants) |
| `convert_cert.py` | Re-package a certificate (and optional key) into other formats. Agent route: POST /v1/pki/convert (pki:issue). |
| `create_person.py` | Create a person in Keycloak with a one-time password. Agent route: POST /v1/people (people:create). |
| `create_tsig_key.py` | Create a TSIG key allowed to update part of a zone (published by the next apply). Agent route: POST /v1/tsig (tsig:manage). |
| `delete_device.py` | Delete a device and take it out of every role. Agent route: POST /v1/devices/<name>/delete (devices:admin). |
| `set_record_link.py` | Link a record of the site's zone from the landing page, or stop linking it. Agent route: POST /v1/zones/<key>/records/link (dns:write). |
| `set_password_policy.py` | Change the domain's password policy (checked as the command checks it). Agent route: POST /v1/domain/password-policy (domain:admin). |
| `delete_record.py` | Remove one DNS record from a zone, only if it is still the record the page showed. Agent route: POST /v1/zones/<key>/records/delete (dns:write). |
| `delete_role.py` | Delete a device role. Agent route: POST /v1/roles/<name>/delete (roles:admin). |
| `delete_tsig_key.py` | Remove a TSIG key (published by the next apply). Agent route: POST /v1/tsig/<name>/delete (tsig:manage). |
| `describe_csr.py` | Decode an uploaded CSR and judge it before signing (the review step). Agent route: POST /v1/pki/describe-csr (pki:read). |
| `device_overview.py` | Devices, roles and the RBAC vocabulary from one directory read. Agent route: GET /v1/devices (devices:read). |
| `dns_filter_change.py` | Change the DNS filter: lists, rules, upstreams (saved and applied), or start the lists job. Agent routes: POST /v1/dns-filter/... (dns:filter). |
| `dns_filter_overview.py` | What the DNS filter tab shows. Agent route: GET /v1/dns-filter (dns:filter). |
| `dhcp_overview.py` | What the Kea (DHCP) page shows, read-only. Agent route: GET /v1/dhcp (dhcp:read). |
| `option_sets.py` | What the DHCP options page shows: the option sets, presets, a target's effective options. Agent route: GET /v1/ipam/options/<site>[/<target>] (dhcp:read). |
| `option_change.py` | One change of the DHCP options page: options, classes, definitions, netboot, which sites edit the organisation's. Agent routes: POST /v1/ipam/... (dhcp:write; the organisation's dhcp:org-options). |
| `errors.py` | The agent rejected the input (HTTP 400); message is safe to show. |
| `inspect_pem.py` | Decode certificates or a CSR for reading, with a trust verdict. Agent route: POST /v1/pki/inspect (pki:read). |
| `issue_key_pair.py` | Generate a private key and certificate for a device that cannot make its own CSR. Agent route: POST /v1/pki/issue (pki:issue), timeout 180 s. |
| `link_device_cert.py` | Record or forget a certificate fingerprint on a device. Agent route: POST /v1/devices/<name>/certs (pki:link-device). |
| `list_issued.py` | Certificates issued by hand, for the Step-CA 'issued' view. Agent route: GET /v1/pki/issued (pki:read). |
| `list_people.py` | People and their groups (read-only; managed in Keycloak). Agent route: GET /v1/people (people:read). |
| `list_tsig_keys.py` | The TSIG keys and their update rights (never their secrets). Agent route: GET /v1/tsig (dns:read). |
| `list_zones.py` | The DNS zones for the BIND page's zone list. Agent route: GET /v1/zones (dns:read). |
| `map_radius_group.py` | Let members of a directory group join the network by password; saved and applied at once. Agent route: POST /v1/radius/people (radius:admin), timeout 960 s. |
| `quote_segment.py` | URL-quote one path segment with nothing kept safe ("/" becomes %2F), so a name cannot change the route. |
| `radius_guides.py` | The FreeRADIUS setup guides and Windows scripts, filled in for this host (public data only). Agent route: GET /v1/radius/guides (radius:read). |
| `radius_overview.py` | What the FreeRADIUS page shows: on/off, clients, password groups, recent decisions. Agent route: GET /v1/radius (radius:read). |
| `radius_sessions.py` | The open 802.1X sessions (from accounting) and what can be done to each. Agent route: GET /v1/radius/sessions (radius:read). |
| `set_radius_client.py` | Change a RADIUS client's vendor or transport; saved and applied at once. Agent route: POST /v1/radius/clients/<name>/set (radius:admin), timeout 960 s. |
| `coa_session.py` | Disconnect a session or make it authenticate again (CoA), sent at once. Agent routes: POST /v1/radius/sessions/disconnect, /reauthenticate (radius:coa), timeout 30 s. |
| `query_log.py` | Search the DNS query log. Agent route: POST /v1/dns-filter/querylog (dns:querylog). |
| `read_audit.py` | Recent audit-log lines for the Audit page. Agent route: GET /v1/audit (audit:read). |
| `remove_radius_client.py` | Remove a RADIUS client; saved and applied at once. Agent route: POST /v1/radius/clients/<name>/delete (radius:admin), timeout 960 s. |
| `remove_reservation.py` | Remove a DHCP reservation and apply at once. Agent route: POST /v1/dhcp/reservations/<mac>/delete (dhcp:write), timeout 960 s. |
| `reset_sign_in.py` | Reset a person's sign-in: new one-time password, TOTP removed, sessions ended. Agent route: POST /v1/people/<uid>/reset (people:reset). |
| `person_action.py` | Disable, enable or remove a person, or change their groups. Agent routes: POST /v1/people/<uid>/disable\|enable (people:disable), /delete (people:remove), /groups (people:groups). |
| `reverse_zones.py` | The reverse (PTR) zones apply generates from the A/AAAA records. Agent route: GET /v1/reverse-zones (dns:read). |
| `rotate_radius_secret.py` | Give a RADIUS client a new shared secret; saved and applied at once. Agent route: POST /v1/radius/clients/<name>/rotate (radius:admin), timeout 960 s. |
| `rotate_tsig_key.py` | Give a TSIG key a new secret. Agent route: POST /v1/tsig/<name>/rotate (tsig:manage). |
| `save_device.py` | Create a device, or replace an existing device's fields. Agent route: POST /v1/devices (devices:enroll) when new, else POST /v1/devices/<name> (devices:admin). |
| `save_role.py` | Create a device role, or replace an existing role's fields. Agent route: POST /v1/roles when new, else POST /v1/roles/<name> (roles:admin). |
| `service_status.py` | The state of every fabric service, for the overview page. Agent route: GET /v1/services (status:read). |
| `sign_csr.py` | Sign a device's CSR with the fabric CA. Agent route: POST /v1/pki/sign (pki:sign), timeout 120 s. |
| `unmap_radius_group.py` | Stop a group's members joining by password; saved and applied at once. Agent route: POST /v1/radius/people/<group>/delete (radius:admin), timeout 960 s. |
| `vault_add_kmip.py` | Add a KMIP HSM/KMS as an unlock method. Agent route: POST /v1/vault/slots/add-hsm (vault:unlock), timeout 120 s. |
| `vault_add_security_key.py` | Add a PKCS#11 security key (e.g. a YubiKey) as an unlock method. Agent route: POST /v1/vault/slots/add-security-key (vault:unlock), timeout 120 s. |
| `vault_add_usb.py` | Add a USB stick as an unlock method. Agent route: POST /v1/vault/slots/add-usb (vault:unlock), timeout 180 s. |
| `vault_devices.py` | Unlock-capable devices plugged into the host, for the add-method forms. Agent route: GET /v1/vault/devices (vault:status). |
| `vault_rotate.py` | Make a new vault key and give it to every unlock method whose device is present. Agent route: POST /v1/vault/rotate (vault:unlock), timeout 900 s. |
| `vault_slot_action.py` | Test or remove one unlock method. Agent route: POST /v1/vault/slots/<id>/<op> (vault:unlock), timeout 120 s. |
| `vault_slots.py` | The vault's unlock methods and this host's name (typed to confirm changes). Agent route: GET /v1/vault/slots (vault:status). |
| `vault_status.py` | OpenBao at a glance for the OpenBao page; never secrets. Agent route: GET /v1/vault (vault:status). |
| `version_info.py` | The fabric version and build shown in every page's header. Agent route: GET /v1/version (permission: session). |
| `zone_detail.py` | One zone's records and BIND sync status, for the forward-zone view. Agent route: GET /v1/zones/<key> (dns:read). |
| `revoke_cert.py` | Revoke a certificate fabric issued; the CRLs are published at once. Agent route: POST /v1/pki/revoke (pki:revoke). |
| `cert_warnings.py` | What is wrong or coming with fabric's certificates, shown at the top of the overview. Agent route: GET /v1/cert-warnings (status:read). |
| `relaxed_settings.py` | The security relaxations turned on, shown at the top of the overview. Agent route: GET /v1/relaxed-settings (status:read). |
| `__init__.py` | Imports every function of this folder, so callers keep `module.function` |
| `domain_overview.py` | The domain, its controller, the password policy and this site's machines. Agent route: GET /v1/domain (domain:read). |
| `gpo_overview.py` | Group Policy: templates, the admin settings GPO, a policy search. Agent routes: GET /v1/gpo, POST /v1/gpo/search (domain:read). |
| `gpo_change.py` | Set or clear a policy in the admin settings GPO. Agent routes: POST /v1/gpo/set, /v1/gpo/clear (gpo:admin). |
| `add_machine.py` | Pre-create a machine with a one-time join password. Agent route: POST /v1/machines (machines:admin). |
| `machine_action.py` | Enable, disable or remove a machine. Agent route: POST /v1/machines/<name>/<action> (machines:admin). |
| `logon_overview.py` | Who may sign in to the site's machines, per OU. Agent route: GET /v1/domain/logon (domain:read). |
| `logon_change.py` | Set or clear one OU's log-on policy (saved and applied). Agent routes: POST /v1/domain/logon/set, /v1/domain/logon/clear (gpo:admin). |
| `list_host_groups.py` | The site's host groups, their machines and the sudo rules on each. Agent route: GET /v1/host-groups (domain:read). |
| `host_group_change.py` | Create or delete a host group, put a machine in or take it out. Agent routes: POST /v1/host-groups, /v1/host-groups/<name>/delete, /v1/host-groups/<name>/members (machines:admin). |
| `list_sudo_rules.py` | The site's sudo rules, each fabric's, the default or an admin's own. Agent route: GET /v1/sudo (domain:read). |
| `sudo_rule_change.py` | Add a sudo rule or remove one of fabric's. Agent routes: POST /v1/sudo, /v1/sudo/<name>/delete (sudo:admin). |
| `federation_overview.py` | The federation's sites, replication, conflicts, limits and address plan. Agent route: GET /v1/federation (federation:read). |
| `security_layers.py` | GET /v1/security: the sign-in layers |
| `raise_signin_layer.py` | POST /v1/security/raise or /kerberos |
| `image_rows.py` | Each service's image: running, validated, update available. Agent route: GET /v1/images (status:read). |
| `start_job.py` | Start a background job: doctor, or one service's image update or rollback. Agent routes: POST /v1/jobs/doctor (status:read), /v1/jobs/images (images:update). |
| `read_job.py` | A job the signed-in person started. Agent route: GET /v1/jobs/<id>. |
| `acme_overview.py` | ACME for LAN machines: the directory and how, the machines enrolled for DNS-01. Agent route: GET /v1/pki/acme (pki:read). |
| `networks_overview.py` | What the Networks tab shows of one site (VLANs, subnet maps, address table, options and their sources). Agent route: GET /v1/networks[/<site>] (dhcp:read). |
| `networks_export.py` | A site's address table as CSV. Agent route: GET /v1/networks/<site>/export (dhcp:read). |
| `networks_change.py` | One change to a site's address plan (number, VLANs, subnets, ranges, addresses); this site's applied at once. Agent routes: POST /v1/networks/<site>/... (dhcp:write), timeout 300 s. |
