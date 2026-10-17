# fabriclib/dns

DNS zones and records as stored in `vars.yaml` (`dns:`), plus TSIG keys
(`tsig_keys`), BIND ACLs (`bind_acls`) and their update policies
(`bind_acl_policies`), used by fabric-agent (web UI), the `fabricctl tsig` /
`fabricctl acl` commands and the `fabricctl --interactive` editor alike. Publishing happens
through apply (`deploy.py`), which reloads only changed zones; a zone added or removed is published in
seconds (`publish_zone_list.py`).

| File | What |
|---|---|
| `constants.py` | Supported record types; the private-use top-level domains (a zone under them hides no public name) |
| `zone_name.py` | Zone key → zone name (`dynamic_zone_var` is the main domain) |
| `validate_record.py` | Build a record dict from user input (one value or the type's own fields), rejecting anything unsafe for a zone file |
| `format_value.py` | Human-readable right-hand side of a record (as rendered in the zone file) |
| `sync_status.py` | Serial BIND is serving vs. the deployed zone file |
| `rndc.py` | Run `rndc` inside the bind9 container (argument list, never a shell) |
| `zone_content_changed.py` | Rendered vs deployed zone file, ignoring the SOA serial |
| `find_changed_zones.py` | The rendered zones whose records changed (the deploy engine installs them) |
| `freeze_and_install.py` | Before BIND restarts: freeze a changed zone, wait for BIND's own write of its journal, then put the new file in place (manual 1.4.1.5) |
| `install_zone_file.py` | Put a zone file in place with a fresh mtime and drop its stale journal; a reverse zone keeps the PTRs DHCP registered |
| `merge_dynamic_records.py` | Kea's PTR and DHCID records from the file being replaced, merged into fabric's regenerated reverse zone (2.1.10.7) |
| `reload_zone.py` | Swap a zone under a running BIND (freeze/thaw, or reload for static zones) until it serves the new serial |
| `list_zones.py` | Zones with record counts (flagging hand-written reverse zones) |
| `ptr_for_ip.py` | Reverse zone and PTR label for an address — or why it gets none (public, loopback, link-local) |
| `reverse_zones.py` | Reverse zones + PTRs generated from all forward A/AAAA records (one per address); used by apply and the web UI |
| `zone_detail.py` | One zone's records (A/AAAA with their automatic PTR, fabric's own names marked, landing links) and sync status (`docker exec … rndc zonestatus`) |
| `add_record.py` | Validate and add a record (locked, audited) |
| `remove_record.py` | Remove a record, refusing if it changed since it was shown or is one of fabric's own names (locked, audited) |
| `set_record_link.py` | Link a record of the site's zone from the landing page, or stop linking it (locked, audited) |
| `add_zone.py` | Add a forward zone, refusing names BIND already answers for and public names not ticked as hidden; served in seconds (locked, audited, rolled back if BIND or the resolver refuses) |
| `remove_zone.py` | Remove a forward zone with its records once its name is typed again; refused while a TSIG key or ACL policy names it (locked, audited, rolled back if BIND or the resolver refuses) |
| `publish_zone_list.py` | The quick path for a zone change: BIND's configuration and the new zone files rendered, `rndc reconfig`, then the resolver's configuration rendered and reloaded |
| `normalize_tsig_keys.py` | Validate `tsig_keys`, fill defaults, take embedded secrets out (they belong in fabric's secrets: `fabric-secrets.yml` or OpenBao) |
| `add_tsig_key.py` | Add a TSIG key (new or existing secret) to vars + secrets (locked, audited) |
| `remove_tsig_key.py` | Remove a TSIG key, its secret, its `key` entries in every ACL and the `rfc2136.ini` fabric wrote for it (locked, audited) |
| `list_tsig_keys.py` | TSIG keys with their effective update rights (own + ACL policies) and ACLs |
| `replace_tsig_secret.py` | Give a key a secret you supply, or a newly generated one (locked, audited) |
| `update_tsig_key.py` | Change what a key may update: records, any name, types, zone, algorithm, `rfc2136.ini` path; secret untouched (locked, audited) |
| `rfc2136_settings.py` | The `rfc2136.ini` text a certbot-style client needs for one key (used by apply and the web UI) |
| `create_zone_tsig_key.py` | Web UI: a new key limited to one forward zone and one scope (listed hosts' ACME, zone ACME, any name + types) |
| `rotate_tsig_key.py` | Web UI: new generated secret for a key, returned with its `rfc2136.ini` text |
| `run_tsig_command.py` | `fabricctl tsig list/add/update/set-secret/rotate/remove` (applies after a change) |
| `set_key_acls.py` | Put a TSIG key in ACLs or take it out (of all, when the key is removed); keeps the key's own `acls` in step (locked, audited) |
| `builtin_acls.py` | The ACLs fabric always renders (protected from removal) |
| `add_acl_entries.py` | Create a BIND ACL or add validated entries (IP, CIDR, `key <tsig>`, ACL, built-ins, `!`) (locked, audited) |
| `remove_acl_entries.py` | Remove ACL entries or a whole ACL and its policy (built-ins protected; locked, audited) |
| `normalize_acl_policies.py` | Validate ACL update policies (hosts or any name, record types, zone) |
| `set_acl_policy.py` | Set or clear the update policy every TSIG key in an ACL inherits (locked, audited) |
| `run_acl_command.py` | `fabricctl acl list/add/remove/policy` (applies after a change) |
| `common/` | Helpers shared by these files |
