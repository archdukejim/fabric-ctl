# fabriclib/vault

OpenBao (secrets), a core fabric service, and its **unlock methods** (key
slots). The host talks to OpenBao's API over fabric_net with TLS verified
against the fabric root CA; after the first init it authenticates only
with fabric's own AppRoles (the root token is revoked).

OpenBao uses the static seal with one vault key. The key lives *wrapped* in
one or more unlock methods; **fabric-unlock** (the openbao unit's start
condition) takes it from any present method, puts it in RAM for OpenBao's
start, and it is wiped once OpenBao is unsealed.

| File | What |
|---|---|
| `constants.py` | File names (slot store, iteration-1 key file, AppRole credentials, bootstrap token), KV mounts, the policies (fabric-setup, fabric-agent, fabric-admin, fabric-auditor), OIDC mount / client / role and the bundle → policy map |
| `ensure_vault_key.py` | First unlock method: a random key in a key-file slot, or an iteration-1 key file migrated as-is; never a new key next to an existing vault |
| `unlock_vault.py` | fabric-unlock: key from any present method → RAM (openbao user, 0400); reports a store changed while locked |
| `wipe_runtime_keys.py` | Overwrite and delete the key copies in RAM once OpenBao is unsealed |
| `list_slots.py` | Unlock methods with type, device, presence, key version and what the type was tested against |
| `test_slot.py` | Unwrap the key through one method and verify it (nothing written) |
| `add_kmip_slot.py` | Make an HSM / key manager (KMIP) an unlock method: certificates checked, wrap + unwrap through the device verified, files root-only |
| `add_security_key_slot.py` | Make a PKCS#11 token an unlock method: new (or existing, non-extractable) RSA key on it, wrap + unwrap verified, PIN root-only |
| `list_pkcs11_tokens.py` | Tokens the allowed PKCS#11 libraries see, with PIN state (no login) |
| `add_usb_slot.py` | Erase a whole, unmounted USB disk and make it an unlock method; key read back and verified before saving |
| `write_device_rules.py` | udev kill-switch rules for enrolled sticks / security keys (by UUID / USB serial) |
| `vault_device_event.py` | Kill switch: an enrolled device pulled while it is the only present method → stop OpenBao; plugged back → start it |
| `remove_slot.py` | Remove a method (never the last; a remaining one must vouch), destroying its copy where possible |
| `rotate_vault_key.py` | New key for every present method, the rest dropped; OpenBao moved over with previous → current key rotation |
| `configure_oidc.py` | Sign-in with Keycloak for people: OIDC auth, discovery verified against the fabric CA, one role admitting the bundles in `OIDC_BUNDLE_POLICIES`; each bundle an external group carrying its policy (admin → `fabric-admin`, `fabric-auditor`) |
| `generate_root_token.py` | Break glass: root token from the recovery keys over the root-only socket (one-time pad), audited |
| `init_openbao.py` | Initialise once: recovery keys + initial root token (None if already initialised) |
| `configure_openbao.py` | Converge: AppRole auth, KV v2 `fabric/` + `apps/`, policies, AppRoles bound to fabric_net, their credentials (root 0400) |
| `revoke_token.py` | Revoke a token (the initial root token after bootstrap) and confirm it is dead |
| `vault_status.py` | Reachable, initialised, sealed, version, seal/storage type, unlock-method store state, engines, auth methods, secrets version (no values) |
| `detect_devices.py` | Security keys (by USB vendor + serial), USB disks (model, serial, UUID) and, given the vars, PKCS#11 tokens; read-only |
| `run_vault_command.py` | `fabricctl vault status / slots / test / remove / rotate / add-usb / add-kmip / tokens / add-key / break-glass / revoke-token / unlock / wipe-key / device-event` |
| `slots/` | One file per unlock-method type: `wrap`, `unwrap`, `present`, `forget` and what it was `TESTED` against |
| `common/` | Helpers shared by the operations above (see its README) |
| `ssh/` | OpenBao's SSH certificate authority for the fabric admins: the toggle, signing, the published CA key (manual 1.6.11.9; see its README) |
| `rotate_db_password.py` | Keycloak's database password rotated by OpenBao, saved, Keycloak applied and healthy again; recorded for doctor (`fabricctl vault rotate-db`) |
