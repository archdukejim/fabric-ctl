# fabriclib/vault/ssh

OpenBao's SSH certificate authority for the fabric admins (manual 1.6.11.9; decisions 2.1.7.5, 2.1.6.39, 2.1.7.12):
off by default, turned on in the web console, 8-hour user certificates with the person's user name as the one
principal, trusted by managed machines through the published CA key; and host certificates from a host CA of their own
(1.6.11.9.6 to 1.6.11.9.11; decision 2.1.7.13): 30 days, for the keys each managed machine publishes on its computer
account, trusted by clients through `@cert-authority` lines.

| File | What |
|---|---|
| `constants.py` | The engine's mount, the signing role and its settings, the lifetime, the published file, the key types signed |
| `set_ssh_certificates.py` | The console's toggle: OpenBao converged, the setting saved, the CA key published or withdrawn, audited |
| `converge_ssh_ca.py` | OpenBao to the setting: on (engine, CA key once, role) or off (role deleted; CA kept) |
| `publish_ssh_ca.py` | The CA's public key at `/certs/ssh-user-ca.pub`, or removed (machines then stop trusting it) |
| `sign_ssh_key.py` | An 8-hour certificate for a fabric admin's public key; everyone else refused and audited |
| `ssh_overview.py` | The SSH page: on or off, the CA key and fingerprint, whether this person may sign and which sites the certificate names (2.1.7.14) |
| `org_ssh_trust.py` | What a site's machines trust from the organisation's CAs: every site's host CA for its names, the user CAs of this site and the writable-DC sites (2.1.7.14) |
| `signable_sites.py` | Which of a person's SSH sites this site's user CA signs for: itself and the sites below it (2.1.7.14, revised) |
| `parse_ssh_key.py` | Read and judge one OpenSSH public key (Ed25519, ECDSA, RSA of 3072 bits and more) |
| `bao_call.py` | One OpenBao call of the SSH engines that must succeed; a refusal of setup's policy says to run the vault step |
| `converge_ssh_host_ca.py` | OpenBao's host CA to the setting: on (engine `ssh-host/`, CA key once, role `fabric-host`) or off (role deleted; CA kept) |
| `host_principals.py` | A machine's certificate names from its account name: short, `.<ad_domain>`, `.<domain>` |
| `parse_ssh_cert.py` | Read one OpenSSH certificate: kind, certified key, principals, validity, signing CA |
| `plan_host_certs.py` | Which of a machine's host keys need signing, which certificates are kept (30 days, renewed with 10 left) |
| `sign_ssh_host_key.py` | One host certificate from the host CA for the principals fabric chose |
| `sign_ssh_hosts.py` | One run of `fabric-ssh-hosts.timer`: prepare, sign, write back, withdraw; this host's own applied |
| `apply_host_ssh_cert.py` | The fabric host's own host certificates and its trust of the host CA (`sshd -t` before and after) |
| `known_hosts_block.py` | fabric's `@cert-authority` lines for the domain's names and short names, and `@revoked` lines |
| `update_revoked_keys.py` | The host keys clients must refuse: withdrawn or replaced certificates' keys until their end, cleared when signed again |
| `ssh_hosts_overview.py` | The SSH page's host certificates: the host CA, each machine's state |
| `__init__.py` | Package marker (empty) |
