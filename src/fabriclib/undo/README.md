# fabriclib/undo

Reverting a host change fabric made (design [1.2.9.5](../../../docs/volume_1_description_and_architecture/1.2.9-host-consent.md#1295-upgrades)):
`fabricctl setup --undo GROUP`, and what `fabricctl uninstall` does with each kind of change. The host's own files
are kept before fabric first changes them (`common/keep_original`).

| File | What |
|---|---|
| `undo_runtime.py` | Docker's `daemon.json` as it was (or without a copy: only fabric's values removed), Docker restarted |
| `undo_firewall.py` | fabric's ufw rules, DOCKER-USER rules and `fabric-firewall.service` removed; ufw off again if it was off |
| `undo_trust.py` | fabric's CA out of the host trust store |
| `undo_time.py` | chrony's files as they were, chrony restarted |
| `undo_resolver.py` | systemd-resolved's stub listener and `/etc/resolv.conf` back |
| `undo_member.py` | This host out of its domain: krb5.conf, sssd.conf, nsswitch.conf and `/etc/hosts` as they were, the keytab removed, sss off in PAM, sssd stopped if fabric started it |
| `undo_group.py` | `fabricctl setup --undo GROUP`: says what it will do, asks, undoes, records the group as declined |
| `uninstall_plan.py` | What uninstall does with each kind of host change: removed, undone or kept |
