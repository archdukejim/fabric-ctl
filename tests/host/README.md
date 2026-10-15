# tests/host

End-to-end test on a real host over SSH (e.g. the reference Raspberry Pi), installing from the `.deb`. **It installs fabric on that host** — use a disposable machine.

| File | What |
|---|---|
| `run.sh` | Package install, setup, doctor, `fabric.target`, certificate page, RFC2136, restricted sign-in, login kit permissions, re-run, stop/start, no secret in any process's argv, `apt purge` with `CLEANUP=1` (reuses the check scripts in `tests/sandbox/`) |
| `reset_user.py` | Put a directory user back to first sign-in (password, no TOTP, new password required) so the suite also runs on a host that was used before |
| `upgrade.sh` | Upgrade in place from the floor, 0.7.1 until 1.0 (2.1.1.55), or the previous release (2.1.1.36): the host wiped, release `FROM` installed from its GitHub release and set up, state seeded and snapshotted, the candidate installed from fabric's apt repository (`TO_SUITE`) and set up, the snapshot compared, doctor and status |
| `upgrade_state.py` | Seeds and snapshots what an upgrade must keep: a person and the admin (identity and password version), a DNS record on the landing page, a device certificate (still valid against the CA), the root CA, fabric's secrets (hashed), a rule added in 0.6's AdGuard UI (a blocked name of the resolver after 0.7), the sign-in layers |
| `installer.py` | The interactive installer through a real terminal on a test host: every question given answers it must refuse (each refusal checked by its message), the firewall declined with ufw on (setup stops before any step, 2.1.2.12), then a full install with everything allowed, doctor, the domain on IPv4 only (2.1.6.29), the landing page at the host's name, the host's own ufw rules kept |
