# packaging/images

One folder per image fabric builds; each is a build context (`Dockerfile` and what it copies). On a host they are
installed as `jinja/<service>/build/`; CI builds and publishes them from the same folders (decision 2.1.1.21, manual
3.14.1).

| Path | What |
|---|---|
| [bind9/](bind9/) | BIND 9 from Debian packages |
| [freeradius/](freeradius/) | FreeRADIUS |
| [kea/](kea/) | Kea DHCP 3.0 from ISC's repository (decision 2.1.1.5) |
| [keycloak/](keycloak/) | Keycloak's optimized build |
| [samba/](samba/) | Samba AD domain controller from Debian packages |
| [stepca/](stepca/) | Step-CA |
| [webui/](webui/) | The fabric-ctl web UI |
| `stage-contexts.sh` | Stages the nine build contexts exactly as a host has them, for `../docker-bake.hcl` |
| `bake_env.py` | Prints the build inputs (pinned bases, Kea's pinned package) from `config/images.lock.yaml` |
| `smoke-test.sh` | Runs one built image's program under fabric's settings and checks its labels, before publishing |
