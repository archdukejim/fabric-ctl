# packaging/deb

The Debian package: turns the repository into an installable `fabricctl` .deb whose installed tree does not
depend on the repository's layout (decision 2.1.2.5).

| File | What |
|---|---|
| `assemble-tree.sh` | Assemble the installed tree from the repository (the one place that knows the mapping; tests use it too) |
| `build-deb.sh` | Build `dist/fabricctl_<version>_all.deb` from this checkout (one package for amd64 and arm64) |
| `control.in` | Package metadata; `@VERSION@` is filled in by `build-deb.sh` |
| `postinst` | Prints the next step; never starts services or touches the network |
| `postrm` | `remove`: leaves the install running and untouched; `purge`: export to `/var/backups/fabric/`, then uninstall |

Repository → host:

| Repository | On the host |
|---|---|
| `src/fabriclib/`, `src/agent/`, `src/federation/`, `src/scephook/`, the CLI's scripts in `src/ux/cli/` | `/usr/lib/fabricctl/fabric/lib/` |
| `src/webui/`, `src/ux/web/`, `templates/webui-app/`, `static/webui-app/` | `/usr/lib/fabricctl/fabric/lib/webui/` |
| `templates/` (the service templates), `src/containers/`, `static/vendor/`, `static/nginx/` | `/usr/lib/fabricctl/fabric/jinja/` |
| `packaging/images/<service>/` | `/usr/lib/fabricctl/fabric/jinja/<service>/build/` |
| `config/` | `/usr/lib/fabricctl/fabric/` |
| `docs/`, `LICENSE`, `README.md` | `/usr/lib/fabricctl/` |
| `examples/vars.yaml` | `/usr/share/doc/fabricctl/examples/vars.yaml` |
| `src/ux/cli/fabricctl` | `/usr/bin/fabricctl` |

`fabricctl setup` then copies `/usr/lib/fabricctl/fabric` to `/opt/fabric` (the
install) and creates `/opt/<service>`, the systemd units and `fabric.target`.
The installed layout did not change when the repository was split (2.1.1.7) or
moved to the Rule 7 layout (manual 2.3.2.1), so existing installs upgrade in place.
The CLI command is `src/ux/cli/fabricctl`; installing from a checkout is
`scripts/install-from-checkout.sh`.

Upgrade: install the newer `.deb`, then `sudo fabricctl setup` (every other
command warns until you do). To remove fabric use `sudo fabricctl uninstall`:
it offers to export all data to a folder you choose and to purge the package.
`sudo apt remove fabricctl` removes only the tool (fabric keeps running);
`sudo apt purge fabricctl` removes fabric too, after exporting its data to
`/var/backups/fabric/` because apt cannot ask where.
