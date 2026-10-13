# src

All of fabric's code (global Rule 7.1). The installed tree on a host is assembled from here by
`packaging/deb/assemble-tree.sh` and does not follow this layout (manual 1.2.2).

| Path | What |
|---|---|
| [fabriclib/](fabriclib/) | fabric's Python library, one operation per file, grouped by domain (imported as `fabriclib.<domain>.<file>`); `fabriclib/cli.py` routes the `fabricctl` subcommands |
| [agent/](agent/) | `fabric-agent`: the root daemon behind the web UI — a fixed, permission-checked JSON API over a unix socket |
| [federation/](federation/) | `fabric-federation`: the federation endpoint sites join through (behind nginx, unix socket) |
| [scephook/](scephook/) | `fabric-scep-hook`: Step-CA's SCEP webhooks, one-time challenges and issued certificates (behind nginx, unix socket; manual 1.5.3) |
| [webui/](webui/) | The fabric-ctl web UI's package (decision 2.1.1.30: its name is kept) |
| [ux/](ux/) | The entry points of the two ways people reach fabric: the CLI and the web UI (decision 2.1.1.9) |
| [containers/](containers/) | Code that runs inside service containers (mounted at run time) |
