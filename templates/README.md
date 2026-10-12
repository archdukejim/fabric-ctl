# templates

Templates rendered by `deploy.py` (and `fabriclib`) from `vars.yaml` into `/opt/<service>/` (systemd units into
`/etc/systemd/system/`). One folder per service. On a host this folder is `jinja/` (manual 1.2.2); the images'
build files are in `packaging/images/` (installed as `jinja/<service>/build/`) and the code that runs inside
containers in `src/containers/`.

| Path | What |
|---|---|
| `vars.yaml.j2` | Every setting with its default; rendered over the admin's `vars.yaml` |
| [bind9/](bind9/) | Authoritative DNS: named.conf parts, zones |
| [fluentbit/](fluentbit/) | Optional log forwarding |
| [resolver/](resolver/) | The DNS filter, a BIND resolver: its container and configuration, the owner's rules, safe search and groups as response policy zones |
| [dnsfilter/](dnsfilter/) | The DNS filter's list matcher, AdGuard Home behind the resolver: its container and `AdGuardHome.yaml` |
| [chrony/](chrony/) | Time on the host (chrony's configuration; not a container) |
| [freeradius/](freeradius/) | Optional 802.1X: config |
| [kea/](kea/) | Optional DHCP: Kea configs |
| [keycloak/](keycloak/) | SSO: compose file |
| [nginx/](nginx/) | Reverse proxy and the static pages: landing, certificates, LDAP guide, manual |
| [openbao/](openbao/) | Secrets: compose file and server config |
| [postgres/](postgres/) | Keycloak's database |
| [samba/](samba/) | The Samba AD domain controller: compose file |
| [stepca/](stepca/) | The CA: compose file, certificate templates |
| [systemd/](systemd/) | The per-service wrapper unit, `fabric.target`, `fabric-agent.service` |
| [webui/](webui/) | Deploying the web UI container: compose file and `webui.json` |
| [webui-app/](webui-app/) | The web UI's own page templates (installed in the app as `lib/webui/templates/`) |
