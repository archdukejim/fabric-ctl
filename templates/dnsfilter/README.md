# templates/dnsfilter

The DNS filter's list matcher, AdGuard Home behind the BIND resolver (manual
[1.12.3](../../docs/volume_1_description_and_architecture/1.12.3-adguard-behind-bind.md#11231-status)).

| File | What |
|---|---|
| `docker-compose.yml.j2` | The `adguard-filter` container: AdGuard Home's own image (pinned), its own account, on `fabric_net` only (nothing published), every capability dropped but `NET_BIND_SERVICE` in the bounding set, port 53 from `ip_unprivileged_port_start`, fabric's list copies read-only |
| `AdGuardHome.yaml.j2` | Its configuration, rendered by `dns_filter/deploy_adguard`: fabric-agent's account, the upstreams, NXDOMAIN for a block, its own query log and statistics off, the lists as files, the groups as clients by ClientID, DoT for the groups once the certificate exists |
