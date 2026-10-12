# templates/resolver

The DNS filter's BIND resolver (manual [1.12.2](../../docs/volume_1_description_and_architecture/1.12.2-bind-resolver.md#11221-status)).

| File | What |
|---|---|
| `docker-compose.yml.j2` | The `bind9-resolver` container: fabric's bind9 image, its own account, `host_ip:53` and `host_ip:853` (DoT), the DNS name's certificate, no capabilities; it forwards to AdGuard Home ([dnsfilter/](../dnsfilter/)) |
| `config/` | Its configuration, rendered by `dns_filter/deploy_resolver` |
