# templates/resolver/config

Rendered into `<base>/resolver/config` by `dns_filter/deploy_resolver` (manual [1.12.2](../../../docs/volume_1_description_and_architecture/1.12.2-bind-resolver.md#11225-the-main-view)).

| File | What |
|---|---|
| `named.conf.j2` | The resolver: clients allowed, DoT and DoH listeners for clients (once the certificate exists), each view forwarding to AdGuard Home (a group's over DoT naming it, manual 1.12.3.6), fabric's zones forwarded to the authoritative BIND in every view, the response policy order, the query, response and RPZ logs |
| `fabric.rpz.j2` | Passthru for fabric's own zones: first, so they are never filtered |
| `owner.rpz.j2` | The owner's allows and blocks (`dns_filter_allow`, `dns_filter_block`) |
| `rules.rpz.j2` | A client group's allows and blocks (`group-<name>.rpz`, manual 1.12.2.15) |
| `safesearch.rpz.j2` | Strict safe search, every engine of fabric's table, YouTube strict or moderate (`safesearch-strict.rpz`, `safesearch-ytmoderate.rpz`) |
| `rndc.key.j2` | The resolver's own control key (`resolver_rndc_secret`) |
