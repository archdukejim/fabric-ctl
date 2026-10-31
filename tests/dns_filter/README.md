# tests/dns_filter

The DNS filter's units with no container, run with the `zone` suite. Against a real resolver: `tests/zones/run.py`, `tests/resolver/`.

| File | What |
|---|---|
| `flush_published_names_test.py` | The filtering resolver forgets the names fabric published (2.1.10.46): flushname for each (every view), flushtree for a zone flushed whole, nothing with the resolver off or nothing changed; a refusal or a resolver not answering said, never raised |
