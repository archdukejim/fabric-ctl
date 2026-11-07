# tests/speed

| File | What |
|---|---|
| `read_cache.py` | In the `settings` suite, no container: the read cache's rules and store (1.8.9, 2.1.8.43 to 2.1.8.45) |
| `run.py` | In the `settings` suite, no container: what a process keeps between requests (the settings, the secrets in fabric-agent, a certificate's dates) and which build the host's services run are read again when it changes, and the caller's copy is its own (1.8.8.2, 2.1.8.35, 2.1.1.83) |
