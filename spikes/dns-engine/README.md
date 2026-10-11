# spikes/dns-engine

The spike for 0.7.5's open question (decision 2.1.1.49, manual 2.3.1.18): which engine matches the DNS filter's
lists. Throwaway (global Rule 4); its findings are recorded in the manual, 2.3.1.18.

| File | What |
|---|---|
| `run.sh` | A: BIND in front (views, the owner's rules, fabric's zone, dnstap) forwarding to AdGuard Home, set up and fed only through its API; B: BIND alone with the same lists merged. Memory, load, adding and toggling a list, answer times, restarts |
| `adguard.py` | AdGuard Home's API as fabric-agent would drive it: first-run setup, its query log and statistics off, upstreams, a group as a client, rules, lists |
| `merge.py` | The lists through fabric's converter, merged into one deduplicated response policy zone |

```bash
KEEP=1 bash spikes/dns-engine/run.sh
```

Work folder: `~/fabric-spike-dns/engine` (the lists, configs, AdGuard's data; its generated password in `ag.pw`,
mode 0600). Needs Docker and internet access (the lists, Cloudflare).
