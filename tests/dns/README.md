# tests/dns

| File | What |
|---|---|
| `freeze_and_install_test.py` | A zone put in place under a running BIND about to restart (`dns/freeze_and_install`, manual 1.4.1.5, 2.3.1.22): BIND's write after `rndc freeze` answered is waited for, so the new file stays; no wait without a journal newer than the file or for a static zone. rndc stood in for, BIND's late write simulated. In the `zone` suite |
| `set_negative_ttl_test.py` | The DHCP subzone, which fabric does not render again, given the 30 s negative-caching TTL of 2.1.4.9 (`dns/set_negative_ttl`): frozen, the SOA's minimum set and serial raised in fabric's one-line form and BIND's own, thawed; left alone when it has it; with BIND down only without a journal newer than the file; a refused thaw or an unreadable SOA said. rndc stood in for; the `kea` suite asks a real BIND. In the `zone` suite |
| `changed_names_test.py` | The names an apply or Sync now changes (`dns/changed_names`, 2.1.10.46): added, changed and removed named, the serial not; a new zone or a zone of many changes flushed whole. In the `zone` suite |
