# tests/dns

| File | What |
|---|---|
| `freeze_and_install_test.py` | A zone put in place under a running BIND about to restart (`dns/freeze_and_install`, manual 1.4.1.5, 2.3.1.22): BIND's write after `rndc freeze` answered is waited for, so the new file stays; no wait without a journal newer than the file or for a static zone. rndc stood in for, BIND's late write simulated. In the `zone` suite |
| `zones_bind_lacks_test.py` | The zones a running BIND does not know though fabric has their files (`dns/zones_bind_lacks`, 2.3.10.11.16: a zone list installed by an apply that stopped before `rndc reconfig`): named in one call, journals and stray lines not taken; docker missing, BIND not answering or no zone files name none. docker exec stood in for; the `zones` suite asks a real BIND. In the `zone` suite |
