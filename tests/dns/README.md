# tests/dns

| File | What |
|---|---|
| `freeze_and_install_test.py` | A zone put in place under a running BIND about to restart (`dns/freeze_and_install`, manual 1.4.1.5, 2.3.1.23): BIND's write after `rndc freeze` answered is waited for, so the new file stays; no wait without a journal newer than the file or for a static zone. rndc stood in for, BIND's late write simulated. In the `zone` suite |
