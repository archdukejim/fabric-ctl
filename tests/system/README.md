# tests/system

Pure tests of `fabriclib/system/`, in the `settings` suite.

| File | What |
|---|---|
| `host_ram_gb_test.py` | The host's memory as setup measures it (`system/host_ram_gb`, 1.2.4.2.1): MemTotal rounded with the crash kernel's reservation counted in, so a 4 GB Ubuntu host is 4 (2.3.1.57); a Pi's 3.88 GiB is 4; 0 when MemTotal cannot be read |
