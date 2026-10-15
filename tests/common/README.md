# tests/common

| File | What |
|---|---|
| `ask.py` | `fabriclib/common/ask.py` (manual 1.1.5.6), run with the `consent` suite, no containers: the answer stripped and the prompt shown as given, an empty answer with and without a default, a secret as typed; EOF and Ctrl-C reach the caller as from `input()` / `getpass()`; a malformed question ID refused before anything is asked |
| `save_vars_test.py` | `fabriclib/common/save_vars.py`, run with the `consent` suite, no containers: written with empty strings as null; the old file's mode kept; no temporary file left; a reader without the lock never sees an empty or partial file; a write failing half way leaves the old file whole |
| `kea_image.py` | Not a test: `build_kea_image()`, the tests' own Kea image (`fabric/kea:test`) built from `packaging/images/kea` with the versions `config/` pins, for `tests/kea/run.py`, `scan.py`, `relay.py` and `tests/samba/ipam_two_site.py`; a fingerprint of its own for the build's refusal |
