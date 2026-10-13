# tests/common

| File | What |
|---|---|
| `ask.py` | `fabriclib/common/ask.py` (manual 1.1.5.6), run with the `consent` suite, no containers: the answer stripped and the prompt shown as given, an empty answer with and without a default, a secret as typed; EOF and Ctrl-C reach the caller as from `input()` / `getpass()`; a malformed question ID refused before anything is asked |
