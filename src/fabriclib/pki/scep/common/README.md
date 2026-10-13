# fabriclib/pki/scep/common

Helpers shared by device enrolment (manual 1.5.3).

| File | What |
|---|---|
| `challenge_lock.py` | An exclusive lock around the challenge store's read-modify-write (the agent and the hook) |
| `read_challenges.py` | The challenge store (hashes only); a damaged one refuses, never reads as empty |
| `write_challenges.py` | Save it atomically, root-only, without challenges finished long ago |
| `hash_challenge.py` | A challenge's SHA-256, what the store keeps |
| `enrol_inputs.py` | The name and device both kinds of enrolment are asked for, checked |
| `__init__.py` | Package marker (empty) |
