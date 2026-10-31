# tests/setup/common

Pure tests of `fabriclib/setup/common/`, in the `consent` suite; systemctl is stubbed. The sandbox suite and the host
suite meet the real units.

| File | What |
|---|---|
| `sssd_sockets_test.py` | sssd's socket units (1.6.7.8, 2.1.6.95): the host's own join masks them after recording them; the undo puts each back as it was (or its package's default when unrecorded) with its failure cleared; nothing without sssd or systemctl; and `join-linux.sh.j2` uses the same glob and the same disable and mask, so the two joins cannot drift |
