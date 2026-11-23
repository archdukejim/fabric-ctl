# tests/setup/common

Pure tests of `fabriclib/setup/common/`, in the `consent` suite; systemctl is stubbed. The sandbox suite and the host
suite meet the real units.

| File | What |
|---|---|
| `apt_install_test.py` | Setup's apt installs (`setup/common/apt_install`): each apt waits up to 10 minutes for dpkg's lock (a fresh host's unattended-upgrades, 2.3.1.57); apt's failure refused naming the packages and the hint. apt stood in for |
| `sssd_sockets_test.py` | sssd's socket units (1.6.7.8, 2.1.6.95): the host's own join masks them after recording them; the undo puts each back as it was (or its package's default when unrecorded) with its failure cleared; nothing without sssd or systemctl; and `join-linux.sh.j2` uses the same glob and the same disable and mask, so the two joins cannot drift |
| `first_admin_needed_test.py` | Whether setup makes the first admin: a new root site does; a provisioned DC, a joining site, or a restore whose directory dump is pending does not |
| `address_in_use_test.py` | The duplicate-address probe for real (as root): a second machine in a network namespace on a veth pair answers, its MAC named; no arping, a failing or unfinished arping refused |
