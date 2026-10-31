# tests/setup/detach

Pure tests of `fabriclib/setup/detach/` (decision 2.1.2.26, manual 1.3.2.3), one per unit, in the `consent` suite;
systemd, the clock and the steps are stubbed. The sandbox suite and the installer test meet the real unit (a session
killed mid-work, then re-attached).

| File | What |
|---|---|
| `choose_start_test.py` | Follow the running unit; resume an unfinished run from its first unfinished step (STEPS' order); start over with `--restart`/`--file`/`--join`, after a finished run, or with no record |
| `read_run_test.py` | The run record read; a missing, damaged, non-mapping or id-less one reads as none |
| `write_run_test.py` | The run record atomic and 0600, a failed write leaving the old one whole |
| `write_handoff_test.py` | The hand-off file new and 0600 in a 0700 folder; an existing file, a planted symlink and a bad run id refused |
| `read_handoff_test.py` | The secrets read once and the file removed; a second read, a loose mode, another owner, a symlink and bad content refused |
| `unit_running_test.py` | `systemctl is-active` states read as running or not; no systemctl reads as not running |
| `can_detach_test.py` | Only a host booted with systemd, with `systemd-run`, detaches |
| `launch_worker_test.py` | `systemd-run` with `--collect`, the run's log and `setup --worker <run>`; only `SUDO_USER`/`SSH_CONNECTION` passed, no secret; a refusal named |
| `follow_run_test.py` | The log shown as it grows (a split character whole); the run's result as the exit status; Ctrl-C detaches (130); a killed unit or no log said |
| `hand_over_test.py` | Settings saved, secrets in the hand-off file only, run recorded, unit started and followed; a failed start leaves no secret; without systemd the steps run in the session |
| `resume_run_test.py` | A resume asks no questions but a needed secret (the invitation, the admin's password), keeps the options, the steps done and the services to restart; unattended without the password file refused |
| `run_worker_test.py` | The unit runs the recorded run's remaining steps with the handed-over secrets and no terminal; another run id, a finished run or refused secrets run nothing |
