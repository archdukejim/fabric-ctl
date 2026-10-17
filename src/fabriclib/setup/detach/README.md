# fabriclib/setup/detach

Setup's work as its own systemd unit, `fabric-setup.service`, so a dropped session does not stop it (decision
2.1.2.26, manual 1.3.2.3).

| File | What |
|---|---|
| `constants.py` | The unit's name, the run record and log in the config folder, the hand-off folder, the environment passed |
| `choose_start.py` | A full setup's first move: follow the running unit, resume the last unfinished run, or ask and start anew |
| `read_run.py` | The last run's record (`setup-run.yaml`): steps done, the step running, how it ended |
| `write_run.py` | Save the run record atomically, 0600 |
| `write_handoff.py` | The secrets typed in the questions, to a new root-only 0600 file in `/run/fabric` for the unit |
| `read_handoff.py` | Read the handed-over secrets once in the unit, removing the file; refuse one not root's 0600 regular file |
| `can_detach.py` | Whether the host was booted with systemd and has `systemd-run` |
| `unit_running.py` | Whether `fabric-setup.service` runs now |
| `launch_worker.py` | `systemd-run --unit fabric-setup --collect` running `fabricctl setup --worker <run>`, output to the run's log |
| `follow_run.py` | Print the run's log as it grows until the unit ends; its result as the exit status; Ctrl-C detaches |
| `hand_over.py` | After the last question: settings saved, secrets handed over, run recorded, unit started and followed |
| `resume_run.py` | Resume the last run from its first unfinished step, asking only for a secret a step ahead needs |
| `run_worker.py` | `setup --worker <run>`: the recorded run's remaining steps inside the unit |
