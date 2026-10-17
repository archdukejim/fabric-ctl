# tests/setup

| File | What |
|---|---|
| `wait_ready_test.py` | Pure, in the `consent` suite: setup's ready gate waits until every check passes in one round, names those still failing when the time is up, and refuses to say it is ready while Postgres's log shows refused sign-ins (2.1.2.25); the probes and clock stubbed (the host suite and the installer test meet the real ones) |
| `run_steps_test.py` | Pure, in the `consent` suite: the step loop keeps a full run's record after each step (done, the step running, the services to restart), saves the settings before deploy, records the end; a `--step` run records nothing (2.1.2.26) |
| `run_setup_test.py` | Pure, in the `consent` suite: a full run follows a running `fabric-setup.service`, resumes an unfinished run, starts over with `--restart`/`--file`/`--join`; `--worker` runs only the recorded run; `--step` stays in the session (2.1.2.26) |
| `detach/` | Pure tests of setup's detached run, one per unit of `fabriclib/setup/detach/` (its README) |
