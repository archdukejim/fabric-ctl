# tests/setup

| File | What |
|---|---|
| `wait_ready_test.py` | Pure, in the `consent` suite: setup's ready gate waits until every check passes in one round, names those still failing when the time is up, and refuses to say it is ready while Postgres's log shows refused sign-ins (2.1.2.25); the probes and clock stubbed (the host suite and the installer test meet the real ones) |
| `run_steps_test.py` | Pure, in the `consent` suite: the step loop keeps a full run's record after each step (done, the step running, the services to restart), saves the settings before deploy, records the end; a `--step` run records nothing (2.1.2.26) |
| `run_setup_test.py` | Pure, in the `consent` suite: a full run follows a running `fabric-setup.service`, resumes an unfinished run, starts over with `--restart`/`--file`/`--join`; `--worker` runs only the recorded run; `--step` stays in the session (2.1.2.26) |
| `import_old_vars_test.py` | Pure, in the `consent` suite: `setup --file` with a 0.7.1 install's vars.yaml (`vars-0.7.1.yaml`, made by 0.7.1's own code with `make_vars_071.py`) lists and ignores the retired keys, keeps the zones, records, TSIG keys' rights and parts, renders as a fresh install would; what 0.8.0 adds asked, or refused unattended naming every key; a damaged or non-fabric file refused (2.1.1.60) |
| `detach/` | Pure tests of setup's detached run, one per unit of `fabriclib/setup/detach/` (its README) |
| `start_unit_test.py` | Pure, in the `consent` suite: a unit systemd is already starting (Keycloak, restarted by systemd with Postgres) is waited for, never stopped mid-start; one in its automatic-restart loop or failed is still stopped, cleared and started; a start that never ends is waited for only until the timeout (2.3.2.5) |
| `require_terminal_test.py` | Pure, in the `consent` suite: setup with no terminal on stdin is refused before anything is asked or written, naming `--non-interactive --file FILE` (2.1.3.4); `--file` alone refused too; `--non-interactive`, a terminal, and a step that needs no input run |
