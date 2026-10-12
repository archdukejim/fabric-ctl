# tests/deploy

| File | What |
|---|---|
| `restart_changed_test.py` | An apply's measured rollout (2.1.14.15, manual 1.14.2.11): the changed services restarted once each in dependency order (OpenBao first, a host service last), the rollout stopped at the first service not healthy (a container) or not active (a host service), the error naming it and those not restarted. Pure logic: `start_unit` and `systemctl` stood in for; the sandbox runs real applies |
