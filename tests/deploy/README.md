# tests/deploy

| File | What |
|---|---|
| `restart_changed_test.py` | An apply's measured rollout (2.1.14.15, manual 1.14.2.11): the changed services restarted once each in dependency order (OpenBao first, a host service last), the rollout stopped at the first service not healthy (a container) or not active (a host service), the error naming it and those not restarted. Pure logic: `start_unit` and `systemctl` stood in for; the sandbox runs real applies |
| `check_service_settings_test.py` | The settings every container starts with, checked before an apply renders anything: each image a reference, each `ip_` a host address of its own in `fabric_subnet`, the uid/gid block from 1000 and under 2^31. Pure logic |
