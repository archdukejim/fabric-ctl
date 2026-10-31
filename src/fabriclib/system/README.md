# fabriclib/system

| File | What |
|---|---|
| `version_info.py` | Installed fabric version and build stamp (`VERSION` and `BUILD` of the tree it runs from) |
| `service_status.py` | Every installed fabric service: systemd state and container health (for `status` and the web UI) |
| `apply_changes.py` | Render + deploy + reload changed services (`interactive.py --apply`, as `fabricctl --apply`), under the vars lock, audited |
| `apply_failure.py` | What a job says when its apply did not finish: the last 10 lines, and the full output in a root-only log the message names (2.1.8.31) |
| `control_stack.py` | `fabricctl start/stop/restart/status`: the whole stack through `fabric.target` |
| `render_template_file.py` | `fabricctl --render-jinja`: render one template with fabric's vars, for the caller |
| `host_reminders.py` | What every administrator is reminded of on this host (the break-glass password's file, the local administrator accounts neither managed nor approved), worked out in a transient unit outside fabric-agent's sandbox (GET /v1/reminders) |
| `relaxed_settings.py` | The security relaxations turned on (e.g. `image_signature_check: false`), for status and the web UI (Rule 10) |
| `show_relaxed_settings.py` | Prints them for `fabricctl status` |
| `host_networks.py` | This host's IPv4 addresses by interface (`ip -j -4 addr`) |
| `host_ram_gb.py` | This host's memory in GB, rounded (from /proc/meminfo) |
| `plan_memory.py` | Memory as a budget (1.2.4.3): every installed service's limit from `host_ram_capacity`, floors and weights; refuses a plan that does not fit |
| `memory_limit_mb.py` | One service's memory limit in MB (an explicit `*_mem_limit`, else the plan): the compose files' `memory_mb()` |
| `show_memory_plan.py` | Prints the memory split for `fabricctl status` and setup's plan |
| `common/` | Helpers shared by these files (`parse_mem_mb`) |
