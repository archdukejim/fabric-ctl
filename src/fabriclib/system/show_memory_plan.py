from fabriclib.common.errors import ValidationError
from fabriclib.system.plan_memory import SERVICES, SETTINGS, plan_memory


def show_memory_plan(v, heading="memory"):
    """Purpose: print how fabric's memory is split (manual 1.2.4.3): the budget, the host's reserve and every installed
             service's limit, so the numbers visibly add up; for `fabricctl status` and setup's plan.
    Inputs:  v — settings: rendered vars carry memory_plan (used as it is); others are planned here (plan_memory);
             heading — the first line's label.
    Returns: None; prints a heading line and one line per service (a limit set by a `*_mem_limit` says so), or the
             plan's refusal when it does not fit.
    Fails:   never (a refused plan is printed, not raised).
    Feeds:   cli (`fabricctl status`), setup/choose_plan."""
    plan = v.get("memory_plan")
    if not isinstance(plan, dict) or not isinstance(plan.get("limits"), dict):
        try:
            plan = plan_memory(v)
        except ValidationError as e:
            print(f"\n{heading}: does not fit — {e}")
            return
    print(f"\n{heading}: {plan['capacity_mb']} MB (host_ram_capacity): {plan['reserve_mb']} MB kept for the host, "
          f"{plan['budget_mb']} MB for fabric's services")
    explicit = plan.get("explicit") or {}
    containers = plan.get("containers") or {}
    for service, mb in plan["limits"].items():
        n = int(containers.get(service, 1))
        what = SERVICES[service][3] if service in SERVICES else service
        size = f"{mb} MB" + (f" x {n}" if n > 1 else "")
        note = f"  (set: {SETTINGS[service][0]})" if service in explicit else ""
        print(f"  {what:<38} {size:>12}{note}")
    if plan.get("unassigned_mb"):
        print(f"  {'not given to any service':<38} {str(plan['unassigned_mb']) + ' MB':>12}")
