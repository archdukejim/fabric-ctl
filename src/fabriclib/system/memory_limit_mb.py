from fabriclib.system.common.parse_mem_mb import parse_mem_mb
from fabriclib.system.plan_memory import SERVICES, SETTINGS, plan_memory


def memory_limit_mb(v, service):
    """Purpose: one service's memory limit in MB, as its compose file sets it (manual 1.2.4.3).
    Inputs:  v — settings or a template's context: `<svc>_mem_limit` (an explicit limit, rendered vars carry it only
             when the admin set it), memory_plan (rendered vars: plan_memory's result), else what plan_memory reads;
             service — a name of plan_memory.SERVICES.
    Returns: int MB: the explicit setting, else the planned limit, else (a service the plan leaves out, being off) its
             floor.
    Fails:   KeyError for an unknown service (a coding error); ValidationError from parse_mem_mb or plan_memory.
    Feeds:   common/jinja_env (the compose templates' `memory_mb('<svc>')`), dns_filter (the resolver's limit),
             system/show_memory_plan."""
    floor = SERVICES[service][0]
    key = SETTINGS.get(service, (None,))[0]
    explicit = parse_mem_mb(v.get(key), key) if key else None
    if explicit:
        return explicit
    plan = v.get("memory_plan")
    if not isinstance(plan, dict) or not isinstance(plan.get("limits"), dict):
        plan = plan_memory(v)
    return int(plan["limits"].get(service) or floor)
