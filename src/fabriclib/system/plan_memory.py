from fabriclib.common.errors import ValidationError
from fabriclib.system.common.parse_mem_mb import parse_mem_mb

RESERVE_MB = 512            # the host's own work: the OS, Docker, fabric's own Python (1.2.4.3.1)

# service: (floor MB, weight, containers, what it is). The floor is the limit it needs to run; the services that use
# memory when they have it share what is left by weight (1.2.4.3.2). Kea runs two containers, each with the limit.
SERVICES = {
    "keycloak": (1024, 6, 1, "Keycloak"),
    "samba": (512, 3, 1, "the domain controller (Samba)"),
    "resolver": (128, 0, 1, "the DNS filter's resolver"),
    "postgres": (128, 1, 1, "Postgres"),
    "bind9": (128, 1, 1, "BIND"),
    "nginx": (256, 0, 1, "nginx"),
    "openbao": (256, 0, 1, "OpenBao"),
    "stepca": (128, 0, 1, "Step-CA"),
    "webui": (96, 0, 1, "the web console"),
    "kea": (128, 0, 2, "Kea (DHCP and its DNS updates)"),
    "freeradius": (128, 0, 1, "FreeRADIUS"),
    "fluentbit": (64, 0, 1, "Fluent Bit"),
}

# the services that had a `*_mem_limit` setting before 0.7.1, and the values it held by default then (an install's
# vars.yaml carries one): such a value is no choice of the admin's, so the service joins the budget. The resolver's
# was 384m in the 0.8.0 candidates and 128m in 0.7.0. AdGuard Home is outside the budget for now: its limit follows
# the host as in 0.7.0 (adguard_mem_limit, 1 GiB at 4 GB, 1.12.3.9), which does not fit beside Keycloak on 4 GB.
SETTINGS = {"openbao": ("openbao_mem_limit", lambda gb: 256), "kea": ("kea_mem_limit", lambda gb: 128),
            "samba": ("samba_mem_limit", lambda gb: int(512 * gb / 4)),
            "freeradius": ("freeradius_mem_limit", lambda gb: 128),
            "fluentbit": ("fluentbit_mem_limit", lambda gb: 64),
            "resolver": ("resolver_mem_limit", lambda gb: (384, 128))}

# the parts a person can turn off (1.1.9), what turns each off, and the services that go with it
PARTS = [("install_kea", "DHCP (install_kea: false)", ["kea"]),
         ("install_freeradius", "802.1X (install_freeradius: false)", ["freeradius"]),
         ("install_fluentbit", "log forwarding (install_fluentbit: false)", ["fluentbit"]),
         ("dns_filter", "the DNS filter (dns_filter: none)", ["resolver"]),
         ("install_keycloak", "Keycloak and the web console (install_keycloak: false)",
          ["keycloak", "postgres", "webui"])]


def _installed(v):
    """Purpose: the services this install runs, from its settings (the defaults as vars.yaml.j2 has them).
    Inputs:  v — settings: install_keycloak (default false), install_webui (default true; only with Keycloak),
             install_kea, install_freeradius, install_fluentbit (default false), dns_filter (default bind).
    Returns: list of service names in SERVICES order.
    Fails:   never.
    Feeds:   plan_memory."""
    keycloak = bool(v.get("install_keycloak", False))
    on = {"samba", "bind9", "nginx", "openbao", "stepca",
          *(["keycloak", "postgres"] if keycloak else []),
          *(["webui"] if keycloak and v.get("install_webui", True) is not False else []),
          *(["kea"] if v.get("install_kea") else []), *(["freeradius"] if v.get("install_freeradius") else []),
          *(["fluentbit"] if v.get("install_fluentbit") else []),
          *(["resolver"] if str(v.get("dns_filter") or "bind").lower() == "bind" else [])}
    return [s for s in SERVICES if s in on]


def _overrides(value, key, number):
    """Purpose: check `memory_floors` / `memory_weights` (manual 1.2.4.3.2): a map of known services to numbers.
    Inputs:  value — the setting (None or {} for none); key — its name; number — callable(service, raw) -> the checked
             number, raising ValidationError.
    Returns: {service: number}.
    Fails:   ValidationError: not a map; an unknown service (names the known ones); what number refuses.
    Feeds:   plan_memory."""
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise ValidationError(f"{key}: a map of service to value, e.g. {{keycloak: ...}}")
    unknown = sorted(set(value) - set(SERVICES))
    if unknown:
        raise ValidationError(f"{key}: no service {', '.join(map(str, unknown))} (services: {', '.join(SERVICES)})")
    return {s: number(s, raw) for s, raw in value.items()}


def _floor(service, raw):
    """Purpose: one `memory_floors` value: MB as a positive whole number, or a size such as 512m.
    Inputs:  service — its name; raw — the value.
    Returns: int MB.
    Fails:   ValidationError for anything else (zero, negative, text that is no size).
    Feeds:   plan_memory (through _overrides)."""
    if isinstance(raw, int) and not isinstance(raw, bool):
        if raw < 1:
            raise ValidationError(f"memory_floors.{service}: {raw} — a positive number of MB")
        return raw
    if isinstance(raw, str):
        return parse_mem_mb(raw, f"memory_floors.{service}")
    raise ValidationError(f"memory_floors.{service}: {raw!r} — a positive number of MB")


def _weight(service, raw):
    """Purpose: one `memory_weights` value: a number, 0 or more (0: the floor only).
    Inputs:  service — its name; raw — the value.
    Returns: float.
    Fails:   ValidationError for a negative number or anything that is not a number.
    Feeds:   plan_memory (through _overrides)."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw < 0:
        raise ValidationError(f"memory_weights.{service}: {raw!r} — a number, 0 or more")
    return float(raw)


def plan_memory(v):
    """Purpose: every installed service's memory limit, planned as a budget (manual 1.2.4.3, decision 2.1.1.47):
             host_ram_capacity less a reserve for the host is the budget; each service gets its floor, and what is
             left goes to the services with a weight, in proportion. Precedence for one service: its own `*_mem_limit`
             setting when the admin set one (that limit, fixed, no share; a value it held by default before 0.7.1
             counts as not set), else its `memory_floors` / `memory_weights` entry, else the built-in floor and
             weight. The limits always add up to the budget (whole MB; what rounding leaves goes to the largest
             weight).
    Inputs:  v — settings: host_ram_capacity (GB), the install flags (_installed), memory_floors, memory_weights,
             openbao_mem_limit, kea_mem_limit, samba_mem_limit, freeradius_mem_limit, fluentbit_mem_limit,
             resolver_mem_limit.
    Returns: {"capacity_mb", "reserve_mb", "budget_mb", "limits": {service: MB per container}, "containers":
             {service: count}, "explicit": {service: MB} (the ones set by a `*_mem_limit`), "settings":
             {"<svc>_mem_limit": the admin's value or None}, "unassigned_mb": what no service took (only when no
             installed service has a weight)}.
    Fails:   ValidationError: host_ram_capacity not a whole number; memory_floors / memory_weights not valid; a
             `*_mem_limit` that is not a size; the floors (and fixed limits) of the installed services do not fit the
             budget — naming the parts that could be turned off, what each frees, and the memory the plan needs.
    Feeds:   vars.yaml.j2 (memory_plan, through jinja_env), system/memory_limit_mb, setup/choose_plan,
             setup/set_ram_capacity, system/show_memory_plan."""
    try:
        gb = int(v.get("host_ram_capacity") or 4)
    except (TypeError, ValueError):
        raise ValidationError(f"host_ram_capacity: {v.get('host_ram_capacity')!r} is not a whole number of GB")
    floors = _overrides(v.get("memory_floors"), "memory_floors", _floor)
    weights = _overrides(v.get("memory_weights"), "memory_weights", _weight)
    capacity = gb * 1024
    budget = capacity - RESERVE_MB
    installed = _installed(v)
    explicit, settings = {}, {}
    for service, (key, old_default) in SETTINGS.items():
        mb = parse_mem_mb(v.get(key), key)
        olds = old_default(gb)
        honoured = mb is not None and mb not in (olds if isinstance(olds, tuple) else (olds,))
        settings[key] = v.get(key) if honoured else None
        if honoured and service in installed:
            explicit[service] = mb
    containers = {s: SERVICES[s][2] for s in installed}
    limits = {s: explicit.get(s, floors.get(s, SERVICES[s][0])) for s in installed}
    need = sum(limits[s] * containers[s] for s in installed)
    if need > budget:
        frees = []
        for flag, what, services in PARTS:
            gone = [s for s in services if s in installed]
            if gone:
                frees.append(f"{what}, {sum(limits[s] * containers[s] for s in gone)} MB")
        need_gb = -(-(need + RESERVE_MB) // 1024)
        raise ValidationError(
            f"memory: the installed services need {need} MB at least, but fabric's budget is {budget} MB "
            f"(host_ram_capacity {gb} GB less {RESERVE_MB} MB for the host). Turn off "
            + ("; or ".join(frees) if frees else "nothing (only the core runs)")
            + f" — or give fabric {need_gb} GB (host_ram_capacity), or lower memory_floors (manual 1.2.4.3)")
    shared = {s: weights.get(s, SERVICES[s][1]) for s in installed if s not in explicit}
    shared = {s: w for s, w in shared.items() if w > 0}
    left = budget - need
    total = sum(shared.values())
    for s, w in shared.items():
        limits[s] += int(left * w / total / containers[s])
    rest = budget - sum(limits[s] * containers[s] for s in installed)
    single = [s for s in sorted(shared, key=lambda s: -shared[s]) if containers[s] == 1]
    if single:
        limits[single[0]] += rest
        rest = 0
    return {"capacity_mb": capacity, "reserve_mb": RESERVE_MB, "budget_mb": budget, "limits": limits,
            "containers": containers, "explicit": explicit, "settings": settings, "unassigned_mb": rest}
