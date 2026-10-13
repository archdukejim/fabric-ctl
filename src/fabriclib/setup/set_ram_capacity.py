from fabriclib.common.console import info
from fabriclib.common.errors import ValidationError
from fabriclib.setup.errors import SetupError
from fabriclib.system.host_ram_gb import host_ram_gb
from fabriclib.system.plan_memory import SERVICES, plan_memory

MIN_RAM_GB = 4                      # 2.1.2.3: a Raspberry Pi with 4 GB is the smallest host


def _plan(data):
    """Purpose: what fabric's largest containers may use at this size, as planned (manual 1.2.4.3).
    Inputs:  data — the settings so far (host_ram_capacity set; the parts as chosen so far, Keycloak on unless set
             off, as the plan's default).
    Returns: str, e.g. "Keycloak 1129 MB, the domain controller (Samba) 563 MB, ..." (the four largest), or the plan's
             refusal when the floors do not fit.
    Fails:   never.
    Feeds:   set_ram_capacity."""
    try:
        plan = plan_memory({"install_keycloak": True, **data})
    except ValidationError as e:
        return str(e)
    top = sorted(plan["limits"].items(), key=lambda kv: -kv[1])[:4]
    return ", ".join(f"{SERVICES[s][3]} {mb} MB" for s, mb in top)


def set_ram_capacity(data):
    """Purpose: how much of this host fabric sizes itself for (2.1.2.3, manual 1.2.4.2): all of the measured memory
             unless set, no longer asked (2.1.2.16); less restricts fabric, leaving the rest to other work on the
             host. Kept as host_ram_capacity: change it with the vars editor (`sudo fabricctl`) or a vars file.
    Inputs:  data — the settings so far (changed: host_ram_capacity).
    Returns: None.
    Fails:   SetupError when the host has less than 4 GB, or a host_ram_capacity set is under 4 or more than the
             host has.
    Feeds:   collect_vars."""
    have = host_ram_gb()
    if have and have < MIN_RAM_GB:
        raise SetupError(f"this host has {have} GB of memory: fabric needs at least {MIN_RAM_GB} GB (2.1.2.3)")
    set_ = int(data.get("host_ram_capacity") or 0)
    if set_:
        if set_ < MIN_RAM_GB or (have and set_ > have):
            raise SetupError(f"host_ram_capacity is {set_} GB: give {MIN_RAM_GB} to {have or 'the host'}'s GB")
        return
    data["host_ram_capacity"] = have or MIN_RAM_GB
    info(f"memory: sized for {data['host_ram_capacity']} GB ({_plan(data)}); give fabric less "
         "with the vars editor")
