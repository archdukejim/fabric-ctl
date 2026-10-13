from fabriclib.common.ask import ask
from fabriclib.common.console import NC, YELLOW
from fabriclib.common.errors import ValidationError
from fabriclib.system.host_ram_gb import host_ram_gb
from fabriclib.system.plan_memory import plan_memory

MIN_RAM_GB = 4                      # 2.1.2.3: a Raspberry Pi with 4 GB is the smallest host


def ask_memory(ctx, have=None):
    """Purpose: the menu's memory item (manual 1.2.9.11.3, 1.2.4.3): how many GB fabric may use (host_ram_capacity),
             from 4 to what the host has; the plan then shows the split.
    Inputs:  ctx — SetupContext: vars (host_ram_capacity, the parts; changed); have — the host's GB (None: measured).
             Interactive.
    Returns: None; ctx.vars["host_ram_capacity"] set. A number outside 4 to the host's GB, text, or a size whose
             memory plan does not fit the parts that are on (plan_memory's refusal) is refused, saying why, and asked
             again; Enter keeps the value (when even that does not fit, the refusal is shown and the menu follows, where
             a part can be turned off).
    Fails:   EOFError from input().
    Feeds:   setup/advanced/setup_menu."""
    have = host_ram_gb() if have is None else have
    now = int(ctx.vars.get("host_ram_capacity") or have or MIN_RAM_GB)
    while True:
        answer = ask("setup.memory", f"\n  GB of memory fabric may use, {MIN_RAM_GB} to {have or 'the host'}'s? "
                     f"[{now}] ", str(now))
        if not answer.isdigit() or int(answer) < MIN_RAM_GB or (have and int(answer) > have):
            print(f"    {YELLOW}{answer!r}: a whole number of GB, {MIN_RAM_GB} to {have or 'what the host has'}{NC}")
            continue
        try:
            plan_memory({**ctx.vars, "host_ram_capacity": int(answer)})
        except ValidationError as e:
            print(f"    {YELLOW}refused: {e}{NC}")
            if int(answer) == now:           # kept as it was: turn a part off in the menu instead
                return
            continue
        ctx.vars["host_ram_capacity"] = int(answer)
        return
