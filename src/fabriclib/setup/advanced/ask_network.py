from fabriclib.common.console import NC, YELLOW
from fabriclib.setup.common.ask_setting import ask_setting
from fabriclib.setup.common.network_problem import network_problem


def ask_network(ctx):
    """Purpose: the menu's network item (manual 1.2.9.11.3): this host's address, the LAN subnet and its gateway, with
             guided mode's questions (setup.vars.host_ip, setup.vars.lan_cidr, setup.vars.lan_gateway) and checks:
             each one valid, then the three together (network_problem).
    Inputs:  ctx — SetupContext: vars (host_ip, lan_cidr, lan_gateway; changed: the current values are the defaults),
             origins (their "found" mark is dropped once answered). Interactive.
    Returns: None; the three set. Answers that do not fit together are refused, saying why, and asked again.
    Fails:   EOFError from input().
    Feeds:   setup/advanced/setup_menu."""
    while True:
        for key in ("host_ip", "lan_cidr", "lan_gateway"):
            ctx.vars[key] = ask_setting(key, ctx.vars.get(key))
            ctx.origins.pop(key, None)
        problem = network_problem(ctx.vars)
        if not problem:
            return
        print(f"    {YELLOW}{problem}: asked again{NC}")
