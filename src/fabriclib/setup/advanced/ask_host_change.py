from fabriclib.common.ask import ask_yes_no
from fabriclib.common.console import NC, YELLOW
from fabriclib.consent.groups import GROUPS


def ask_host_change(ctx, group):
    """Purpose: the menu's item for one recommended or choice host change (manual 1.2.9.11.3, decision 2.1.2.18): on
             (Proceed allows it) or off. Turned off it first shows what declining it means ("If no: …") and is
             recorded declined at Proceed, a relaxation status shows; what needs it goes off too, and turning one on
             turns on what it needs (the firewall needs ports, the host's own rules need the firewall), each said.
             Domain membership is its setting (host_join_domain, the question setup.host_join_domain), the resolver its
             choice (use_host_dns: off keeps the host's resolver, and port 53 must be freed another way).
    Inputs:  ctx — SetupContext: host_choices ({group: bool}; changed), vars (host_join_domain, use_host_dns; changed);
             group — a recommended group of GROUPS, or "resolver". Interactive.
    Returns: None.
    Fails:   EOFError from input().
    Feeds:   setup/advanced/setup_menu."""
    g = GROUPS[group]
    if group == "member":
        now = ctx.vars.get("host_join_domain", True) is not False
        on = ask_yes_no("setup.host_join_domain", GROUPS["member"]["question"], now)
        ctx.vars["host_join_domain"] = on
    elif group == "resolver":
        now = ctx.vars.get("use_host_dns", True) is False
        on = ask_yes_no(f"setup.consent.{group}", g["question"], now)
        ctx.vars["use_host_dns"] = not on
    else:
        now = ctx.host_choices.get(group, True)
        on = ask_yes_no(f"setup.consent.{group}", g["question"], now)
        ctx.host_choices[group] = on
        if on:
            need = g.get("needs")
            while need and not ctx.host_choices.get(need, True):
                ctx.host_choices[need] = True
                print(f"    also on: {GROUPS[need]['title']} ({g['title']} needs it)")
                need = GROUPS[need].get("needs")
        else:
            off = {group}
            for other, meta in GROUPS.items():         # in order, so a chain (ports, firewall, own_rules) follows
                if meta.get("needs") in off and ctx.host_choices.get(other, True):
                    ctx.host_choices[other] = False
                    off.add(other)
                    print(f"    also off: {meta['title']} (it needs {GROUPS[meta['needs']]['title']})")
    if now and not on:
        print(f"    {YELLOW}If no: {g['declined']}.{NC}")
