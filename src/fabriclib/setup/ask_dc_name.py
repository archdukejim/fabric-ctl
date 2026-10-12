from fabriclib.common.ask import ask
from fabriclib.common.console import NC, YELLOW
from fabriclib.samba.dc_name_problem import dc_name_problem
from fabriclib.samba.suggested_dc_name import suggested_dc_name
from fabriclib.setup.errors import SetupError
from fabriclib.setup.permanent_mark import permanent_mark


def ask_dc_name(ctx):
    """Purpose: setup's question for the domain controller's own name (2.1.6.45, manual 1.6.5.23): permanent (an AD DC
             cannot be renamed), independent of the host's name, `dc-<hostname>` suggested so the name says which
             machine it lives on. Asked only when not set: an existing install keeps its DC's name (keep_old_install).
    Inputs:  ctx — SetupContext: vars (dc_name, hostname, ad_domain, ad_netbios), non_interactive. Interactive unless
             non_interactive.
    Returns: None; ctx.vars["dc_name"] set, lower case: a valid name already set is kept; unattended, a missing one
             takes the suggestion; asked (marked "⚠ Permanent", 2.1.2.20), Enter takes the suggestion and a name
             the DC cannot have is refused, saying why, and asked again.
    Fails:   SetupError unattended for a dc_name set but invalid (dc_name_problem); EOFError from ask().
    Feeds:   setup/collect_vars (after the AD domain)."""
    v = ctx.vars
    netbios = str(v.get("ad_netbios") or str(v.get("ad_domain") or "").split(".")[0])[:15]
    current = str(v.get("dc_name") or "").strip().lower()
    if current and not dc_name_problem(current, netbios):
        v["dc_name"] = current
        return
    suggestion = suggested_dc_name(v.get("hostname"))
    if dc_name_problem(suggestion, netbios):
        suggestion = ""
    if ctx.non_interactive:
        if current or not suggestion:
            raise SetupError(f"dc_name: {dc_name_problem(current, netbios)} (manual 1.6.5.23)")
        v["dc_name"] = suggestion
        return
    while True:
        answer = ask("setup.dc_name", f"    Domain controller's name{permanent_mark('dc_name')}"
                     f"{f' [{suggestion}]' if suggestion else ''}: ").lower()
        chosen = answer or suggestion
        problem = dc_name_problem(chosen, netbios)
        if not problem:
            v["dc_name"] = chosen
            return
        print(f"    {YELLOW}{problem}{NC}")
