from fabriclib.common.ask import ask
from fabriclib.common.console import NC, YELLOW
from fabriclib.setup.common.ca_exists import ca_exists
from fabriclib.setup.permanent_mark import permanent_mark


def ask_ca_lifetime(ctx):
    """Purpose: the menu's CA item (manual 1.2.9.11.3): the root CA's lifetime in years (2.1.5.6), asked only before the
             CA exists. The intermediate lives a year less.
    Inputs:  ctx — SetupContext; reads ctx.vars cert_root_ca_days (default 3650). Interactive.
    Returns: None; ctx.vars["cert_root_ca_days"] set (whole years as days). Once the CA exists nothing is asked: the
             refusal says the lifetime is fixed. A value that is not a whole number of years from 1 to 30 is refused
             with the reason and asked again.
    Fails:   EOFError from input().
    Feeds:   setup/advanced/setup_menu."""
    if ca_exists(ctx):
        print(f"    {YELLOW}refused: this install's CA exists, its lifetime is fixed (2.1.5.6){NC}")
        return
    years = round(int(ctx.vars.get("cert_root_ca_days") or 3650) / 365)
    while True:
        answer = ask("setup.ca_years", f"\n  The internal CA's root is valid for how many years (its intermediate a "
                     f"year less; fixed once made)?{permanent_mark('cert_root_ca_days')} [{years}] ", str(years))
        if answer.isdigit() and 1 <= int(answer) <= 30:
            ctx.vars["cert_root_ca_days"] = int(answer) * 365
            return
        print(f"    {YELLOW}{answer!r}: a whole number of years, 1 to 30{NC}")
