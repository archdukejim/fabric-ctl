from fabriclib.common.ask import ask
from fabriclib.common.console import BOLD, NC, YELLOW, heading
from fabriclib.samba.suggested_ad_domain import suggested_ad_domain
from fabriclib.samba.suggested_dc_name import suggested_dc_name
from fabriclib.setup.advanced.menu_items import menu_items
from fabriclib.setup.common.network_problem import network_problem
from fabriclib.setup.common.valid_setting import FIRST_ADMIN, valid_setting
from fabriclib.setup.detect_network import detect_network

SECTIONS = {"required": "Required (setup cannot proceed until each has a value):",
         "before": "Before the install:",
         "host": "Changes to this host (recommended; each can be declined):"}


def _fill_found(ctx):
    """Purpose: the values setup can find or default, filled in and marked so the menu shows them as such (1.2.9.11.3):
             the domain home.arpa, this host's name and network as found, the first admin fabric-admin.
    Inputs:  ctx — SetupContext: vars (changed only where a value is missing or not valid), origins (changed).
    Returns: None.
    Fails:   never (detect_network finds what it can).
    Feeds:   setup_menu."""
    v = ctx.vars
    found = None
    for key in ("hostname", "host_ip", "lan_cidr", "lan_gateway"):
        if not valid_setting(key, str(v.get(key) or "")):
            found = detect_network() if found is None else found
            if found.get(key):
                v[key], ctx.origins[key] = found[key], "found"
    for key, default in (("domain", "home.arpa"), ("webui_admin_user", FIRST_ADMIN)):
        if not valid_setting(key, str(v.get(key) or "")):
            v[key], ctx.origins[key] = default, "default"


def _show(items):
    """Purpose: print the menu: its three parts, each item numbered with its value.
    Inputs:  items — menu_items' list.
    Returns: None.
    Fails:   never.
    Feeds:   setup_menu."""
    heading("fabric setup: every setting")
    part = None
    for n, item in enumerate(items, 1):
        if item["part"] != part:
            part = item["part"]
            print(f"  {SECTIONS[part]}")
        dots = "." * max(2, 34 - len(item["title"]))
        value = f"{YELLOW}{item['value']}{NC}" if item["missing"] else item["value"]
        print(f"   {n:>2}) {item['title']} {dots} {value}")


def setup_menu(ctx, networks=None):
    """Purpose: setup's menu of every setting (manual 1.2.9.11.3, decision 2.1.2.19), from the start's [A]dvanced or the
             plan's [M]enu: a number asks that item with guided mode's question and checks, then the menu shows again;
             [P]roceed goes on to the plan once every required item has a value (it names those it waits for); [Q]uit
             changes nothing. Something not on the list is refused, saying which numbers are.
    Inputs:  ctx — SetupContext: vars, origins, host_choices, admin_password (all changed by the items); networks —
             host_networks() for DHCP's questions (None: this host's). Interactive.
    Returns: None, on Proceed: every required setting valid, the AD domain and the DC's name set (their suggestions
             taken when none was chosen), the network's answers fitting together.
    Fails:   SystemExit("setup cancelled") on Quit; EOFError from input().
    Feeds:   setup/run_setup (Advanced at the start), setup/choose_plan ([M]enu)."""
    _fill_found(ctx)
    while True:
        items = menu_items(ctx, networks)
        _show(items)
        waits = [str(n) for n, item in enumerate(items, 1) if item["missing"]]
        wait_text = f" (waits for {', '.join(waits)})" if waits else ""
        prompt = f"\n  {BOLD}[P]roceed{NC}{wait_text}, a number to change it, or [Q]uit: "
        answer = ask("setup.menu", prompt).lower()
        if answer in ("q", "quit"):
            raise SystemExit("setup cancelled")
        if answer in ("p", "proceed"):
            if waits:
                print(f"    {YELLOW}not yet: {', '.join(waits)} need{'s' if len(waits) == 1 else ''} an answer{NC}")
                problem = network_problem(ctx.vars) if all(
                    valid_setting(k, str(ctx.vars.get(k) or "")) for k in ("host_ip", "lan_cidr", "lan_gateway")) \
                    else ""
                if problem:
                    print(f"    {YELLOW}the network: {problem}{NC}")
                continue
            if not ctx.vars.get("ad_domain"):
                ctx.vars["ad_domain"] = suggested_ad_domain(str(ctx.vars.get("domain") or ""))
            # the DC's name is permanent (2.1.6.45): the suggestion shown is saved, so a later host rename never
            # moves it (the 0.7.1 candidate's install left it unset, 2.3.1.21.2)
            if not ctx.vars.get("dc_name"):
                ctx.vars["dc_name"] = suggested_dc_name(ctx.vars.get("hostname"))
            return
        if answer.isdigit() and 1 <= int(answer) <= len(items):
            items[int(answer) - 1]["ask"]()
            continue
        print(f"    {YELLOW}{answer!r} is not on the list: a number from 1 to {len(items)}, P to proceed or Q to "
              f"quit{NC}")
