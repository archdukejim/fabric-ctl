import os

from fabriclib.common.ask import ask
from fabriclib.common.console import BOLD, GREEN, NC, RED
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.dns.add_zone import add_zone
from fabriclib.dns.constants import PRIVATE_TLDS
from fabriclib.dns.remove_zone import remove_zone
from fabriclib.menu.edit_dns_zone import edit_dns_zone
from fabriclib.menu.save_menu_change import menu_actor


def _count(zone):
    """Purpose: how many records a zone holds.
    Inputs:  zone — the zone's dict in `dns:` (or None).
    Returns: int, over every list-valued field.
    Fails:   never.
    Feeds:   edit_dns."""
    return sum(len(v) for v in (zone or {}).values() if isinstance(v, list))


def _add(data):
    """Purpose: ask for a new zone's name (and, for a public name, whether it hides the real one) and add it.
    Inputs:  data — the vars working copy; its `dns` is refreshed from vars.yaml after the change.
    Returns: None; the outcome is printed.
    Fails:   EOFError from ask(); a refusal (ValidationError) is printed.
    Feeds:   edit_dns."""
    name = ask("menu.dns.new_zone", "New zone name: ").rstrip(".").lower()
    hide = False
    private = name == "home.arpa" or name.endswith(".home.arpa") or name.rsplit(".", 1)[-1] in PRIVATE_TLDS
    if name and not private:
        print("This name is under a public top-level domain: every client of this site would get this zone's "
              "answers instead of the real ones.")
        hide = ask("menu.dns.hide_public", "Hide the public name? [y/N]: ").lower() == "y"
    try:
        res = add_zone(menu_actor(), name, hide_public=hide)
        print(f"{GREEN}Zone {res['name']} added: BIND answers for it now.{NC}")
    except ValidationError as e:
        print(f"{RED}{e}{NC}")
    data["dns"] = load_vars().get("dns") or {}


def _remove(data, zones):
    """Purpose: pick a zone, show how many records go with it, ask for its name again and remove it.
    Inputs:  data — the vars working copy; its `dns` is refreshed from vars.yaml after the change; zones — the keys
             listed (the site's own first).
    Returns: None; the outcome is printed.
    Fails:   EOFError from ask(); a refusal (ValidationError) is printed.
    Feeds:   edit_dns."""
    choice = ask("menu.dns.remove_pick", f"Zone to remove (2-{len(zones)}): ")
    if not choice.isdigit() or not 2 <= int(choice) <= len(zones):
        print(f"{RED}Pick one of the added zones (the site's own zone cannot be removed).{NC}")
        return
    key = zones[int(choice) - 1]
    print(f"Removing {key} removes its {_count((data.get('dns') or {}).get(key))} record(s).")
    confirm = ask("menu.dns.remove_confirm", f"Type the zone's name ({key}) to confirm: ")
    try:
        res = remove_zone(menu_actor(), key, confirm)
        print(f"{GREEN}Zone {res['name']} removed with its {res['records']} record(s).{NC}")
    except ValidationError as e:
        print(f"{RED}{e}{NC}")
    data["dns"] = load_vars().get("dns") or {}


def edit_dns(data):
    """Purpose: menu listing the DNS zones in the vars (the main domain always first), adding and removing zones
             (served or dropped by BIND in seconds: fabriclib/dns/add_zone, remove_zone, manual 1.4.1.3).
    Inputs:  data — the vars working copy; its `dns` is refreshed from vars.yaml after a zone change.
    Returns: None when "b" is picked.
    Fails:   a refused name or removal (ValidationError: the reason) is shown and the menu goes on; EOFError from
             ask().
    Feeds:   run_vars_menu (menu 1), edit_complex_variable (key dns)."""
    while True:
        zones_data = data.get("dns") if isinstance(data.get("dns"), dict) else {}
        os.system("clear")
        print(f"{BOLD}--- DNS Records Editor ---{NC}\n")
        domain = data.get("domain", "example.com")
        zones = list(zones_data)
        if "dynamic_zone_var" in zones:
            zones.remove("dynamic_zone_var")
        zones.insert(0, "dynamic_zone_var")
        print("Available Zones:")
        for i, z in enumerate(zones, 1):
            print(f"  {i}) {domain if z == 'dynamic_zone_var' else z} ({z}, {_count(zones_data.get(z))} records)")
        print("\n  a) Add a new zone")
        print("  r) Remove a zone")
        print("  b) Back to variables")
        choice = ask("menu.dns.zone_pick", f"Select a zone (1-{len(zones)}), 'a', 'r', or 'b': ").lower()
        if choice == "b":
            return
        if choice == "a":
            _add(data)
            ask("menu.continue", "Press Enter to continue...")
        elif choice == "r":
            _remove(data, zones)
            ask("menu.continue", "Press Enter to continue...")
        elif choice.isdigit() and 1 <= int(choice) <= len(zones):
            edit_dns_zone(data, zones[int(choice) - 1], domain)
