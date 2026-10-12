import os
import subprocess

from fabriclib.common.ask import ask
from fabriclib.common.console import BLUE, BOLD, GREEN, NC, RED, YELLOW
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.paths import BIND_DATA_DIR
from fabriclib.dns.add_record import add_record
from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.dns.format_value import format_value
from fabriclib.dns.remove_record import remove_record
from fabriclib.dns.sync_status import sync_status
from fabriclib.menu.apply_and_report import apply_and_report
from fabriclib.menu.save_menu_change import menu_actor

SYNC_COLOURS = {"in_sync": GREEN, "out_of_sync": YELLOW, "not_loaded": RED, "unreachable": YELLOW}


def _prompt_record(rtype):
    """Purpose: ask for the fields fabriclib.dns.validate_record expects for one record type.
    Inputs:  rtype — A, AAAA, CNAME, TXT, MX, SRV (any other type gets only a name).
    Returns: dict form: name plus ip | target | text | priority/target | priority/weight/port/target (MX priority
             defaults to "10", SRV priority and weight to "0"); unvalidated strings (add_record validates).
    Fails:   EOFError / KeyboardInterrupt from ask().
    Feeds:   edit_dns_zone."""
    form = {"name": ask("menu.dns.record.name", "Record name (e.g. '@', 'www'): ")}
    if rtype in ("A", "AAAA"):
        form["ip"] = ask("menu.dns.record.ip", "IP address: ")
    elif rtype == "CNAME":
        form["target"] = ask("menu.dns.record.cname_target", "Canonical name / target: ")
    elif rtype == "TXT":
        form["text"] = ask("menu.dns.record.text", "Text: ")
    elif rtype == "MX":
        form["priority"] = ask("menu.dns.record.mx_priority", "Priority [10]: ", "10")
        form["target"] = ask("menu.dns.record.mx_target", "Mail exchange: ")
    elif rtype == "SRV":
        form["priority"] = ask("menu.dns.record.srv_priority", "Priority [0]: ", "0")
        form["weight"] = ask("menu.dns.record.srv_weight", "Weight [0]: ", "0")
        form["port"] = ask("menu.dns.record.srv_port", "Port: ")
        form["target"] = ask("menu.dns.record.srv_target", "Target: ")
    return form


def _apply():
    """Purpose: run an apply from inside the menu without leaving it when the apply fails.
    Inputs:  none.
    Returns: None.
    Fails:   never for a failed apply (its exit is caught; the error was printed).
    Feeds:   edit_dns_zone."""
    try:
        apply_and_report()
    except SystemExit:
        pass


def edit_dns_zone(data, zone_key, domain):
    """Purpose: menu for one DNS zone: its sync state and records; add or delete a record, apply live, or force-recreate
             the zone.
    Inputs:  data — the vars working copy, refreshed from vars.yaml after each change (so a later save from the menu
             cannot overwrite it with a stale copy); zone_key — key under dns ("dynamic_zone_var" is the main domain);
             domain — the name shown for dynamic_zone_var. Prompts on stdin.
    Returns: None when "b" is picked.
    Fails:   ValidationError from add_record / remove_record is shown and the menu goes on. "f" (typed "force") stops
             bind9, deletes db.<zone> and its journal, applies and restarts bind9. EOFError/KeyboardInterrupt
             propagate.
    Feeds:   edit_dns."""
    shown = domain if zone_key == "dynamic_zone_var" else zone_key
    while True:
        zone = ((data.get("dns") or {}).get(zone_key)) or {}
        os.system("clear")
        print(f"{BOLD}--- DNS Zone: {shown} ---{NC}\n")
        state, message = sync_status(shown)
        print(f"  {SYNC_COLOURS.get(state, NC)}{message}{NC}\n")
        records, idx = {}, 1
        for rtype in RECORD_TYPES:
            for ridx, record in enumerate(zone.get(rtype) or []):
                print(f"  {idx}) [{rtype}] {record.get('name') or f'{RED}(missing name){NC}'} -> "
                      f"{format_value(rtype, record)}")
                records[idx] = (rtype, ridx, record.get("name") or "")
                idx += 1
        print("\n  a) Add new record")
        if records:
            print("  d) Delete record")
        print("  l) Live update (apply: publish changed zones)")
        print("  f) Force update (rm journal, recreate zone, restart bind9)")
        print("  b) Back to zones")
        choice = ask("menu.dns.zone.option", "Select an option: ").lower()
        if choice == "b":
            return
        try:
            if choice == "d" and records:
                pick = ask("menu.dns.zone.delete_pick", f"Enter record number to delete (1-{len(records)}): ")
                if pick.isdigit() and int(pick) in records:
                    rtype, ridx, name = records[int(pick)]
                    remove_record(menu_actor(), zone_key, rtype, ridx, name)
            elif choice == "a":
                rtype = ask("menu.dns.record.type", f"Record type ({', '.join(RECORD_TYPES)}): ").upper()
                if rtype:
                    add_record(menu_actor(), zone_key, rtype, _prompt_record(rtype))
        except ValidationError as exc:
            print(f"{RED}{exc}{NC}")
            ask("menu.continue", "Press Enter to continue...")
            continue
        data.clear()
        data.update(load_vars())
        if choice == "l":
            _apply()                       # the deploy engine freezes and thaws each changed zone itself
            ask("menu.continue", "Press Enter to continue...")
        elif choice == "f":
            print(f"\n{YELLOW}WARNING: This will delete the journal file, overwrite the zone data, and restart the "
                  f"BIND9 container.{NC}")
            if ask("menu.dns.zone.force_confirm", "Type 'force' to confirm: ").lower() == "force":
                subprocess.run(["systemctl", "stop", "bind9"])
                for suffix in ("", ".jnl"):
                    path = os.path.join(BIND_DATA_DIR, f"db.{shown}{suffix}")
                    if os.path.exists(path):
                        os.remove(path)
                        print(f"Removed {path}")
                print(f"{BLUE}Applying deployment to recreate zone...{NC}")
                _apply()
                print(f"{BLUE}Restarting BIND9 container...{NC}")
                subprocess.run(["systemctl", "restart", "bind9"])
                print(f"{GREEN}Force update complete.{NC}")
            ask("menu.continue", "Press Enter to continue...")
