import os
import sys

from fabriclib.common.console import BOLD, NC, RED
from fabriclib.common.load_vars import load_vars
from fabriclib.common.paths import VARS_FILE
from fabriclib.menu.apply_and_report import apply_and_report
from fabriclib.menu.constants import IMMUTABLE_KEYS, LIST_SCHEMAS, SERVICE_KEYS, WARNED_KEYS
from fabriclib.menu.edit_category import edit_category
from fabriclib.menu.edit_dns import edit_dns
from fabriclib.menu.edit_links import edit_links
from fabriclib.menu.edit_list_of_dicts import edit_list_of_dicts
from fabriclib.menu.mint_certificate_menu import mint_certificate_menu
from fabriclib.menu.parse_value import parse_value
from fabriclib.menu.save_menu_change import save_menu_change

OWN_SCREENS = set(SERVICE_KEYS) | {"dns", "tsig_keys", "domain"}


def run_vars_menu():
    """Purpose: `fabricctl --interactive` (and `fabricctl` alone): the vars editor — DNS, certificates, services,
             TSIG keys, links, everything else; add or delete a setting; apply.
    Inputs:  none; this install's vars.yaml; prompts on stdin.
    Returns: never normally: sys.exit(0) on q/quit/exit or after an apply.
    Fails:   sys.exit with the apply's code when it fails; OSError saving; EOFError from input().
    Feeds:   interactive.py --interactive (cli.py --interactive).
    Notes:   every change is saved at once (under the vars lock) and audited; IMMUTABLE_KEYS cannot be deleted,
             edited or added over; changed WARNED_KEYS ask for "yes" before an apply (compared with the vars last
             deployed)."""
    data = load_vars(VARS_FILE)
    deployed = dict(data)
    while True:
        os.system("clear")
        print(f"{BOLD}--- Interactive Variables Editor ---{NC}\n")
        for i, title in enumerate(("DNS Configuration", "Mint Certificates", "Docker & Services", "TSIG Keys",
                                   "Landing Page Links", "Advanced Configuration"), 1):
            print(f"  {BOLD}{i}{NC}) {title}")
        print("\nOptions:")
        print(f"  {BOLD}a{NC}    Add new variable")
        print(f"  {BOLD}d{NC}    Delete variable")
        print(f"  {BOLD}apply{NC} Save and Apply changes")
        print(f"  {BOLD}q{NC}    Quit without applying\n")
        choice = input("Select a category (1-6), or option: ").strip().lower()

        if choice in ("q", "quit", "exit"):
            print("Exiting.")
            sys.exit(0)
        if choice == "apply":
            warned = [k for k in WARNED_KEYS if k in data and k in deployed and data[k] != deployed[k]]
            if warned:
                print(f"\n{RED}{BOLD}[WARNING]{NC} You are about to apply changes to highly sensitive network "
                      f"configurations: {', '.join(warned)}")
                print("This may break routing and require widespread restarts.")
                if input("Are you absolutely sure you want to apply? (type 'yes'): ").strip().lower() != "yes":
                    continue
            print("Applying changes...")
            apply_and_report()
            sys.exit(0)
        if choice == "a":
            key = input("New variable key: ").strip()
            if key in IMMUTABLE_KEYS and key in data:      # adding over one would change it (dc_name: 2.1.6.45)
                print(f"{RED}Cannot change immutable key: {key}{NC}")
                input("Press Enter to continue...")
            elif key:
                data[key] = parse_value(input(f"Value for {key} (Enter for null): ").strip())
                save_menu_change(VARS_FILE, data, key, "None", data[key], "ADDED")
        elif choice == "d":
            key = input("Variable key to delete: ").strip()
            if key in IMMUTABLE_KEYS:
                print(f"{RED}Cannot delete immutable key: {key}{NC}")
                input("Press Enter to continue...")
            elif key in data:
                old = data.pop(key)
                save_menu_change(VARS_FILE, data, key, old, "None", "DELETED")
        elif choice == "1":
            edit_dns(data)
        elif choice == "2":
            mint_certificate_menu(data)
        elif choice == "3":
            edit_category("Docker & Services", data, lambda d: [k for k in SERVICE_KEYS if k in d])
        elif choice == "4":
            edit_list_of_dicts("tsig_keys", data, LIST_SCHEMAS["tsig_keys"])
        elif choice == "5":
            edit_links()
        elif choice == "6":
            edit_category("Advanced Configuration", data, lambda d: [k for k in d if k not in OWN_SCREENS])
