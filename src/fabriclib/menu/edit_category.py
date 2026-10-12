import os

from fabriclib.common.ask import ask
from fabriclib.common.console import BLUE, BOLD, GREEN, NC, RED, YELLOW
from fabriclib.common.paths import VARS_FILE
from fabriclib.menu.constants import IMMUTABLE_KEYS, WARNED_KEYS
from fabriclib.menu.edit_complex_variable import edit_complex_variable
from fabriclib.menu.parse_value import parse_value
from fabriclib.menu.save_menu_change import save_menu_change


def edit_category(title, data, keys):
    """Purpose: one category screen of the vars editor: list its settings, edit a plain one, open the editor of a
             dict or list.
    Inputs:  title — shown as the heading; data — the vars working copy; keys — a function giving the category's
             keys from data (so new keys show up while the screen is open).
    Returns: None when "b" is picked.
    Fails:   an IMMUTABLE_KEYS setting is refused with a message; OSError saving; EOFError from input().
    Feeds:   run_vars_menu (menus 3 and 6)."""
    while True:
        os.system("clear")
        print(f"{BOLD}--- {title} ---{NC}\n")
        shown = keys(data)
        if not shown:
            print(f"{YELLOW}No active variables in this category.{NC}")
        for i, k in enumerate(shown, 1):
            v = data[k]
            mark = (f" {BOLD}🔒 [IMMUTABLE]{NC}" if k in IMMUTABLE_KEYS
                    else f" {YELLOW}⚠️ [CAUTION]{NC}" if k in WARNED_KEYS else "")
            print(f"  {i}) {BLUE}{k}{NC}: {GREEN}{'(complex structure)' if isinstance(v, (dict, list)) else v}{NC}"
                  f"{mark}")
        print(f"\n  {BOLD}b{NC} Back to categories")
        pick = ask("menu.category.pick", f"Select a variable to edit (1-{len(shown)}) or 'b': ").lower()
        if pick == "b":
            return
        if not (pick.isdigit() and 1 <= int(pick) <= len(shown)):
            continue
        k = shown[int(pick) - 1]
        if k in IMMUTABLE_KEYS:
            print(f"\n{RED}Error: '{k}' is an immutable variable and cannot be changed post-deployment.{NC}")
            ask("menu.continue", "Press Enter to continue...")
            continue
        current = data[k]
        if isinstance(current, (dict, list)):
            edit_complex_variable(k, data)
            continue
        print(f"\nEditing: {BLUE}{k}{NC}")
        if k in WARNED_KEYS:
            print(f"{YELLOW}⚠️ WARNING: Editing this variable could impact network routing!{NC}")
        print(f"Current value: {GREEN}{current}{NC}")
        typed = ask(f"menu.vars.{k}", "New value (Enter to keep current, 'null' to clear): ")
        if typed:
            data[k] = parse_value(typed)
            save_menu_change(VARS_FILE, data, k, current, data[k])
            print(f"{GREEN}Saved.{NC}")
            ask("menu.continue", "Press Enter to continue...")
