import os

from fabriclib.common.ask import ask
from fabriclib.common.console import BOLD, NC, YELLOW
from fabriclib.common.paths import VARS_FILE
from fabriclib.menu.save_menu_change import save_menu_change


def _typed(text):
    """Purpose: one field as typed: "[a, b]" is a list, digits an int, anything else the text.
    Inputs:  text — str (not empty).
    Returns: list, int or str.
    Fails:   never.
    Feeds:   edit_list_of_dicts."""
    if text.startswith("[") and text.endswith("]"):
        return [v.strip() for v in text[1:-1].split(",")]
    return int(text) if text.isdigit() else text


def edit_list_of_dicts(key, data, schema):
    """Purpose: menu to add, change or delete entries of a list-of-mappings setting.
    Inputs:  key — the setting (e.g. tsig_keys); data — the vars working copy (data[key] made a list if it is not);
             schema — the field names asked for.
    Returns: None when "b" is picked; each change saved and audited.
    Fails:   no validation here (a bad entry is refused at apply); OSError saving; EOFError from input().
    Feeds:   run_vars_menu (menu 4, tsig_keys), edit_complex_variable."""
    if not isinstance(data.get(key), list):
        data[key] = []
    items = data[key]
    while True:
        os.system("clear")
        print(f"{BOLD}--- Editor: {key} ---{NC}\n")
        if not items:
            print(f"{YELLOW}No custom entries defined. System defaults will be used.{NC}")
        for i, item in enumerate(items, 1):
            print(f"  {i}) {item.get('name', f'Item {i}')}")
            for k, v in item.items():
                if k != "name":
                    print(f"      {k}: {v}")
        print("\n  a) Add new entry")
        if items:
            print("  m) Modify entry")
            print("  d) Delete entry")
        print("  b) Back to variables")
        choice = ask(f"menu.list.{key}.option", "Select an option: ").lower()
        if choice == "b":
            return
        if choice == "a":
            print(f"\nAdding new entry to {key}:")
            new = {f: _typed(val) for f in schema if (val := ask(f"menu.list.{key}.add.{f}", f"  {f}: "))}
            if new:
                items.append(new)
                save_menu_change(VARS_FILE, data, key, "None", str(new))
        elif choice in ("m", "d") and items:
            pick = ask(f"menu.list.{key}.pick",
                       f"Enter item number to {'modify' if choice == 'm' else 'delete'} (1-{len(items)}): ")
            if not (pick.isdigit() and 1 <= int(pick) <= len(items)):
                continue
            idx = int(pick) - 1
            if choice == "d":
                del items[idx]
                save_menu_change(VARS_FILE, data, key, "item", "None", "DELETED")
                continue
            item = items[idx]
            print(f"\nModifying entry {idx + 1}:")
            for f in schema:
                val = ask(f"menu.list.{key}.edit.{f}", f"  {f} [{item.get(f, '')}]: ")
                if val:
                    item[f] = _typed(val)
            save_menu_change(VARS_FILE, data, key, "old", str(item))
