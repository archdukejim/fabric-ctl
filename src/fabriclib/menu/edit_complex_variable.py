from fabriclib.common.ask import ask
from fabriclib.common.console import NC, YELLOW
from fabriclib.common.paths import VARS_FILE
from fabriclib.menu.constants import LIST_SCHEMAS
from fabriclib.menu.edit_dns import edit_dns
from fabriclib.menu.edit_list_of_dicts import edit_list_of_dicts


def edit_complex_variable(key, data):
    """Purpose: open the right editor for a dict or list setting picked on a category screen.
    Inputs:  key — the setting; data — the vars working copy.
    Returns: None. dns: edit_dns; tsig_keys, ldap_groups, ldap_organizational_units: edit_list_of_dicts with their
             fields; anything else: "No interactive editor exists" (edit vars.yaml by hand).
    Fails:   as the editor it opens.
    Feeds:   edit_category."""
    if key == "dns":
        edit_dns(data)
    elif key in LIST_SCHEMAS:
        edit_list_of_dicts(key, data, LIST_SCHEMAS[key])
    else:
        print(f"\n{YELLOW}No interactive editor exists for {key}. Please edit manually in {VARS_FILE}{NC}")
        ask("menu.continue", "Press Enter to continue...")
