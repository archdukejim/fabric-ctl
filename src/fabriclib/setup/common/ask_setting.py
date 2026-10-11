from fabriclib.common.ask import ask
from fabriclib.setup.common.valid_setting import LABELS, valid_setting


def ask_setting(key, default):
    """Purpose: prompt until the operator gives a valid value for one setting (guided mode, and the menu's item for it:
             the same question, 2.1.2.19).
    Inputs:  key — setting name (label from LABELS); default — offered value (Enter accepts it) or None.
    Returns: the valid answer (str).
    Fails:   EOFError from input() when stdin is closed; loops on invalid input by design, saying "not a valid <key>".
    Feeds:   setup/collect_vars, setup/advanced (domain, hostname, organisation, network, first admin)."""
    while True:
        answer = ask(f"setup.vars.{key}", f"  {LABELS.get(key, key)} [{default or ''}]: ", default or "")
        if valid_setting(key, answer):
            return answer
        print(f"    not a valid {key}")
