from fabriclib.common.ask import ask
from fabriclib.setup.common.first_admin_refused import first_admin_refused
from fabriclib.setup.common.valid_setting import LABELS


def ask_admin_fact(key, default):
    """Purpose: one of the first Directory Administrator's facts (user name, full name, e-mail; 2.1.6.69), asked until
             it is taken, saying why an answer is not.
    Inputs:  key — webui_admin_user, webui_admin_name or webui_admin_email; default — the value offered (Enter takes
             it) or None.
    Returns: str, the answer.
    Fails:   EOFError from input.
    Feeds:   setup/ask_first_admin, setup/advanced/ask_first_admin_item."""
    while True:
        answer = ask(f"setup.vars.{key}", f"  {LABELS[key]} [{default or ''}]: ", default or "").strip()
        why = first_admin_refused(key, answer)
        if why is None:
            return answer
        print(f"    not a valid {key}: {why}")
