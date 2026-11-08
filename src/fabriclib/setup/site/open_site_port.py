import subprocess

from fabriclib.common.ask import ask_yes_no
from fabriclib.security.ufw_active import ufw_active
from fabriclib.setup.errors import SetupError
from fabriclib.setup.site.site_rule import site_rule


def open_site_port(port, cidr, active=ufw_active, run=subprocess.run):
    """Purpose: when ufw is on it would block the site: opening it is a host change, so it is asked first, on the
             terminal (manual 1.3.6.7, global Rule 12), and undone when the site stops (close_site_port).
    Inputs:  port — int; cidr — the LAN (str or None); active — callable() -> bool (tests give their own); run —
             subprocess.run.
    Returns: True when a rule was added; False when ufw is off, so nothing blocks the site.
    Fails:   SetupError when declined (nothing changed, offering --terminal) or when ufw refuses; EOFError from input.
    Feeds:   setup/site/guided_site."""
    if not active():
        return False
    where = f"from {cidr}" if cidr else "from anywhere"
    if not ask_yes_no("setup.site_port", f"ufw is on and would block the setup site. Open TCP {port} {where} until the "
                                         "site stops", True):
        raise SetupError(f"without TCP {port} open a browser cannot reach the setup site. Open it yourself and run "
                         "setup again, or run Guided here: sudo fabricctl setup --terminal. Nothing was changed.")
    res = run(["ufw", "allow", *site_rule(port, cidr)], capture_output=True, text=True)
    if res.returncode != 0:
        raise SetupError(f"ufw would not open TCP {port}: {res.stderr.strip()}. Run Guided here instead: "
                         "sudo fabricctl setup --terminal. Nothing was changed.")
    return True
