import os
import sys

# colour only on a terminal, never with NO_COLOR set (no-color.org): the words stay, uncoloured
_TTY = sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and not os.environ.get("NO_COLOR")
BOLD, BLUE, GREEN, YELLOW, RED, NC = (("\033[1m", "\033[94m", "\033[92m", "\033[93m", "\033[91m", "\033[0m")
                                      if _TTY else ("",) * 6)


def heading(text):
    """Purpose: print a bold section heading (preceded by a blank line) to stdout.
    Inputs:  text — str, the heading. Colour only when stdout is a terminal and TERM is not "dumb".
    Returns: None.
    Fails:   never in practice — only an OSError from writing to a closed stdout.
    Feeds:   setup/run_setup.py, setup/choose_plan.py (console output only)."""
    print(f"\n{BOLD}{text}{NC}", flush=True)


def info(text):
    """Purpose: print an indented informational line ("·") to stdout.
    Inputs:  text — str, the message. Colour only on a terminal.
    Returns: None.
    Fails:   never in practice — only an OSError from writing to a closed stdout.
    Feeds:   setup steps (collect_vars, condition_host, configure_firewall, create_admin, init_pki, …)."""
    print(f"  {BLUE}·{NC} {text}", flush=True)


def ok(text):
    """Purpose: print an indented success line ("✓") to stdout.
    Inputs:  text — str, the message. Colour only on a terminal.
    Returns: None.
    Fails:   never in practice — only an OSError from writing to a closed stdout.
    Feeds:   most setup steps (deploy_config, start_services, verify_install, …) and run_setup."""
    print(f"  {GREEN}✓{NC} {text}", flush=True)


def warn(text):
    """Purpose: print an indented warning line ("!") to stdout (not stderr).
    Inputs:  text — str, the message. Colour only on a terminal.
    Returns: None.
    Fails:   never in practice — only an OSError from writing to a closed stdout.
    Feeds:   setup steps (configure_firewall, create_accounts, create_admin, harden_docker, preflight, …)."""
    print(f"  {YELLOW}!{NC} {text}", flush=True)


def err(text):
    """Purpose: print an indented error line ("✗") to stderr.
    Inputs:  text — str, the message. Colour follows stdout being a terminal (not stderr).
    Returns: None.
    Fails:   never in practice — only an OSError from writing to a closed stderr.
    Feeds:   setup/run_setup.py, setup/verify_install.py."""
    print(f"  {RED}✗{NC} {text}", file=sys.stderr, flush=True)
