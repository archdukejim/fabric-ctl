import subprocess
import sys

from fabriclib.common.ask import ask
from fabriclib.common.console import YELLOW, NC
from fabriclib.common.errors import ValidationError
from fabriclib.ipam.check_block import check_block
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.set_block import set_block
from fabriclib.ipam.suggestions import suggest_block


def ask_site_number(v, secrets, non_interactive, container="samba", tty=None):
    """Purpose: setup's question for the site's number (manual 1.10.4.13.4, 1.10.4.18.1; decision 2.1.10.16), asked
             once, after the domain controller runs and before the upgrade moves 0.7's subnets: the second octet of
             what fabric suggests (`10.<n>.<VLAN>.0/24`), the suggestion (its order in the organisation, or the next
             free number) its default. Asked only while the site has no number; changed later with `fabricctl ipam
             block`. Unattended (--non-interactive, or no terminal: setup's worker, 1.3.2) the suggestion is taken. A
             site with a read-only DC is not asked: setup names the command that sets it.
    Inputs:  v — rendered settings (site_name, ad_dc_type); secrets — fabric's secrets (ad_agent_password);
             non_interactive — take the suggestion without asking; container — the DC's container (tests name
             their own); tty — whether a person answers (None: stdin is a terminal). Interactive: question
             "setup.site_number"; Enter takes the suggestion, a number that is not 1-255 or another site's is
             refused, saying why, and asked again.
    Returns: list of str to show ([] when the site already has a number).
    Fails:   EOFError / KeyboardInterrupt from ask(); never for the domain: a DC not answering or refusing the write
             leaves the number for later, and says so.
    Feeds:   setup/start_services (the start step, after convergence)."""
    site = v.get("site_name")
    if not site:
        return []
    try:
        read = read_plan(v, secrets, of=site, container=container)
    except (ValidationError, OSError, subprocess.TimeoutExpired) as e:
        return [f"site number: not asked now, the domain did not answer ({e}); set it later with "
                "fabricctl ipam block <n> (fabric suggests one until then)"]
    if site_plan(read, site)["block"] is not None:
        return []
    suggestion = suggest_block(read["sites"], site)
    if v.get("ad_dc_type") == "rodc":
        return [f"site number: not asked, this site's DC is read-only; set it with fabricctl ipam block "
                f"{suggestion or '<n>'} (written at its writable partner DC)"]
    chosen = suggestion
    person = sys.stdin.isatty() if tty is None else tty
    if not non_interactive and person:
        print("\n  The site's number is the second octet of the subnets fabric suggests: 10.<number>.<VLAN>.0/24.")
        while True:
            answer = ask("setup.site_number", f"    Site number [{suggestion or ''}]: ", default=str(suggestion or ""))
            try:
                chosen = check_block(answer, read["sites"], site)
                break
            except ValidationError as e:
                print(f"    {YELLOW}{e}{NC}")
    if not chosen:
        return ["site number: every number from 1 to 255 is taken; none given"]
    try:
        set_block(v, "setup", chosen, secrets=secrets, container=container, source="setup")
    except (ValidationError, OSError, subprocess.TimeoutExpired) as e:
        return [f"site number: {chosen} could not be written ({e}); set it later with fabricctl ipam block {chosen}"]
    return [f"site number: {chosen} (fabricctl ipam block to change it)"]
