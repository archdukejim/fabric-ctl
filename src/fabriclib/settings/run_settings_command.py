import os
import sys

import yaml

from fabriclib.common.ask import ask_yes_no
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.paths import DEPLOY_BASE_DIR, VARS_FILE
from fabriclib.samba.dc_provisioned import dc_provisioned
from fabriclib.samba.refuse_named_dc import refuse_named_dc
from fabriclib.settings.apply_settings import apply_settings
from fabriclib.settings.export_settings import export_settings
from fabriclib.settings.parse_settings_file import parse_settings_file
from fabriclib.settings.plan_settings import plan_settings
from fabriclib.system.version_info import version_info

USAGE = """usage: fabricctl settings export [FILE]       the wizard's settings into a settings file (no FILE: printed)
       fabricctl settings import FILE [--yes] a settings file's plan, then one apply (asked first, unless --yes)"""


def _actor():
    """Purpose: who changes the settings from the host, for the audit log: root, and the account that ran sudo.
    Inputs:  env SUDO_USER.
    Returns: str ("root" or "root (sudo by <user>)").
    Fails:   never.
    Feeds:   run_settings_command."""
    who = os.environ.get("SUDO_USER")
    return f"root (sudo by {who})" if who and who != "root" else "root"


def _print_plan(plan):
    """Purpose: a plan as the console shows it (manual 1.8.5.5): each change old → new, the parts started or stopped,
             the memory plan, what the file's import ignored and why.
    Inputs:  plan — plan_settings' result.
    Returns: None; prints.
    Fails:   never.
    Feeds:   run_settings_command."""
    print("The plan (nothing has changed yet):")
    for c in plan["changes"]:
        print(f"  {c['key']}: {c['old']} -> {c['new']}")
    if not plan["changes"]:
        print("  nothing changes: the settings are already so")
    for p in plan["parts"]:
        print(f"  {p['service']}: {p['change']}")
    if plan["memory"]:
        print(f"  memory, a budget of {plan['memory']['budget_mb']} MB:")
        for r in plan["memory"]["rows"]:
            print(f"    {r['service']}: {r['before'] if r['before'] is not None else '—'} -> "
                  f"{r['after'] if r['after'] is not None else '—'} MB")
    for i in plan["ignored"]:
        print(f"  ignored: {i['key']} ({i['reason']})")


def run_settings_command(argv, vars_file=VARS_FILE):
    """Purpose: `fabricctl settings` — the setup wizard's settings file on a host without a browser (manual 1.8.5.4):
             export writes every wizard setting (no secret, nothing console-only); import reads a file, lists what it
             ignores and why, shows the plan, and after a yes (or --yes) runs one apply, audited as SETTINGS_CHANGE
             from cli. Only routes to the settings/ units and prints.
    Inputs:  argv — list of str after "settings": export [FILE] | import FILE [--yes]; vars_file — the install's
             vars.yaml (tests: a scratch one).
    Returns: exit status: 0 exported, applied, nothing to change, or not confirmed (nothing changed); 1 refused (a file
             that cannot be read or is not a settings file, an invalid wizard value, a dc_name while this host has no
             installed DC (fabric names DCs itself, 2.1.6.65; on an installed host it is ignored as console-only):
             nothing changed) or the apply failed ("error: …" on stderr); 2 usage.
    Fails:   OSError writing the export or from the settings and audit files; subprocess.TimeoutExpired from the apply;
             EOFError when the question cannot be asked (no --yes and no terminal).
    Feeds:   fabriclib/cli.py (`fabricctl settings`)."""
    args = [a for a in argv if a not in ("--yes", "-y")]
    yes = len(args) != len(argv)
    if args[:1] == ["export"] and len(args) <= 2 and not yes:
        res = export_settings(load_vars(vars_file), version_info()["version"])
        if len(args) == 1:
            sys.stdout.write(res["text"])
            return 0
        fd = os.open(args[1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(res["text"])
        print(f"the setup wizard's settings: {args[1]} (import it with sudo fabricctl settings import {args[1]}, or "
              "the console's Settings)")
        return 0
    if args[:1] != ["import"] or len(args) != 2:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        with open(args[1], encoding="utf-8") as f:
            text = f.read(256 * 1024)
    except (OSError, UnicodeDecodeError) as e:
        print(f"error: cannot read {args[1]}: {e}", file=sys.stderr)
        return 1
    v = load_vars(vars_file)
    try:
        parsed = parse_settings_file(text, known=v)
        if any(i["key"] == "dc_name" for i in parsed["ignored"]):      # fabric names its DCs (2.1.6.65)
            refuse_named_dc(yaml.safe_load(text)["settings"], dc_provisioned(v.get("deploy_base_dir")
                                                                             or DEPLOY_BASE_DIR),
                            f"the settings file {args[1]}")
        plan = plan_settings(v, parsed["settings"], parsed["ignored"], source="cli")
    except ValidationError as e:
        print(f"error: {e} (nothing changed)", file=sys.stderr)
        return 1
    _print_plan(plan)
    if not plan["keys"]:
        return 0
    if not yes and not ask_yes_no("settings.import.apply", "Apply this plan now", False):
        print("Nothing changed.")
        return 0
    try:
        res = apply_settings(plan, _actor())
    except ValidationError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(res["output"].rstrip()[-1500:])
    print(res["message"], file=sys.stdout if res["ok"] else sys.stderr)
    return 0 if res["ok"] else 1
