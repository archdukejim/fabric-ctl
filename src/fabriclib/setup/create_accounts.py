import subprocess

from fabriclib.common.console import ok
from fabriclib.consent.check_consent import check_consent
from fabriclib.consent.plan_accounts import plan_accounts


def run(ctx):
    """Purpose: one fabric-* system user and group per service, in fabric's uid band (600-649), so bind-mounted
             files have the right owner (manual 1.2.9.8). Asks nothing: the `accounts` consent was given before
             the first step.
    Inputs:  ctx — SetupContext: vars.service_users, config_dir (consent.yaml).
    Returns: None; accounts exist (nologin, no home). Idempotent.
    Fails:   SetupError from plan_accounts (an id taken by another account) or check_consent (not approved);
             CalledProcessError from groupadd/useradd.
    Feeds:   setup step `accounts`, run by run_setup via STEPS."""
    actions = plan_accounts(ctx.vars)
    if not actions:
        ok("service accounts in place")
        return
    check_consent(ctx.config_dir, "accounts", [a["text"] for a in actions])
    for a in actions:
        if a["do"] == "group":
            subprocess.run(["groupadd", "--system", "-g", str(a["gid"]), a["name"]], check=True)
        elif a["do"] == "user":
            subprocess.run(["useradd", "--system", "-u", str(a["uid"]), "-g", str(a["gid"]), "-M", "-d",
                            "/nonexistent", "-s", "/usr/sbin/nologin", a["name"]], check=True)
        ok(a["text"])
