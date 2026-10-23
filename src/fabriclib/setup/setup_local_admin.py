from fabriclib.common.console import ok, warn
from fabriclib.common.errors import ValidationError
from fabriclib.consent.check_consent import check_consent
from fabriclib.consent.plan_local_admin import plan_local_admin
from fabriclib.localadmin.check_local_admin import check_local_admin
from fabriclib.localadmin.common.local_admin_token import local_admin_token
from fabriclib.localadmin.ensure_local_admin import ensure_local_admin
from fabriclib.setup.errors import SetupError


def run(ctx):
    """Purpose: the fabric host's local-admin (decision 2.1.7.16, manual 1.7.1.4.1), as a setup step after OpenBao: with
             the `local_admin` host change approved, the account made (or kept) and its password set by OpenBao, then
             the hourly check run once (SSH refused unless the domain's switch is on, 2.1.7.19).
    Inputs:  ctx — SetupContext: vars, config_dir. OpenBao running and unsealed (after the vault step).
    Returns: None.
    Fails:   SetupError when OpenBao gives no token, or ensure_local_admin refuses (an account of the name fabric did
             not make; no sudo or wheel group; OpenBao or the host refusing).
    Feeds:   setup step `localadmin`, run by run_setup via STEPS."""
    if not check_consent(ctx.config_dir, "local_admin", plan_local_admin(ctx.vars)):
        return
    token, why = local_admin_token(ctx.vars)
    if token is None:
        raise SetupError(f"local-admin: {why}")
    try:
        done = ensure_local_admin(ctx.vars, ctx.config_dir, token)
    except ValidationError as e:
        raise SetupError(f"local-admin: {e}")
    for line in done or ["local-admin: kept as it is (its password in OpenBao)"]:
        ok(line)
    out = check_local_admin(ctx.vars, ctx.config_dir, "setup", "cli")
    for line in out["lines"]:
        (ok if out["ok"] else warn)(line)
