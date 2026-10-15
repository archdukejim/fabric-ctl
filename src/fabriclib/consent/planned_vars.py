import os

from fabriclib.common.errors import ValidationError
from fabriclib.common.jinja_env import jinja_env
from fabriclib.deploy.render_vars import render_vars
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.setup.errors import SetupError


def planned_vars(ctx):
    """Purpose: the settings this setup run will render, before anything is deployed, so the host-change
             questions come at the start (manual 1.2.9.4, step 1).
    Inputs:  ctx — SetupContext: vars (collected and chosen settings), source_dir (fabric's tree: jinja/),
             secrets_file (read when it exists; a fresh install renders without secrets).
    Returns: the rendered settings (dict), as render_vars returns them.
    Fails:   SetupError with render_vars' refusal (a plan whose memory does not fit, 1.2.4.3; any setting it refuses);
             errors from load_secrets on an unreadable secrets file.
    Feeds:   setup/run_setup and setup/choose_plan (plan_host_changes)."""
    secrets = load_secrets(ctx.secrets_file, ctx.vars or None) if os.path.exists(ctx.secrets_file) else {}
    try:
        final, _ = render_vars(jinja_env(os.path.join(ctx.source_dir, "jinja")), secrets or {}, dict(ctx.vars))
    except ValidationError as e:            # said, not traced: the plan shows it and setup stops
        raise SetupError(str(e)) from None
    return final
