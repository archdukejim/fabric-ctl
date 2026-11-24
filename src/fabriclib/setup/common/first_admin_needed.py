import os

from fabriclib.backup.restore_pending import read_restore_pending
from fabriclib.federation.common.is_root_site import is_root_site


def first_admin_needed(ctx):
    """Purpose: whether setup creates the first admin and so needs their password (2.1.6.33): a root site with the web
             console, whose directory does not exist yet. A restore of an online bundle (manual 1.3.7.6) brings the
             directory as a dump setup loads before the DC starts (restore-pending.json), so the DC's marker is not
             there yet but the directory, with its admins, is: no first admin then.
    Inputs:  ctx — SetupContext: vars (install_webui, install_keycloak), join_invitation, config_dir, deploy_base.
    Returns: bool.
    Fails:   errors of is_root_site reading federation.yaml; ValueError reading a restore-pending.json that is not
             JSON.
    Feeds:   setup/ask_first_admin, setup/advanced (the first admin item and Proceed's check), setup/choose_plan."""
    v = ctx.vars
    return bool(v.get("install_webui") and v.get("install_keycloak") and not ctx.join_invitation
                and is_root_site(os.path.join(ctx.config_dir, "federation.yaml"))
                and not os.path.exists(os.path.join(ctx.deploy_base, "samba", "data", ".fabric-provisioned"))
                and not read_restore_pending(ctx.config_dir).get("directory"))
