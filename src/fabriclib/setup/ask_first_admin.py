import os

from fabriclib.common.ask import ask_secret
from fabriclib.common.console import BOLD, NC, YELLOW
from fabriclib.federation.common.is_root_site import is_root_site
from fabriclib.samba.password_meets_policy import password_meets_policy
from fabriclib.setup.errors import SetupError


def ask_first_admin(ctx, needed=None):
    """Purpose: the first admin's password, chosen by the person setting fabric up (2.1.6.33): asked with the other
             questions, before any step, typed twice and checked against the domain's password policy; or read
             from --admin-password-file unattended (never on a command line, Rule 10). Kept in memory only.
    Inputs:  ctx — SetupContext: vars (install_webui, install_keycloak, webui_admin_user, ad_password_policy),
             config_dir, deploy_base, join_invitation, non_interactive, admin_password_file; needed — None to work it
             out (a root site whose directory does not exist yet: the admin step will create them), True to ask
             anyway (the admin step found no such person). Interactive unless a file is given.
    Returns: None; ctx.admin_password set when needed.
    Fails:   SetupError when unattended without --admin-password-file, or when that file's password is refused;
             OSError reading the file; EOFError from input.
    Feeds:   setup/run_setup (after the plan), setup/create_admin (needed=True)."""
    v = ctx.vars
    if needed is None:
        needed = (v.get("install_webui") and v.get("install_keycloak") and not ctx.join_invitation
                  and is_root_site(os.path.join(ctx.config_dir, "federation.yaml"))
                  and not os.path.exists(os.path.join(ctx.deploy_base, "samba", "data", ".fabric-provisioned")))
    if not needed or ctx.admin_password:
        return
    user, policy = v["webui_admin_user"], v["ad_password_policy"]
    if ctx.admin_password_file:
        with open(ctx.admin_password_file) as f:
            password = f.read().rstrip("\n")
        refused = password_meets_policy(password, user, policy)
        if refused:
            raise SetupError(f"the first admin's password in {ctx.admin_password_file} is refused: {refused}")
        ctx.admin_password = password
        return
    if ctx.non_interactive:
        raise SetupError(f"the first admin ({user}) needs a password: --admin-password-file FILE (2.1.6.33; never "
                         "on the command line)")
    print(f"\n  The first admin, {BOLD}{user}{NC}, signs in to the web console with a password you choose now "
          "(it is not shown or stored by setup).")
    while True:
        password = ask_secret("setup.admin_password", f"    Password for {user}: ")
        refused = password_meets_policy(password, user, policy)
        if refused:
            print(f"    {YELLOW}{refused}{NC}")
            continue
        if ask_secret("setup.admin_password_again", "    The same again: ") == password:
            ctx.admin_password = password
            return
        print(f"    {YELLOW}the two differ: once more{NC}")
