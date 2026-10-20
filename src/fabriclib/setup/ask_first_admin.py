from fabriclib.common.ask import ask_secret
from fabriclib.common.console import NC, YELLOW
from fabriclib.samba.password_meets_policy import password_meets_policy
from fabriclib.setup.common.ask_admin_fact import ask_admin_fact
from fabriclib.setup.common.first_admin_needed import first_admin_needed
from fabriclib.setup.common.first_admin_refused import KEYS, first_admin_refused
from fabriclib.setup.errors import SetupError


def ask_first_admin(ctx, needed=None):
    """Purpose: the first Directory Administrator, named by the person setting fabric up straight after `fabric-admin`
             (2.1.6.69, 2.1.6.93): their user name (never fabric-admin or another of fabric's names), first and
             last names (required) and e-mail address (optional; data, nothing is sent), and their password, typed
             twice and checked against the domain's password policy. Asked with the other questions, before any
             step; unattended, the facts come from the vars file (--file) and the password from --admin-password-file
             (never on a command line, Rule 10). The password is kept in memory only.
    Inputs:  ctx — SetupContext: vars (install_webui, install_keycloak, webui_admin_user, webui_admin_first_name,
             webui_admin_last_name, webui_admin_email, ad_password_policy, ad_tier_password_policies; the facts are
             set here), config_dir,
             deploy_base, join_invitation, non_interactive, admin_password_file; needed — None to work it out (a root
             site whose directory does not exist yet: the admin step will create them), True to ask anyway (the admin
             step found no such person). Interactive unless unattended.
    Returns: None; ctx.vars' four facts and ctx.admin_password set when needed.
    Fails:   SetupError unattended when a fact is missing or refused (naming every such key and why), without
             --admin-password-file, or when that file's password is refused; OSError reading the file; EOFError
             from input.
    Feeds:   setup/run_setup (before the plan), setup/advanced/ask_first_admin_item and setup/create_admin
             (needed=True)."""
    v = ctx.vars
    if needed is None:
        needed = first_admin_needed(ctx)
    if not needed:
        return
    refused = {key: first_admin_refused(key, v.get(key)) for key in KEYS}
    if ctx.non_interactive and any(refused.values()):   # every key to add at once (a 0.7.x file has none: 3.3.5.4)
        raise SetupError("the first Directory Administrator (2.1.6.69) needs "
                         + "; ".join(f"{key} in the vars file: {why}" for key, why in refused.items() if why))
    for key, why in refused.items():
        v[key] = str(v.get(key) or "").strip() if why is None else ask_admin_fact(key, v.get(key))
    if ctx.admin_password:
        return
    # theirs is the Directory Administrators' own policy once setup has it (2.1.6.71), else the domain's
    user = v["webui_admin_user"]
    policy = (v.get("ad_tier_password_policies") or {}).get("directory_admins") or v["ad_password_policy"]
    if ctx.admin_password_file:
        with open(ctx.admin_password_file) as f:
            password = f.read().rstrip("\n")
        refused = password_meets_policy(password, user, policy)
        if refused:
            raise SetupError(f"the first admin's password in {ctx.admin_password_file} is refused: {refused}")
        ctx.admin_password = password
        return
    if ctx.non_interactive:
        raise SetupError(f"the first admin ({user}) needs a password: --admin-password-file FILE (2.1.6.69; never "
                         "on the command line)")
    while True:
        password = ask_secret("setup.admin_password", f"    Password for {user} (web console sign-in, not shown): ")
        refused = password_meets_policy(password, user, policy)
        if refused:
            print(f"    {YELLOW}{refused}{NC}")
            continue
        if ask_secret("setup.admin_password_again", "    The same again: ") == password:
            ctx.admin_password = password
            return
        print(f"    {YELLOW}the two differ: once more{NC}")
