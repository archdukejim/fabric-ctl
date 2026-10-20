import os

import yaml

from fabriclib.common.console import info
from fabriclib.common.errors import ValidationError
from fabriclib.samba.check_password_policy import DEFAULT_POLICY, POLICY_KEYS
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.federation.decode_invitation import decode_invitation
from fabriclib.federation.upstream_version_problem import upstream_version_problem
from fabriclib.samba.dc_provisioned import dc_provisioned
from fabriclib.samba.refuse_named_dc import refuse_named_dc
from fabriclib.setup.detect_network import detect_network
from fabriclib.security.check_signin_lowering import check_signin_lowering
from fabriclib.setup.ask_ad_domain import ask_ad_domain
from fabriclib.samba.tier_policy_defaults import tier_policy_defaults
from fabriclib.setup.common.ask_setting import ask_setting
from fabriclib.setup.common.network_problem import network_problem
from fabriclib.setup.common.valid_setting import REQUIRED, valid_setting
from fabriclib.setup.errors import SetupError
from fabriclib.setup.finish_vars import finish_vars
from fabriclib.setup.move_dns_filter import move_dns_filter
from fabriclib.setup.set_ram_capacity import set_ram_capacity
from fabriclib.setup.upgrade_vars import upgrade_vars

def _load(path):
    """Purpose: read a YAML vars file if it exists.
    Inputs:  path — file path or None/"".
    Returns: the parsed dict; {} when path is empty, missing or the file is empty.
    Fails:   OSError if unreadable; yaml.YAMLError if it does not parse.
    Feeds:   collect_vars."""
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _join_defaults(ctx, data):
    """Purpose: settings a site joining an upstream (setup --join) starts from: the invitation's site name and
             organisation domain, and a domain of its own, by default <site>.<organisation domain>.
    Inputs:  ctx — SetupContext: join_invitation, vars_file, config_dir; data — the settings so far (changed).
    Returns: None; data gets site_name, org_domain, ldap_base_dn, (unless set) domain and, from an invitation that
             names the domain (any site with a writable DC makes one), ad_domain, ad_password_policy and ad_dc_type
             (so setup asks neither).
    Fails:   SetupError when the invitation is damaged (decode_invitation) or comes from an upstream older than
             0.8.0 (upstream_version_problem), when this host already has a fabric
             that is not a member of that upstream (only fresh installs join: design F1), or when site_name is
             set to another name than the invitation's.
    Feeds:   collect_vars."""
    try:
        inv = decode_invitation(ctx.join_invitation)
    except ValidationError as e:
        raise SetupError(str(e)) from None
    problem = upstream_version_problem(inv)            # before anything is asked or done (2.1.6.65's revision)
    if problem:
        raise SetupError(problem)
    upstream = load_registry(os.path.join(ctx.config_dir, "federation.yaml"))["upstream"]
    if os.path.exists(ctx.vars_file) and not (upstream and upstream.get("site_name") == inv["upstream"]):
        raise SetupError("only a fresh install can join a fabric: this host already has one "
                         "(fabricctl uninstall first, or invite it later when existing installs can join)")
    if data.get("site_name") and str(data["site_name"]).lower() != inv["site"]:
        raise SetupError(f"the invitation is for site {inv['site']}, but site_name is {data['site_name']}")
    data["site_name"], data["org_domain"], data["ldap_base_dn"] = inv["site"], inv["org_domain"], inv["ldap_base_dn"]
    if not data.get("domain"):
        data["domain"] = f"{inv['site']}.{inv['org_domain']}"
    if inv["dc"]:                            # the organisation's domain: this site's DC joins it (manual 1.9.8.4)
        data["ad_domain"], data["ad_password_policy"] = inv["ad_domain"], inv["ad_password_policy"]
        data["ad_dc_type"] = inv["dc"]
    info(f"joining {inv['upstream']} ({inv['org_domain']}) as site {inv['site']}, domain {data['domain']}")


def collect_vars(ctx, ask=True):
    """Purpose: work out the settings this install is rendered from and save them as <config>/fabric.yaml.
    Inputs:  ctx — SetupContext: user_vars_file (--file), join_invitation (--join: _join_defaults), non_interactive,
             vars_file (existing install),
             source_dir (a checkout's ../custom-vars.yaml), config_dir, secrets_file, deploy_base;
             ask — False for Advanced (2.1.2.19): nothing is asked here,
             the menu asks what is missing and finish_vars runs after it.
    Returns: path of fabric.yaml (str), or None with ask=False (not saved yet). Leaves ctx.vars = the data and
             ctx.fresh_install set. Precedence: an existing
             vars.yaml is the base and --file overrides the keys it sets; on a fresh install without --file a
             checkout's custom-vars.yaml is used. Existing installs keep their digest-pinned images
             (upgrade_vars); image_* keys set explicitly are recorded in image_pins. AdGuard Home's settings move to
             the BIND resolver's (move_dns_filter, 0.7). Missing/invalid required
             values are asked for (defaults from detect_network; the first admin by ask_first_admin); the AD domain
             is asked when missing (ask_ad_domain); the DC's name is never asked (fabric names it,
             finish_vars' name_dc, 2.1.6.65): a --file or custom-vars.yaml that names it is refused while no DC is
             installed, and on an installed host the installed DC's name is kept over the file's; the rest takes
             defaults changed later (2.1.2.16): the password
             policy (DEFAULT_POLICY, a vars file's keys kept, 2.1.6.35), the memory (set_ram_capacity) and, on a
             fresh install only (no vars file, no provisioned domain), who may sign in to the site's machines
             (finish_vars). Embedded TSIG secrets go to the secrets file, never into fabric.yaml (finish_vars).
    Fails:   SetupError for a --file that would lower a sign-in layer (check_signin_lowering) or that names the DC
             for a new install (refuse_named_dc, nothing changed), for missing/invalid
             required values (the AD domain included) with
             --non-interactive, invalid tsig_keys, or a
             secrets file that cannot be written (ValidationError converted); OSError/yaml errors on files.
    Feeds:   run_setup main (before the first admin, the menu, choose_plan and the steps); ctx.vars feeds
             them and the steps before deploy; deploy_config renders from fabric.yaml."""
    data = {}
    user_file = ctx.user_vars_file
    # a fresh install: no settings yet and no domain provisioned (an upgrade or a reinstall keeps its settings)
    provisioned = dc_provisioned(ctx.deploy_base)
    fresh = not os.path.exists(ctx.vars_file) and not provisioned
    repo_vars = os.path.join(os.path.dirname(ctx.source_dir), "custom-vars.yaml")
    user = _load(user_file) if user_file else {}
    if os.path.exists(ctx.vars_file):
        # An existing install's values (incl. DNS records added in the web UI
        # or editor) are the base; a --file only overrides the keys it sets.
        data = _load(ctx.vars_file)
        info(f"current settings from {ctx.vars_file}")
        # The images this host runs are kept (a fabric upgrade never changes
        # them: `fabricctl images update` does). Images the admin set
        # explicitly (a vars file now or earlier, recorded in image_pins) are
        # also left alone by `images update`.
        explicit = {**_load(repo_vars), **user}
        pins = set(data.get("image_pins") or []) | {k for k in explicit if k.startswith("image_")}
        data["image_pins"] = sorted(pins)
        for change in upgrade_vars(data, {k: True for k in pins}):
            info(change)
    elif not user_file and os.path.exists(repo_vars):
        # Fresh install from a checkout with the classic custom-vars.yaml.
        # Never on an existing install: it would undo later edits.
        user_file, user = repo_vars, _load(repo_vars)
    if user_file:
        try:                                  # a --file never lowers a sign-in layer (2.1.6.24): the command does
            check_signin_lowering(_load(ctx.vars_file) if os.path.exists(ctx.vars_file) else {}, user)
            refuse_named_dc(user, provisioned, f"the vars file {user_file}")     # fabric names its DCs (2.1.6.65)
        except ValidationError as e:
            raise SetupError(str(e))
        if provisioned and data.get("dc_name") and "dc_name" in user:     # installed: the DC keeps its name
            if str(user["dc_name"]).strip().lower() != str(data["dc_name"]).lower():
                info(f"dc_name in {user_file} ignored: the installed domain controller keeps its name (2.1.6.65)")
            user = {k: val for k, val in user.items() if k != "dc_name"}
        data.update(user)
        info(f"overrides from {user_file}")
    # 0.7: AdGuard Home's settings move to the BIND resolver (2.1.12.3); nothing to do on a host without them
    for line in move_dns_filter(data, ctx.deploy_base, ctx.config_dir):
        info(line)

    if ctx.join_invitation:
        _join_defaults(ctx, data)

    ctx.fresh_install = fresh
    if ask or ctx.non_interactive:
        bad = [k for k in REQUIRED if not valid_setting(k, str(data.get(k) or ""))]
        if bad:
            if ctx.non_interactive:
                raise SetupError(f"missing or invalid in the vars file: {', '.join(bad)}")
            guess = {**detect_network(), "domain": "home.arpa"}
            print("\n  A few details about this network:")
            for key in bad:
                data[key] = ask_setting(key, data.get(key) or guess.get(key))
        # the network's answers together: the host in its subnet, the gateway too and not the host, the host's own
        # address
        while (problem := network_problem(data)):
            if ctx.non_interactive:
                raise SetupError(problem)
            print(f"    {problem}: asked again")
            guess = detect_network()           # offered first: the bad answer would be offered back otherwise
            for key in ("host_ip", "lan_cidr", "lan_gateway"):
                data[key] = ask_setting(key, guess.get(key) or data.get(key))
        if not valid_setting("friendly_name", str(data.get("friendly_name") or "")):
            if ctx.non_interactive and data.get("friendly_name"):
                raise SetupError("friendly_name: 1-40 printable characters without quotes, backslashes or <>")
            data["friendly_name"] = ("Home Network" if ctx.non_interactive
                                     else ask_setting("friendly_name", "Home Network"))

        # the first Directory Administrator (user name, first and last names, an optional e-mail, password) is asked
        # by ask_first_admin, only when setup creates them (2.1.6.69, 2.1.6.93)

        # The directory (manual 1.6.3): the AD domain is asked (permanent, 2.1.6.11); its password policy starts from
        # the default, a vars file's keys kept, and is changed later (2.1.6.35, 2.1.2.16)
        if not data.get("ad_domain"):
            if ctx.non_interactive:
                raise SetupError("missing in the vars file: ad_domain (manual 1.1.9.7: the directory's domain is "
                                 "permanent and has no default)")
            ctx.vars = data
            ask_ad_domain(ctx)
    policy = data.get("ad_password_policy") or {}
    if not (set(POLICY_KEYS) | {"complexity"}) <= set(policy):
        data["ad_password_policy"] = {**DEFAULT_POLICY, **policy}
        info("password policy: fabric's default (2.1.6.35), change it any time: sudo fabricctl domain password-policy")
    # the tiers' own policies (2.1.6.71): copies of the default at the install that adds them, set on the host after
    tiers = tier_policy_defaults(data["ad_password_policy"], data.get("ad_tier_password_policies"))
    if tiers != data.get("ad_tier_password_policies"):
        data["ad_tier_password_policies"] = tiers
        info("the tiers' password policies: fabric-admin's (3 failed sign-ins, then 15 minutes) and the Directory "
             "Administrators', copies of the default; on this host: sudo fabricctl domain password-policy --tier")
    # how much of this host fabric may use (2.1.2.3, manual 1.2.4.2): all of it, measured, unless set (2.1.2.16)
    set_ram_capacity(data)
    # Kerberos sign-in stays off unless set (2.1.6.32, 2.1.2.16): the template's default; turned on later

    ctx.vars = data
    if not (ask or ctx.non_interactive):
        return None                       # Advanced: the menu asks what is missing, then finish_vars
    return finish_vars(ctx)
