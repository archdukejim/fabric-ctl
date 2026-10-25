import os

from fabriclib.common.errors import ValidationError
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.samba.dc_provisioned import dc_provisioned
from fabriclib.samba.suggested_dc_name import suggested_dc_name
from fabriclib.setup.errors import SetupError


def name_dc(ctx):
    """Purpose: the domain controller's name, which fabric alone chooses (2.1.6.65, manual 1.6.5.26); nothing is asked,
             interactive or not. An installed DC keeps the name it has (0.7.x's `dc-<host>` included); a site that
             joined an upstream keeps the name the upstream gave it in the join's answer; a site joining now is given
             its name by the upstream at the join (setup's `join` step); a new domain's DC is `dc-0001` (a number
             the DC could not have, the host's own name, passed over: suggested_dc_name).
    Inputs:  ctx — SetupContext: vars (hostname, ad_domain, ad_netbios, dc_name; changed), deploy_base (the installed
             DC's marker, samba/dc_provisioned), config_dir (federation.yaml: the name an upstream gave),
             join_invitation (setup --join).
    Returns: None; ctx.vars["dc_name"] set (or, for a site about to join, removed until the upstream gives it).
    Fails:   SetupError from suggested_dc_name (never for a new domain: dc-0001 or the next is free); OSError or
             yaml errors reading federation.yaml.
    Feeds:   setup/finish_vars (after the questions or the menu, so both modes name the DC the same way)."""
    v = ctx.vars
    if dc_provisioned(ctx.deploy_base):
        return                                 # the installed DC's name, as the settings have it: never changed
    upstream = load_registry(os.path.join(ctx.config_dir, "federation.yaml"))["upstream"] or {}
    if upstream.get("dc_name"):
        v["dc_name"] = upstream["dc_name"]     # given by the upstream when this site joined (a re-run of setup)
        return
    if ctx.join_invitation:
        v.pop("dc_name", None)                 # the upstream gives it in the join's answer (setup/join_federation)
        return
    netbios = str(v.get("ad_netbios") or str(v.get("ad_domain") or "").split(".")[0])[:15]
    try:
        v["dc_name"] = suggested_dc_name(hostname=str(v.get("hostname") or ""), netbios=netbios)
    except ValidationError as e:
        raise SetupError(str(e)) from None
