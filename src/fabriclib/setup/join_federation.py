import base64
import os

from fabriclib.common.console import info, ok
from fabriclib.common.errors import ValidationError
from fabriclib.common.read_images_lock import read_images_lock
from fabriclib.federation.join_upstream import join_upstream
from fabriclib.secrets.save_secrets import save_secrets
from fabriclib.setup.errors import SetupError


def run(ctx):
    """Purpose: setup step `join` (only with `fabricctl setup --join`): join the upstream before
             anything is rendered, so this install is set up as a site of that fabric — its CA an
             intermediate signed by the organisation's root (bring-your-own-CA path), its organisation suffix
             the upstream's (manual 1.9.4.1).
    Inputs:  ctx — SetupContext: join_invitation, vars (from collect_vars: domain, host_ip, image_stepca if set),
             secrets / secrets_file (ca_password, created here if missing), config_dir, source_dir (images.lock).
    Returns: None. ctx.vars gains byoc, ca_crt_path, ica_crt_path, ica_key_path, site_name, org_domain,
             ldap_base_dn and the organisation's cert_* settings (friendly_name only when unset); the deploy
             step saves them. The
             site CA key and certificates are kept in <base>/fabric/config/site-ca (0700); the DNS link's
             TSIG secret goes to fabric's secrets (federation_tsig.upstream). When the root prepared this site in
             its domain: the service accounts' passwords (ad_*_password) and the temporary join account (ad_join)
             go to fabric's secrets, and ctx.vars gains ad_domain, ad_dc_type, ad_join_server, ad_join_server_name,
             posix_id_range, ad_site_ou and ad_org_ou (manual 1.9.8.4, 1.9.8.14), posix_id_block (the size of the
             block it was given) and, from a parent that sends them, ldap_groups (the organisation's gids, 2.1.6.46).
    Fails:   SetupError with join_upstream's message (invitation damaged/expired/used, the upstream refused or
             unreachable, the root not the pinned one, a certificate that does not fit).
    Feeds:   setup STEPS, after `docker` (the key is made with the pinned Step-CA image) and before `deploy`.
    Notes:   without --join it does nothing. A re-run after a successful join reuses what was staged and does
             not contact the upstream again (the invitation is single-use). The key is made as root: the step
             user does not exist yet; the pki step copies it into Step-CA's data and gives it to that user."""
    if not ctx.join_invitation:
        return
    password = ctx.secrets.get("ca_password")
    if not password:
        password = base64.b64encode(os.urandom(32)).decode()
        try:
            save_secrets({"ca_password": password}, ctx.secrets_file)
        except ValidationError as e:
            raise SetupError(str(e)) from None
        ctx.secrets = None                       # reload on next use
    image = ctx.vars.get("image_stepca") or read_images_lock(ctx.source_dir)["stepca"]["ref"]
    v = {**ctx.vars, "image_stepca": image, "service_users": {"step": {"uid": 0, "gid": 0}}}
    info("joining the upstream fabric (one-time invitation)")
    try:
        res = join_upstream(v, ctx.join_invitation, password, os.path.join(ctx.config_dir, "site-ca"),
                            ctx.vars["domain"], ctx.vars["host_ip"], config_dir=ctx.config_dir,
                            audit_path=ctx.path("fabric", "archive", "audit.log"),
                            dns_port=int(ctx.vars.get("bind_dns_port") or 53))
    except ValidationError as e:
        raise SetupError(f"joining the upstream failed: {e}") from None
    dom = res.get("domain") or {}
    if res.get("dns_secret") or dom:
        update = {"federation_tsig": {"upstream": res["dns_secret"]}} if res.get("dns_secret") else {}
        if dom:                                  # the domain this site's DC joins (manual 1.9.8.4)
            update.update({f"ad_{kind}_password": dom["accounts"][kind] for kind in ("agent", "keycloak", "radius")})
            update["ad_join"] = {"user": dom["join_user"], "password": dom["join_password"]}
        try:
            save_secrets(update, ctx.secrets_file)
        except ValidationError as e:
            raise SetupError(str(e)) from None
        ctx.secrets = None
    if dom:
        first, last = (int(x) for x in str(dom["id_range"]).split("-"))
        ctx.vars.update({"ad_domain": dom["ad_domain"], "ad_dc_type": dom["dc_type"],
                         "ad_join_server": dom["dc_address"], "ad_join_server_name": dom["dc_host"],
                         "posix_id_range": dom["id_range"], "ad_site_ou": dom["site_ou"],
                         "ad_org_ou": dom["org_ou"],
                         # the organisation's block size, for the sites it may nest (2.1.6.46)
                         "posix_id_block": last - first + 1})
        if dom.get("groups"):                    # the organisation's groups and their gids, as the root has them
            ctx.vars["ldap_groups"] = dom["groups"]
    joined = dict(res["vars"])
    if ctx.vars.get("friendly_name"):
        joined.pop("friendly_name", None)
    ctx.vars.update(joined)
    up = res["upstream"]
    ok(f"{'joined' if res['joined'] else 'member of'} {up['site_name']} ({up['domain']}) as site "
       f"{ctx.vars['site_name']}; CA: an intermediate of the organisation's root")
