import os
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.federation.decode_invitation import decode_invitation
from fabriclib.federation.join_upstream import join_upstream
from fabriclib.pki.common.ca_files import ca_files
from fabriclib.pki.common.describe_cert import describe_cert
from fabriclib.pki.replace_site_ca import replace_site_ca
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.secrets.save_secrets import save_secrets
from fabriclib.setup.renew_service_certs import renew_service_certs
from fabriclib.system.apply_changes import apply_changes


def reparent_site(ctx, actor, invitation):
    """Purpose: move this site under another parent — the root site or another site that may hold sites — with
             an invitation from that parent (manual 1.9.5.1): for a nested site whose parent is gone
             for good, or to change where a site hangs. The site keeps its name, directory part and data; it
             gets a new CA from the new parent.
    Inputs:  ctx — SetupContext with state loaded (vars, config_dir); actor — str (audit); invitation — the new
             parent's invitation text (made with `fabricctl federation invite <this site>` there).
    Returns: {"parent": the new parent's site name, "site_ca_depth": CAs between this site's CA and the root,
             "applied": bool, "output": the apply's output tail}.
    Fails:   ValidationError "only a site that joined an upstream can be re-parented"; "the invitation is for
             site <x>, this is <y>"; "the invitation is for another organisation (root or base DN differ)";
             join_upstream's and replace_site_ca's messages; errors from renew_service_certs; OSError.
    Feeds:   run_federation_command (reparent).
    Notes:   Step-CA is restarted on the new CA and every service certificate is re-issued from it. Client
             certificates and device certificates from the old CA stay valid until they expire (they chain to
             the same root), but people's web UI certificates must be re-issued (`fabricctl client-cert`):
             nginx now accepts this CA's chain only. The old parent still lists the site until it is removed
             there (`fabricctl federation remove`, which leaves the moved site's domain objects alone). In the
             domain the new parent links this site's AD site to its own (2.1.6.20, manual 1.9.8.14); the directory's
             folders are the domain's (1.6.13.2), so nothing of the site moves. Audited as FED_REPARENT."""
    v = ctx.vars
    reg_path = os.path.join(ctx.config_dir, "federation.yaml")
    if not load_registry(reg_path)["upstream"]:
        raise ValidationError("only a site that joined an upstream can be re-parented")
    inv = decode_invitation(invitation)
    if inv["site"] != v.get("site_name"):
        raise ValidationError(f"the invitation is for site {inv['site']}, this is {v.get('site_name')}")
    with open(ca_files(v)[0]) as f:
        root_fp = describe_cert(f.read())["sha256"]
    if inv["root_sha256"].upper() != root_fp.upper() or inv["ldap_base_dn"] != v.get("ldap_base_dn"):
        raise ValidationError("the invitation is for another organisation (root or base DN differ)")
    password = load_secrets(v=v).get("ca_password")
    work_dir = os.path.join(ctx.config_dir, f"site-ca-{inv['upstream']}")
    res = join_upstream(v, invitation, password, work_dir, v["domain"], v["host_ip"], config_dir=ctx.config_dir,
                        audit_path=ctx.path("fabric", "archive", "audit.log"), replace=True,
                        dns_port=int(v.get("bind_dns_port") or 53))
    new = res["vars"]
    if res.get("dns_secret"):                # the DNS link to the new parent
        stored = load_secrets(v=v)
        save_secrets({"federation_tsig": dict(stored.get("federation_tsig") or {}, upstream=res["dns_secret"])},
                     v=v)
    replace_site_ca(v, new)
    with vars_lock():
        data = load_vars()
        data.update({k: new[k] for k in ("ica_crt_path", "ica_key_path", "ica_parents_path", "site_ca_depth")})
        save_vars(data)
    subprocess.run(["systemctl", "restart", "stepca"], check=True)
    if renew_service_certs(ctx, force=True) != 0:
        raise ValidationError("the service certificates could not be re-issued under the new parent: see "
                              "`fabricctl status`")
    ok, output = apply_changes(actor, "cli")
    write_audit(actor, "FED_REPARENT", f"site={inv['site']} parent={res['upstream']['site_name']} "
                                       f"depth={new['site_ca_depth']}", "cli")
    return {"parent": res["upstream"]["site_name"], "site_ca_depth": new["site_ca_depth"], "applied": ok,
            "output": output[-2000:]}
