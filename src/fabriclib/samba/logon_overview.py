from fabriclib.common.errors import ValidationError
from fabriclib.directory.run_op import run_op
from fabriclib.samba.check_logon_policies import check_logon_policies
from fabriclib.samba.host_logon_default import HOSTS_OU, host_logon_default
from fabriclib.samba.logon_ou_path import logon_ou_path
from fabriclib.secrets.load_secrets import load_secrets

ALWAYS = ["fabric-break-glass", "BUILTIN\\Administrators"]       # in every fabric log-on policy (1.6.11.4)


def logon_overview(v, ou=None, secrets=None, container="samba"):
    """Purpose: who may sign in to the site's machines, per OU (manual 1.6.11.4): what `fabricctl domain logon show`,
             domain status and the web console's Machines section show. While `logon_policies` is null, the site's
             OU with the log-on rights of before 0.9, read in the domain. The site's OU=fabric-hosts always shows a
             policy: the setting's, or the default (the fabric admins, 2.1.6.53).
    Inputs:  v — fabric vars (site_name, logon_policies, webui_admin_group); ou — one OU's path to show, None for
             all; secrets — fabric's secrets (default: load_secrets(), only while the setting is null); container —
             the DC's container.
    Returns: {"site", "legacy": bool (no per-OU policies yet), "read_only": bool (the site's DC is read-only: who may
             sign in is changed at the site above, 2.1.6.52), "unapplied": bool (a read-only DC's site whose settings
             hold per-OU policies, saved before such changes were refused: its DC never applies them), "always": the
             groups every policy keeps, "policies":
             [{"ou" (path, "" the site's OU), "console", "remote"}] sorted by OU, "error": "" or why the legacy
             list could not be read (then its lists are empty)}.
    Fails:   ValidationError for an OU path refused, or a setting check_logon_policies refuses.
    Feeds:   samba/run_domain_command (logon show, status), agent route GET /v1/domain/logon (domain:read)."""
    policies = check_logon_policies(v.get("logon_policies"))
    read_only = v.get("ad_dc_type") == "rodc"
    out = {"site": v.get("site_name", ""), "legacy": policies is None, "read_only": read_only,
           "unapplied": read_only and policies is not None, "always": ALWAYS, "policies": [], "error": ""}
    if policies is None:
        try:
            legacy = run_op(v, secrets if secrets is not None else load_secrets(), "logon_groups",
                            {"names": [], "admin_group": v.get("webui_admin_group") or "admins"}, container)["legacy"]
        except ValidationError as e:
            legacy, out["error"] = [], str(e)
        except (KeyError, OSError) as e:          # no secrets to sign in to the directory with
            legacy, out["error"] = [], f"{type(e).__name__}: {e}"
        policies = {"": {"console": legacy, "remote": legacy}}
    site = v.get("site_name", "")
    policies = {**policies}
    policies.setdefault(HOSTS_OU, host_logon_default(site))
    want = None if ou is None else logon_ou_path(ou)
    out["policies"] = [{"ou": path, **entry} for path, entry in sorted(policies.items())
                       if want is None or path == want]
    return out
