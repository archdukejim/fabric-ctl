from fabriclib.common.write_audit import write_audit
from fabriclib.samba.gpo_request import gpo_request


def set_gpo_policy(v, actor, policy, values, enabled=True, source="cli", container="samba", control=False):
    """Purpose: set one policy in this site's admin settings GPO, or in its controls GPO (linked enforced: the sites
             below cannot override it, 2.1.6.20) (manual 4.6.8): Enabled with its element values, or Disabled.
    Inputs:  v — fabric vars (site_name); actor — str, for the audit; policy — its name or title; values — {element id:
             text}; enabled — bool; source — audit source; container — the DC's container; control — bool, the
             controls GPO.
    Returns: list of str, what changed ([] when it already was so).
    Fails:   ValidationError from gpo_request (no such policy, a wrong element or value, the DC not running).
    Feeds:   samba/run_gpo_command (`fabricctl gpo set`); agent route POST /v1/gpo/set (gpo:admin).
    Notes:   audited as GPO_SET."""
    site = v["site_name"]
    done = gpo_request({"op": "set", "site": site, "policy": policy, "values": values or {}, "enabled": bool(enabled),
                        "control": bool(control)}, container, v)
    write_audit(actor, "GPO_SET", f"site={site} policy={policy}" + ("" if enabled else " disabled")
                + (" control" if control else ""), source)
    return done
