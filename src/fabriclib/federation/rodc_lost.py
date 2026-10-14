import datetime
import json
import os

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.federation.plan_rodc_lost import plan_rodc_lost
from fabriclib.samba.domain_sites import domain_sites
from fabriclib.samba.run_rodc_lost import run_rodc_lost

BATCH = 50                  # accounts reset per call into the DC (each batch recorded before the next)


def _record_path(config_dir, site):
    """Purpose: where an incident's record is kept: <config>/rodc-lost-<site>.json (root, 0600; never a password).
    Inputs:  config_dir; site.
    Returns: str.
    Fails:   never.
    Feeds:   rodc_lost."""
    return os.path.join(config_dir, f"rodc-lost-{site}.json")


def _load(path):
    """Purpose: an incident's record, or {} when there is none (an unreadable one counts as none).
    Inputs:  path.
    Returns: dict.
    Fails:   never.
    Feeds:   rodc_lost."""
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def rodc_lost(v, config_dir, actor, target, confirmed=None, source="cli", sites=None, runner=run_rodc_lost,
              now=None):
    """Purpose: a site's read-only DC is lost or stolen (decision 2.1.6.58, manual 1.9.8.21): at a writable DC of a
             site above it, every account whose password that DC was told (msDS-RevealedUsers) is listed and shown;
             on confirmation each is given a new random password (people must change it at their next sign-in;
             machine and service accounts are rotated), and then the DC is removed (its computer account and so its
             `<site>-rodc-cache` allowance, its own krbtgt account, its server objects and DNS records). Only accounts
             in the revealed list are ever reset. Each step is recorded as it is done, so a second run carries on and
             never resets an account twice; once finished, a run says so and changes nothing.
    Inputs:  v — fabric vars (site_name, ad_dc_type); config_dir — the install's config folder (the record); actor —
             who (audit); target — the site; confirmed — callable(plan) -> bool, asked after the list is shown
             and before anything changes (None: only the plan is returned); source — the audit's ("cli", "web");
             sites — domain_sites()'s list (tests); runner — run_rodc_lost (tests pass their own); now — datetime.
    Returns: {"plan": plan_rodc_lost's answer, "reset": [{"dn", "kind"}] (this run), "removed": [names] (this run),
             "changed": bool}.
    Fails:   ValidationError, audited FED_RODC_LOST_REFUSED: the plan's refusal (this site, not below, this DC
             read-only, no such site); the writable DC does not answer, or refuses (nothing changed); not confirmed
             (nothing changed); a step's failure (the steps before it recorded: run again).
    Feeds:   run_federation_command (`fabricctl federation rodc-lost <site>`), agent/post_federation (the console).
    Notes:   audited FED_RODC_LOST_LISTED, FED_RODC_LOST_RESET (each account, with its kind), FED_RODC_LOST_REMOVED,
             FED_RODC_LOST_DONE."""
    target = str(target or "").strip().lower()
    stamp = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def refuse(why):
        write_audit(actor, "FED_RODC_LOST_REFUSED", f"site={target}: {why}", source)
        raise ValidationError(why)

    sites = domain_sites() if sites is None else sites
    plan = plan_rodc_lost(v, target, sites)
    if plan["refused"]:
        refuse(plan["refused"])
    path = _record_path(config_dir, target)
    record = _load(path)
    try:
        listing = runner({"action": "list", "site": target})
    except ValidationError as e:
        refuse(str(e))
    plan = plan_rodc_lost(v, target, sites, listing, record)
    result = {"plan": plan, "reset": [], "removed": [], "changed": False}
    if plan["noop"]:
        return result
    if record.get("done_at") or record.get("accounts") is None:
        record = {"site": target, "listed_at": stamp, "reset": [], "removed": [],
                  **({"previous": record["done_at"]} if record.get("done_at") else {})}
    record.update({"accounts": plan["accounts"], "rodcs": plan["rodcs"]})
    write_file_if_changed(path, json.dumps(record, indent=1) + "\n", 0o600)
    write_audit(actor, "FED_RODC_LOST_LISTED", f"site={target} rodcs={','.join(plan['rodcs'])} "
                f"accounts={len(plan['accounts'])} to_reset={len(plan['reset_left'])}", source)
    if confirmed is None:
        return result
    if not confirmed(plan):
        refuse("not confirmed: nothing was changed")
    left = plan["reset_left"]
    for i in range(0, len(left), BATCH):
        done = runner({"action": "reset", "site": target, "accounts": left[i:i + BATCH]})["reset"]
        record["reset"] = sorted(set(record.get("reset") or []) | {a["dn"] for a in done})
        write_file_if_changed(path, json.dumps(record, indent=1) + "\n", 0o600)
        for a in done:
            write_audit(actor, "FED_RODC_LOST_RESET", f"site={target} kind={a['kind']} dn={a['dn']}", source)
        result["reset"] += done
        result["changed"] = True
    for name in plan["remove_left"]:
        runner({"action": "remove", "site": target, "name": name})
        record["removed"] = sorted(set(record.get("removed") or []) | {name})
        write_file_if_changed(path, json.dumps(record, indent=1) + "\n", 0o600)
        write_audit(actor, "FED_RODC_LOST_REMOVED", f"site={target} rodc={name}", source)
        result["removed"].append(name)
        result["changed"] = True
    record["done_at"] = stamp
    write_file_if_changed(path, json.dumps(record, indent=1) + "\n", 0o600)
    write_audit(actor, "FED_RODC_LOST_DONE", f"site={target} reset={len(result['reset'])} "
                f"removed={','.join(result['removed']) or '-'}", source)
    return result
