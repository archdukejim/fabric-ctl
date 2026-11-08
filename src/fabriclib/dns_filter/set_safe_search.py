import copy

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns_filter.check_filter_groups import YOUTUBE
from fabriclib.dns_filter.check_filter_settings import check_filter_settings
from fabriclib.dns_filter.common.filter_target import filter_target


def set_safe_search(actor, group, on, youtube="strict", source="cli", dry=False):
    """Purpose: switch strict safe search on or off for everyone or one client group, with YouTube's level (manual
             1.12.2.15): every engine of the table at once, YouTube strict or moderate. Saved in vars.yaml; applied
             by the next apply.
    Inputs:  actor — who asks (audit); group — "" for everyone, else a group's name; on — bool (a form's "on"/"true"/
             "1" counts as on); youtube — "strict" or "moderate"; source — "cli" or "web".
             dry — True: only checked, nothing saved or audited (a change held for the DNS filter tab's Apply, 1.12.3.17).
    Returns: {"group" ("" or the name), "on": bool, "youtube"}.
    Fails:   ValidationError for an unknown group or another YouTube level; OSError or yaml errors from the vars file
             and the audit log.
    Feeds:   agent/post_dns_filter (POST /v1/dns-filter/safe-search)."""
    if isinstance(on, str):
        on = on.strip().lower() in ("on", "true", "1", "yes")
    youtube = str(youtube or "strict").strip().lower()
    if youtube not in YOUTUBE:
        raise ValidationError("youtube: strict or moderate")
    with vars_lock():
        data = copy.deepcopy(load_vars())
        target, keys, label = filter_target(data, group)
        target[keys["safe_search"]], target[keys["youtube"]] = bool(on), youtube
        check_filter_settings(data)
        if not dry:
            save_vars(data)
    if not dry:
        write_audit(actor, "DNS_FILTER_SAFE_SEARCH", f"{label}: " + (f"strict, YouTube {youtube}" if on else "off"), source)
    return {"group": "" if label == "everyone" else label[6:], "on": bool(on), "youtube": youtube}
