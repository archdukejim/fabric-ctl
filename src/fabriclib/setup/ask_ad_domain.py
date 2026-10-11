import re

from fabriclib.common.console import BOLD, NC, YELLOW
from fabriclib.samba.suggested_ad_domain import suggested_ad_domain
from fabriclib.setup.permanent_mark import permanent_mark

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")    # as check_samba_settings takes them


def ask_ad_domain(ctx):
    """Purpose: the directory's question (manual 1.6.3, 1.1.9.8), asked by setup when it is not set: the AD domain
             (2.1.6.11: chosen once, permanent; a sibling of fabric's domain suggested). Fabric's directory is a Samba
             AD domain on every install. Its password policy is not asked: a new domain starts from the default
             (collect_vars, 2.1.6.35; 2.1.2.16).
    Inputs:  ctx — SetupContext; reads and sets ctx.vars ad_domain; domain for the suggestion. Interactive.
    Returns: None; ctx.vars["ad_domain"] set (the question marked "⚠ Permanent", 2.1.2.20; Enter takes the value
             already set or the suggestion; a domain AD cannot use is refused, saying why, and asked again).
    Fails:   EOFError from input().
    Feeds:   setup/collect_vars."""
    print("\n  fabric's directory is a Samba AD domain (people, groups, devices; Windows and Linux machines may join).")
    domain = str(ctx.vars.get("domain") or "").lower()
    current = str(ctx.vars.get("ad_domain") or "").lower()
    print(f"    The AD domain is {BOLD}permanent{NC}: it cannot be changed once the domain exists.")
    suggestion = current or suggested_ad_domain(domain)
    if suggested_ad_domain(domain):
        where = ("beside fabric's domain, apart from the sites' names" if domain.count(".") >= 2
                 else "under fabric's domain (it has no parent of its own to sit beside)")
        print(f"    Suggested: {suggested_ad_domain(domain)}, {where}; press Enter to take it. "
              f"It cannot be {domain} itself.")
    while True:
        answer = input(f"    AD domain{permanent_mark('ad_domain')}{f' [{suggestion}]' if suggestion else ''}: "
                       ).strip().lower()
        chosen = answer or suggestion
        labels = chosen.split(".")
        if (chosen and chosen != domain and len(labels) >= 2 and all(_LABEL.match(x) for x in labels)
                and len(chosen) <= 253 and not domain.endswith("." + chosen)
                and labels[-1] not in ("local", "localhost")):
            ctx.vars["ad_domain"] = chosen
            break
        print(f"    {YELLOW}a domain of two labels or more (letters, digits, hyphens), not .local, not {domain} itself "
              f"nor a parent of it{NC}")
