import ipaddress
import re
import urllib.parse

from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.check_filter_groups import check_filter_groups
from fabriclib.dns_filter.common.rule_names import NAME_RE

# the providers whose DoT certificate name is known, by address and by name (AdGuard's own upstream examples)
BY_ADDRESS = {"1.1.1.1": "cloudflare-dns.com", "1.0.0.1": "cloudflare-dns.com", "8.8.8.8": "dns.google",
              "8.8.4.4": "dns.google", "9.9.9.9": "dns.quad9.net", "149.112.112.112": "dns.quad9.net",
              "94.140.14.14": "dns.adguard-dns.com", "94.140.15.15": "dns.adguard-dns.com"}
BY_NAME = {"cloudflare-dns.com": ["1.1.1.1", "1.0.0.1"], "one.one.one.one": ["1.1.1.1", "1.0.0.1"],
           "dns.google": ["8.8.8.8", "8.8.4.4"], "dns.quad9.net": ["9.9.9.9", "149.112.112.112"],
           "dns.adguard-dns.com": ["94.140.14.14", "94.140.15.15"]}
# the markers 0.6's AdGuard config builder wrote between fabric's generated rules, adguard_rules and the UI's
GENERATED_END = "! fabric: the rules above are generated (fabric's own names stay resolvable)"
SETTING_END = "! fabric: the rules above are adguard_rules (vars); rules you add in this UI go below"
RULE = re.compile(r"^(@@)?\|\|([a-z0-9_.-]+)\^(\$important)?$")

# the default upstreams (vars.yaml.j2): used when none of AdGuard's could be carried
CLOUDFLARE = ({"address": "1.1.1.1", "name": "cloudflare-dns.com"},
              {"address": "1.0.0.1", "name": "cloudflare-dns.com"})


def _upstream(line, own_ip, not_carried):
    """Purpose: one AdGuard upstream as the resolver's DoT upstreams.
    Inputs:  line — an upstream_dns line; own_ip — this site's BIND (its line is fabric's, not the owner's);
             not_carried — list, appended to when the line cannot be carried.
    Returns: list of {address, name} (empty when skipped).
    Fails:   never.
    Feeds:   import_adguard_settings."""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("[/") or line == own_ip:
        return []
    url = urllib.parse.urlsplit(line if "://" in line else "udp://" + line)
    host = (url.hostname or "").lower()
    if host in BY_NAME:
        return [{"address": a, "name": host} for a in BY_NAME[host]]
    if host in BY_ADDRESS:                     # plain DNS to such a provider is encrypted from now on
        return [{"address": host, "name": BY_ADDRESS[host]}]
    not_carried.append(f"upstream {line}: the resolver forwards over DNS-over-TLS only and the certificate name for "
                       "it is not known — add it as {address, name} in dns_filter_upstreams")
    return []


def _rule(rule, own, settings, not_carried):
    """Purpose: one AdGuard user rule as the owner's allow or block (`||name^`, `@@||name^`, also with $important).
    Inputs:  rule — the line; own — fabric's domains (their rules were fabric's own); settings — the result, changed;
             not_carried — list, appended to when the rule cannot be carried.
    Returns: None.
    Fails:   never.
    Feeds:   import_adguard_settings."""
    rule = rule.strip()
    if not rule or rule.startswith(("!", "#")):
        return
    m = RULE.match(rule.lower())
    if m and NAME_RE.match(m.group(2)) and "." in m.group(2):
        name = m.group(2)
        try:                                   # the host's own address was fabric's rule too
            ipaddress.ip_address(name)
            return
        except ValueError:
            pass
        if any(name == d or name.endswith("." + d) for d in own):
            return
        key = "dns_filter_allow" if m.group(1) else "dns_filter_block"
        if name not in settings[key]:
            settings[key].append(name)
        return
    not_carried.append(f"rule {rule}: only ||name^ and @@||name^ rules move (each name with every name below it)")


def _safe_search(ss, who, not_carried):
    """Purpose: AdGuard's safe search (global or a client's) as fabric's one switch and YouTube level (1.12.2.15).
    Inputs:  ss — AdGuard's safe_search block ({enabled, google, youtube, ...}; an engine left out counts as on, as
             AdGuard's default); who — "everyone" or the group, for the messages; not_carried — appended to.
    Returns: (on: bool, youtube: "strict" or "moderate"). AdGuard enforces YouTube's moderate level, so YouTube on
             stays moderate; YouTube off becomes strict, and is said.
    Fails:   never.
    Feeds:   import_adguard_settings, _groups."""
    ss = ss or {}
    if not ss.get("enabled"):
        return False, "strict"
    off = [e for e in ("bing", "duckduckgo", "ecosia", "google", "pixabay", "yandex", "youtube")
           if ss.get(e, True) is False]
    if off:
        not_carried.append(f"safe search for {who}: {', '.join(off)} was left out in AdGuard; fabric's strict safe "
                           "search covers every engine at once" + (" (YouTube strict)" if "youtube" in off else ""))
    return True, "strict" if "youtube" in off else "moderate"


def _group_name(name, taken):
    """Purpose: an AdGuard client's name as a group name: lowercase letters, digits and '-', at most 32, unique.
    Inputs:  name — AdGuard's client name; taken — set of names already used (changed: the result is added).
    Returns: str.
    Fails:   never.
    Feeds:   _groups."""
    base = re.sub(r"[^a-z0-9]+", "-", str(name or "client").lower()).strip("-")[:28].strip("-") or "client"
    base = "everyone-1" if base == "everyone" else base
    out, n = base, 1
    while out in taken:
        n += 1
        out = f"{base}-{n}"
    taken.add(out)
    return out


def _groups(cfg, v, own, everyone, not_carried):
    """Purpose: AdGuard's persistent clients as client groups (1.12.2.15): each client's IPv4 addresses and subnets
             the resolver may answer, its safe search (its own, or everyone's when it used the global settings).
    Inputs:  cfg — AdGuardHome.yaml as a dict; v — the vars (lan_cidr, fabric_subnet, security.firewall_allow); own —
             fabric's domains; everyone — (on, youtube) from the global safe search; not_carried — appended to.
    Returns: list of groups as dns_filter_groups holds them.
    Fails:   never (an id fabric cannot use is listed in not_carried with the reason).
    Feeds:   import_adguard_settings."""
    taken, used, groups = set(), set(), []
    for c in (cfg.get("clients") or {}).get("persistent") or []:
        label = str(c.get("name") or "client")
        name = _group_name(label, taken)
        clients = []
        for raw in c.get("ids") or []:
            try:                      # an id is kept only where the settings check takes it (and no other group)
                probe = {**v, "dns_filter_groups": [{"name": "probe", "clients": [str(raw)]}]}
                check_filter_groups(probe, own)
                ident = probe["dns_filter_groups"][0]["clients"][0]
            except ValidationError as e:
                not_carried.append(f"client {label}: {raw} ({str(e).removeprefix('group probe: ')}; MAC addresses and "
                                   "client IDs come with device groups in 0.8)")
                continue
            if ident in used:
                not_carried.append(f"client {label}: {raw} is already another client's")
                continue
            used.add(ident)
            clients.append(ident)
        if not clients:
            not_carried.append(f"client {label}: nothing to match it by (no IPv4 address or subnet fabric answers)")
            taken.discard(name)
            continue
        on, youtube = everyone if c.get("use_global_settings", True) else \
            _safe_search(c.get("safe_search"), name, not_carried)
        if c.get("upstreams"):
            not_carried.append(f"client {label}: its own upstreams (every group uses the resolver's)")
        if c.get("blocked_services"):
            not_carried.append(f"client {label}: blocked services (fabric does not block services as such)")
        groups.append({"name": name, "clients": clients, "safe_search": on, "youtube": youtube, "allow": [],
                       "block": []})
    return groups


def import_adguard_settings(cfg, v):
    """Purpose: 0.6's AdGuard Home settings as the DNS filter's (manual 2.3.12.1.9, 1.12.3.11, decisions 2.1.12.3,
             2.1.12.6): its upstreams (as DNS-over-TLS where the provider's certificate name is known; Cloudflare's
             when none can be), its lists by URL (ticked as they were), its `||name^` and `@@||name^` rules, its safe
             search and its persistent clients as groups (1.12.2.15); everything else is listed, never dropped
             silently.
    Inputs:  cfg — AdGuardHome.yaml as a dict, or None when AdGuard never ran (then the adguard_* vars are used: what
             a first deploy would have started with); v — the vars (adguard_upstreams, adguard_filter_lists,
             adguard_rules, ip_bind9, domain, org_domain, ad_domain, host_ip, and what check_filter_groups reads).
    Returns: {"settings": {dns_filter: "bind", dns_filter_upstreams, dns_filter_lists, dns_filter_allow,
             dns_filter_block, dns_filter_safe_search, dns_filter_youtube, dns_filter_groups (its persistent clients,
             1.12.2.15)}, "not_carried": [str, one per item that did not move], "clients": [AdGuard's persistent
             clients, as they were (kept in the import record)]}.
    Fails:   never (a missing or odd key reads as empty).
    Feeds:   nothing in the product since 0.8.0 (its caller, setup/move_dns_filter, retired: stale-code register
             2.3.1.5.1, S12); tests/resolver/run.py, tests/resolver/groups.py."""
    cfg = cfg or {}
    dns = cfg.get("dns") or {}           # AdGuard's schema 34 (0.6's): dns, filters, user_rules, filtering, clients
    own = [d for d in (v.get("domain"), v.get("org_domain"), v.get("ad_domain")) if d]
    not_carried = []
    settings = {"dns_filter": "bind", "dns_filter_upstreams": [], "dns_filter_lists": [], "dns_filter_allow": [],
                "dns_filter_block": []}
    if cfg:
        ups = dns.get("upstream_dns") or []
        lists = [f for f in cfg.get("filters") or [] if f.get("enabled", True)]
        off = [f for f in cfg.get("filters") or [] if not f.get("enabled", True)]
        rules = list(cfg.get("user_rules") or [])
        rules = rules[rules.index(GENERATED_END) + 1:] if GENERATED_END in rules else rules
    else:
        ups = v.get("adguard_upstreams") if v.get("adguard_upstreams") is not None else \
            ["https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"]
        lists = v.get("adguard_filter_lists") if v.get("adguard_filter_lists") is not None else \
            [{"name": "AdGuard DNS filter",
              "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"}]
        off = []
        rules = v.get("adguard_rules") or []
    for line in ups:
        for u in _upstream(str(line), str(v.get("ip_bind9") or ""), not_carried):
            if u not in settings["dns_filter_upstreams"]:
                settings["dns_filter_upstreams"].append(u)
    if not settings["dns_filter_upstreams"]:
        settings["dns_filter_upstreams"] = [dict(u) for u in CLOUDFLARE]
        not_carried.append("no upstream could be carried over DNS-over-TLS: Cloudflare's (1.1.1.1, 1.0.0.1) are used "
                           "(dns_filter_upstreams)")
    for f, enabled in [(f, True) for f in lists] + [(f, False) for f in off]:
        url = str(f.get("url") or "").strip()
        if url.startswith(("https://", "http://")) and url not in [x["url"] for x in settings["dns_filter_lists"]]:
            settings["dns_filter_lists"].append({"name": f.get("name") or url, "url": url, "enabled": enabled})
        elif url:
            not_carried.append(f"list {f.get('name') or url}: only lists on http(s) can be fetched")
    for f in cfg.get("whitelist_filters") or []:
        not_carried.append(f"allowlist {f.get('name') or f.get('url')}: allowlists are not supported; allow names in "
                           "dns_filter_allow")
    for rule in rules:
        if str(rule) != SETTING_END:
            _rule(str(rule), own, settings, not_carried)
    filtering = cfg.get("filtering") or {}
    on, youtube = _safe_search(filtering.get("safe_search"), "everyone", not_carried)
    settings["dns_filter_safe_search"], settings["dns_filter_youtube"] = on, youtube
    settings["dns_filter_groups"] = _groups(cfg, v, own, (on, youtube), not_carried)
    if filtering.get("parental_enabled"):
        not_carried.append("AdGuard's parental service: not carried (add an adult-content list from the catalogue)")
    if filtering.get("safebrowsing_enabled"):
        not_carried.append("AdGuard's safe browsing service: not carried (add a security list from the catalogue)")
    if (filtering.get("blocked_services") or {}).get("ids"):
        not_carried.append("blocked services: not carried (fabric does not block services as such)")
    for r in filtering.get("rewrites") or []:
        not_carried.append(f"DNS rewrite {r.get('domain')} → {r.get('answer')}: add it as a DNS record in fabric")
    return {"settings": settings, "not_carried": not_carried,
            "clients": list((cfg.get("clients") or {}).get("persistent") or [])}
