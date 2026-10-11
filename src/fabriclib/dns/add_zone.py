import copy
import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.paths import FEDERATION_FILE
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns.constants import PRIVATE_TLDS
from fabriclib.dns.publish_zone_list import publish_zone_list
from fabriclib.dns.zone_name import zone_name
from fabriclib.federation.common.load_registry import load_registry

# the menu's HOST_RE (validate_record) without the underscore a record name may have: BIND will not load a zone
# named with one (found by tests/zones); lowercase, at least two labels, no leading or trailing hyphen
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
ZONE_RE = re.compile(rf"^{LABEL}(?:\.{LABEL})+$")


def _is_public(name):
    """Purpose: whether a zone name sits under a public top-level domain (manual 1.4.1.3).
    Inputs:  name — a checked zone name.
    Returns: False under home.arpa or a private-use top-level domain (PRIVATE_TLDS), True otherwise.
    Fails:   never.
    Feeds:   add_zone."""
    return not (name == "home.arpa" or name.endswith(".home.arpa") or name.rsplit(".", 1)[-1] in PRIVATE_TLDS)


def _taken(data, name):
    """Purpose: why BIND already answers for a name, if it does.
    Inputs:  data — the vars; name — a checked zone name.
    Returns: the reason (str), or "" when the name is free.
    Fails:   yaml.YAMLError or OSError reading the federation registry.
    Feeds:   add_zone."""
    domain = str(data.get("domain") or "").lower()
    if name == domain:
        return "it is the site's own domain"
    ddns = f"{(data.get('dhcp') or {}).get('ddns_subdomain') or 'dhcp'}.{domain}"
    if name == ddns:
        return "it is the zone DHCP registers names in"
    if name == str(data.get("ad_domain") or "").lower():
        return "it is the Windows domain's zone"
    if name.endswith(".arpa") and not (name == "home.arpa" or name.endswith(".home.arpa")):
        return "reverse zones are generated from the A and AAAA records"
    if any(zone_name(data, k).lower() == name for k in data.get("dns") or {}):
        return "it is already a zone"
    registry = load_registry(FEDERATION_FILE)
    sites = [str(r.get("domain") or "").lower() for r in registry["sites"].values()]
    if registry["upstream"]:
        sites.append(str(registry["upstream"].get("domain") or "").lower())
    if name in sites:
        return "it is another site's zone (federation)"
    return ""


def add_zone(actor, name, hide_public=False, source="cli"):
    """Purpose: add a forward zone (manual 1.4.1.3, decision 2.1.4.5): a key of `dns:` with its `ns` record
             (zone_authority), served by BIND and forwarded by the DNS filter's resolver within seconds
             (publish_zone_list), no apply needed. Its records are then added as in any zone.
    Inputs:  actor — who asks (audit); name — the zone's name (a trailing dot and capitals are dropped);
             hide_public — True when the owner ticked that this name hides the real one on the internet (required for a
             name under a public top-level domain); source — "cli" or "web". Reads and writes vars.yaml under vars_lock.
    Returns: {"key", "name" (the same: a new zone's key is its name), "public" (bool), "resolver" (the resolver was
             reloaded too)}.
    Fails:   ValidationError with the reason, and nothing changed: not a DNS name of at least two labels (ZONE_RE);
             one BIND already answers for (the site's domain, the DHCP zone, the AD zone, a reverse zone, an existing
             zone, another site's); a public name without hide_public; or the publish failing (BIND or the resolver
             refusing): then the vars are put back, both configurations rendered again, and the message says why.
             OSError or yaml.YAMLError from the vars file, the registry or the audit log.
    Feeds:   agent route POST /v1/zones (fabric-agent, src/agent/post_dns.py); menu/edit_dns ("a")."""
    name = str(name or "").strip().rstrip(".").lower()
    if not ZONE_RE.match(name):
        raise ValidationError(f"{name or 'the name'!r} is not a DNS name of at least two labels "
                              "(letters, digits and '-', e.g. home.lan)")
    public = _is_public(name)
    with vars_lock():
        data = load_vars()
        why = _taken(data, name)
        if why:
            raise ValidationError(f"{name} is refused: {why}")
        if public and not hide_public:
            raise ValidationError(f"{name} is under a public top-level domain: every client of this site would get "
                                  "this zone's answers instead of the real ones. Tick 'Hide the public name' to add "
                                  "it anyway.")
        before = copy.deepcopy(data)
        data.setdefault("dns", {})
        if data["dns"] is None:
            data["dns"] = {}
        data["dns"][name] = {"zone_authority": True}
        save_vars(data)
        try:
            published = publish_zone_list(added=(name,))
        except Exception as e:
            save_vars(before)
            try:
                publish_zone_list(removed=(name,))
            except Exception as again:          # the vars are back; say both
                raise ValidationError(f"zone {name} not added: {e}. Putting the old zone list back failed too: "
                                      f"{again}; run an apply")
            raise ValidationError(f"zone {name} not added: {e}")
    write_audit(actor, "DNS_ZONE_ADD", f"zone={name}" + (" (hides the public name)" if public else ""), source)
    return {"key": name, "name": name, "public": public, "resolver": published["resolver"]}
