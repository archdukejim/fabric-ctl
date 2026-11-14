import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.dns.alias_grants import alias_grants
from fabriclib.dns.key_record_choices import key_record_choices
from fabriclib.dns.tsig_key_mode import tsig_key_mode


def _names(records, dom):
    """Purpose: The _acme-challenge names a list of hosts may update, for display.
    Inputs:  records — list of host labels; dom — str zone name.
    Returns: str "_acme-challenge.<host>.<dom>, …".
    Fails:   never.
    Feeds:   list_tsig_keys.
    """
    return ", ".join(f"_acme-challenge.{r}.{dom}" for r in records)


def _choices(data, dom):
    """Purpose: A zone's record choices, or none when fabric no longer has the zone.
    Inputs:  data — the vars; dom — the zone's name.
    Returns: key_record_choices() or [].
    Fails:   never.
    Feeds:   list_tsig_keys."""
    try:
        return key_record_choices(data, dom)
    except ValidationError:
        return []


def list_tsig_keys():
    """Purpose: The TSIG keys in vars.yaml with their effective update rights (their own grants plus those inherited
             from ACL policies) and the ACLs that hold them; never secrets. Rights are deny-by-default.
    Inputs:  none. Reads vars.yaml (tsig_keys, bind_acls, bind_acl_policies, domain).
    Returns: [{"name", "algorithm", "types" (space-joined), "scope" (text; "no update rights" if none), "ini"
             (rfc2136.ini path), "acls" (sorted ACL names), "domain" (its zone), "mode" ("acme" or "custom",
             tsig_key_mode, 2.1.4.12), "records" (its names), "with_aliases" ([{"record", "names"}]: each record
             with its aliases and the names it covers today, 2.1.4.14), "primary", "any_name" (bool), "notes" (what
             fabric changed on it, e.g. a name dropped with its record)}].
    Fails:   OSError or yaml.YAMLError from load_vars; KeyError if a stored ACL policy lacks domain or record_types
             (normalized policies always have them).
    Feeds:   agent route GET /v1/tsig (fabric-agent, src/agent/, called by the web UI); run_tsig_command
             (list, update, after-apply output); tests/pki/run.py.
    Notes:   ACL membership counts only positive `key "<name>"` entries (a `!key` exclusion is not membership). The
             default "ini" is hard-coded as /opt/<name>/rfc2136.ini, while apply writes it under the deploy base.
    """
    data = load_vars()
    covered = alias_grants(data)
    acls = data.get("bind_acls") or {}
    policies = data.get("bind_acl_policies") or {}
    out = []
    for k in data.get("tsig_keys") or []:
        name, dom = k.get("name", ""), k.get("domain") or data.get("domain")
        member = sorted(a for a, entries in acls.items()
                        if any(re.fullmatch(rf'key\s+"?{re.escape(name)}"?', str(e).strip()) for e in entries or []))
        rights = []
        entries = covered.get(name, {})
        if k.get("records") or entries:
            if k.get("records"):
                rights.append(_names(k["records"], dom))
            for record, names in entries.items():
                rights.append(f"{record} and its aliases ({_names(names, dom) or 'nothing today: no such record'})")
        elif k.get("primary"):
            rights.append(f"_acme-challenge (zone {dom})")
        elif k.get("any_name"):
            rights.append(f"any name in {dom}")
        for acl in member:
            pol = policies.get(acl)
            if pol:
                what = _names(pol["records"], pol["domain"]) if pol.get("records") else f"any name in {pol['domain']}"
                rights.append(f"{what} ({' '.join(pol['record_types'])}, via ACL {acl})")
        out.append({"name": name, "algorithm": k.get("algorithm", "hmac-sha256"),
                    "types": " ".join(k.get("record_types") or ["TXT"]),
                    "scope": "; ".join(rights) or "no update rights",
                    "ini": k.get("out") or f"/opt/{name}/rfc2136.ini", "acls": member,
                    "domain": dom, "mode": tsig_key_mode(k, _choices(data, dom)),
                    "records": list(k.get("records") or []),
                    "with_aliases": [{"record": r, "names": n} for r, n in entries.items()],
                    "primary": bool(k.get("primary")), "any_name": bool(k.get("any_name")),
                    "notes": list(k.get("notes") or [])})
    return out
