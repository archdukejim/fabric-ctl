import base64
import binascii
import re

from fabriclib.common.errors import ValidationError

ALGORITHMS = ("hmac-sha256", "hmac-sha512", "hmac-sha384", "hmac-sha224", "hmac-sha1", "hmac-md5")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9*_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$")
RTYPE_RE = re.compile(r"^[A-Z0-9]{1,10}$")
ACL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")


def normalize_tsig_keys(keys, domain, secrets=None):
    """Purpose: Validate tsig_keys, fill defaults and take every secret out of the entries (secrets belong in fabric's
             secrets, never in vars).
    Inputs:  keys — list of dicts: name (required, NAME_RE, unique), algorithm (default hmac-sha256, one of ALGORITHMS),
             domain (default `domain`; "{{ domain }}" replaced), record_types (default [TXT]), records (hosts: only
             _acme-challenge.<host>.<domain>), records_with_aliases (A or AAAA records: the same for each and for every
             CNAME of the zone pointing at it at each render, 2.1.4.14), any_name (any name in the zone; never
             implied), primary, out (rfc2136.ini
             path), acls (BIND ACLs to put the key in), secret (base64 of an existing key, e.g. from another DNS server
             whose clients must keep working).
             domain — str, the fabric domain.
             secrets — optional {name: secret} merged in first (a secret embedded in an entry wins).
    Returns: (keys, embedded): the normalized list, and {name: secret} for every secret found or given.
    Fails:   ValidationError "tsig_keys entry needs a name", "invalid or duplicate TSIG key name", "…: algorithm must be
             one of …", "…: invalid domain …", "…: invalid record_types …", "…: invalid record names …",
             "…: invalid records_with_aliases …", "…: invalid ACL names …", "…: secret is not valid base64".
    Feeds:   deploy/merge_tsig_keys (apply), setup/collect_vars.py, add_tsig_key, update_tsig_key, replace_tsig_secret
             (to check a
             secret); ACL_RE, LABEL_RE and RTYPE_RE are reused by normalize_acl_policies.
    Notes:   records and records_with_aliases clear any_name; any_name is kept only when explicitly true. Whether a
             records_with_aliases entry is an A or AAAA record of the zone is checked where a person picks it
             (edit_tsig_names, create_zone_tsig_key): a record removed later grants nothing (alias_grants).
    """
    embedded = {}
    for name, secret in (secrets or {}).items():
        embedded[str(name)] = str(secret)
    out, seen = [], set()
    for raw in keys or []:
        if not isinstance(raw, dict) or not raw.get("name"):
            raise ValidationError(f"tsig_keys entry needs a name: {raw!r}")
        key = dict(raw)
        name = str(key["name"])
        if not NAME_RE.match(name) or name in seen:
            raise ValidationError(f"invalid or duplicate TSIG key name: {name!r}")
        seen.add(name)
        key["algorithm"] = str(key.get("algorithm") or "hmac-sha256").lower()
        if key["algorithm"] not in ALGORITHMS:
            raise ValidationError(f"TSIG key {name}: algorithm must be one of {', '.join(ALGORITHMS)}")
        dom = str(key.get("domain") or domain).replace("{{ domain }}", domain).replace("{{domain}}", domain)
        if not LABEL_RE.match(dom.rstrip(".")):
            raise ValidationError(f"TSIG key {name}: invalid domain {dom!r}")
        key["domain"] = dom.rstrip(".")
        key["record_types"] = [str(t).upper() for t in (key.get("record_types") or ["TXT"])]
        if not all(RTYPE_RE.match(t) for t in key["record_types"]):
            raise ValidationError(f"TSIG key {name}: invalid record_types {key['record_types']!r}")
        if key.get("records_with_aliases"):
            key["records_with_aliases"] = [str(r).rstrip(".") for r in key["records_with_aliases"]]
            bad = [r for r in key["records_with_aliases"] if not LABEL_RE.match(r) or r.startswith("*") or r == "@"]
            if bad:
                raise ValidationError(f"TSIG key {name}: invalid records_with_aliases {bad!r} (A or AAAA record names)")
        else:
            key.pop("records_with_aliases", None)
        if key.get("records"):
            key["records"] = [str(r).rstrip(".") for r in key["records"]]
            bad = [r for r in key["records"] if not LABEL_RE.match(r)]
            if bad:
                raise ValidationError(f"TSIG key {name}: invalid record names {bad!r}")
            key.pop("any_name", None)
        elif key.get("records_with_aliases"):
            key.pop("records", None)
            key.pop("any_name", None)
        else:
            key.pop("records", None)
            if key.get("any_name"):
                key["any_name"] = True          # zonesub: any name in the zone — explicit only
            else:
                key.pop("any_name", None)
        if key.get("acls"):
            key["acls"] = [str(a) for a in key["acls"]]
            bad = [a for a in key["acls"] if not ACL_RE.match(a) or a in ("any", "none", "localhost", "localnets",
                                                                             "tsig-updaters")]
            if bad:
                raise ValidationError(f"TSIG key {name}: invalid ACL names {bad!r}")
        if "secret" in key:
            embedded[name] = str(key.pop("secret"))
        out.append(key)
    for name, secret in embedded.items():
        try:
            if not base64.b64decode(secret, validate=True):
                raise ValueError
        except (binascii.Error, ValueError):
            raise ValidationError(f"TSIG key {name}: secret is not valid base64") from None
    return out, embedded
