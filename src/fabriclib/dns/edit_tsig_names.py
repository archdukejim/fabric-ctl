from fabriclib.common.errors import ValidationError
from fabriclib.dns.key_record_choices import key_record_choices
from fabriclib.dns.normalize_tsig_keys import LABEL_RE, RTYPE_RE
from fabriclib.dns.tsig_key_mode import tsig_key_mode

EDITS = ("add", "drop", "add_with_aliases", "drop_with_aliases", "scope", "record_types")
SCOPES = ("records", "primary", "any_name")


def _names(edit, field):
    """Purpose: One list of names from an edit, lower case, blanks dropped.
    Inputs:  edit — dict; field — one of EDITS' list fields.
    Returns: list of str.
    Fails:   ValidationError "… must be a list of names" for another value.
    Feeds:   edit_tsig_names."""
    value = edit.get(field) or []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValidationError(f"{field} must be a list of names")
    return [v.strip().rstrip(".").lower() for v in value if v.strip()]


def _scope(key):
    """Purpose: A key's scope as Edit names shows it.
    Inputs:  key — a tsig_keys entry.
    Returns: "any_name", "primary" or "records" (names, or none yet).
    Fails:   never.
    Feeds:   edit_tsig_names."""
    if key.get("records") or key.get("records_with_aliases"):
        return "records"
    return "any_name" if key.get("any_name") else "primary" if key.get("primary") else "records"


def edit_tsig_names(data, name, edit):
    """Purpose: A TSIG key's names changed, its secret, zone, algorithm and credentials file untouched (decisions
             2.1.4.13 and 2.1.4.14, manual 1.4.1.9.1 and 1.4.1.9.3): a name added or removed, a record with its
             aliases added or removed whole, and for a Custom key its scope and record types. Nothing is saved here:
             the hold's check (agent/pending_tsig), update_tsig_key and `fabricctl tsig update` call it.
    Inputs:  data — the vars (domain, dns, tsig_keys); name — the key's name; edit — dict of EDITS: add, drop (names
             of `records`), add_with_aliases, drop_with_aliases (A or AAAA records of `records_with_aliases`), scope
             (one of SCOPES; Custom only), record_types (list; Custom only).
    Returns: (key, said): the key's new entry (not yet normalized), and the change in words for the held list and
             the audit, e.g. ["add web", "remove nas", "add files and its aliases"].
    Fails:   ValidationError, saying why, for: a key no longer there; an unknown edit field or nothing to change; a
             name not valid as a record name; a name already granted, or one not granted that is removed; a record
             with aliases that is not an A or AAAA record of the key's zone; any change ACME (DNS-01) mode would not
             make to an ACME key (a name that is not a record of its zone, a scope or record types); names with a
             scope other than records; no record type; the key's last name removed ("remove the key instead").
    Feeds:   update_tsig_key (`edit`), agent/pending_tsig (the hold's check), run_tsig_command (`tsig update`)."""
    unknown = set(edit) - set(EDITS)
    if unknown:
        raise ValidationError(f"cannot change {', '.join(sorted(unknown))}")
    keys = data.get("tsig_keys") or []
    old = next((k for k in keys if k.get("name") == name), None)
    if old is None:
        raise ValidationError(f"no TSIG key named {name!r}")
    domain = old.get("domain") or data.get("domain") or ""
    try:
        choices = key_record_choices(data, domain)
    except ValidationError:
        choices = []
    mode = tsig_key_mode(old, choices)
    in_zone = {c["name"] for c in choices}
    addresses = {c["name"] for c in choices if c["address"]}
    add, drop = _names(edit, "add"), _names(edit, "drop")
    add_aliases, drop_aliases = _names(edit, "add_with_aliases"), _names(edit, "drop_with_aliases")
    scope, types = edit.get("scope"), edit.get("record_types")
    if not (add or drop or add_aliases or drop_aliases or scope or types is not None):
        raise ValidationError("nothing to change: add or remove a name")
    for n in add + drop + add_aliases + drop_aliases:
        if not LABEL_RE.match(n) or n.startswith("*") or n == "@":
            raise ValidationError(f"{n!r} is not valid as a record name")
    if mode == "acme" and (scope or types is not None):
        raise ValidationError(f"TSIG key {name} is an ACME (DNS-01) key: its scope and record types are ACME "
                              "mode's (TXT at its records' challenge names); make a Custom key for more")
    key = dict(old)
    records = [str(r).lower() for r in key.get("records") or []]
    with_aliases = [str(r).lower() for r in key.get("records_with_aliases") or []]
    said = []
    for n in drop:
        if n not in records:
            raise ValidationError(f"{n} is not granted to TSIG key {name}")
        records.remove(n)
        said.append(f"remove {n}")
    for n in drop_aliases:
        if n not in with_aliases:
            raise ValidationError(f"{n} and its aliases are not granted to TSIG key {name}")
        with_aliases.remove(n)
        said.append(f"remove {n} and its aliases")
    for n in add:
        if n in records:
            raise ValidationError(f"{n} is already granted to TSIG key {name}")
        if mode == "acme" and n not in in_zone:
            raise ValidationError(f"{n} is not a record of {domain}: an ACME (DNS-01) key is given only its zone's "
                                  "records (a Custom key may name others)")
        records.append(n)
        said.append(f"add {n}")
    for n in add_aliases:
        if n in with_aliases:
            raise ValidationError(f"{n} and its aliases are already granted to TSIG key {name}")
        if n not in addresses:
            raise ValidationError(f"{n} is not an A or AAAA record of {domain}: only those are picked with their "
                                  "aliases")
        with_aliases.append(n)
        said.append(f"add {n} and its aliases")
    new_scope = scope or _scope(old)
    if new_scope not in SCOPES:
        raise ValidationError(f"scope must be one of {', '.join(SCOPES)}")
    if new_scope != "records":
        if add or add_aliases:
            raise ValidationError(f"names are granted only with the scope records, not {new_scope}")
        records, with_aliases = [], []
    if types is not None:
        types = [str(t).strip().upper() for t in (types if isinstance(types, list) else [types]) if str(t).strip()]
        if not types:
            raise ValidationError("choose at least one record type")
        bad = [t for t in types if not RTYPE_RE.match(t)]
        if bad:
            raise ValidationError(f"invalid record types {bad!r}")
        key["record_types"] = types
        said.append(f"types {' '.join(types)}")
    if new_scope == "records" and not records and not with_aliases:
        raise ValidationError(f"that is TSIG key {name}'s last name: a key that may update nothing is removed "
                              "instead (remove the key instead)")
    for field, value in (("records", records), ("records_with_aliases", with_aliases)):
        if value:
            key[field] = value
        else:
            key.pop(field, None)
    if scope and scope != _scope(old):
        key.pop("any_name", None)
        key.pop("primary", None)
        if scope == "any_name":
            key["any_name"] = True
        elif scope == "primary":
            key["primary"] = True
        said.append(f"scope {scope}")
    elif new_scope == "records":
        key.pop("primary", None)
    return key, said
