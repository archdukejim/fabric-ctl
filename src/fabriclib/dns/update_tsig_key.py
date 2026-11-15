from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns.edit_tsig_names import edit_tsig_names
from fabriclib.dns.normalize_tsig_keys import normalize_tsig_keys

FIELDS = ("records", "records_with_aliases", "any_name", "record_types", "domain", "algorithm", "out")


def update_tsig_key(actor, name, changes, source="cli", edit=None):
    """Purpose: Change what an existing TSIG key may update; its secret is untouched. Run apply afterwards.
    Inputs:  actor — str, who asks (audit).
             name — str key name.
             changes — dict with keys from FIELDS: records (list), records_with_aliases (list), any_name (True),
             record_types, domain, algorithm, out; a value of None, [] or "" removes that field.
             source — "cli" (default) or "web". Reads/writes vars.yaml under vars_lock.
             edit — optional dict for edit_tsig_names (names added or removed one at a time, a record with its
             aliases, a Custom key's scope and record types; decisions 2.1.4.13, 2.1.4.14), applied after `changes`.
    Returns: the key dict as stored after normalize_tsig_keys.
    Fails:   ValidationError "cannot change …" (unknown field), "no TSIG key named …", one from edit_tsig_names
             (its refusals, manual 1.4.1.9.3) or from normalize_tsig_keys; nothing is saved then;
             OSError or yaml.YAMLError from vars_lock / load_vars / save_vars / write_audit.
    Feeds:   run_tsig_command (`fabricctl tsig update`); agent route POST /v1/tsig/<name>/update (the console's Edit
             names, held for DNS' Apply: 2.1.8.18).
    """
    unknown = set(changes) - set(FIELDS)
    if unknown:
        raise ValidationError(f"cannot change {', '.join(sorted(unknown))}")
    with vars_lock():
        data = load_vars()
        keys = list(data.get("tsig_keys") or [])
        idx = next((i for i, k in enumerate(keys) if k.get("name") == name), None)
        if idx is None:
            raise ValidationError(f"no TSIG key named {name!r}")
        key = dict(keys[idx])
        for field, value in changes.items():
            if value in (None, [], ""):
                key.pop(field, None)
            else:
                key[field] = value
        keys[idx] = key
        said = []
        if edit is not None:
            keys[idx], said = edit_tsig_names({**data, "tsig_keys": keys}, name, edit)
        data["tsig_keys"], _ = normalize_tsig_keys(keys, data.get("domain", ""))
        save_vars(data)
    stored = data["tsig_keys"][idx]
    write_audit(actor, "TSIG_UPDATE", f"key={name} " + ("; ".join(said) + (f" {changes}" if changes else "")
                                                         if said else f"{changes}"), source)
    return stored
