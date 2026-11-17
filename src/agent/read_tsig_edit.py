from agent.read_strings import read_strings
from agent.read_text import read_text
from fabriclib.common.errors import ValidationError

FIELDS = ("add", "drop", "add_with_aliases", "drop_with_aliases")


def read_tsig_edit(data):
    """Purpose: The body of a TSIG key's Edit names (POST /v1/tsig/<name>/update, decision 2.1.4.13) as
             edit_tsig_names takes it.
    Inputs:  data — the request body: add, drop, add_with_aliases, drop_with_aliases (lists of names), scope
             (text), record_types (list of text); every field optional.
    Returns: dict with only the fields given.
    Fails:   ValidationError for a field of the wrong kind (-> 400), or one this route does not know.
    Feeds:   post_dns (tsig/<name>/update), pending_tsig (the hold's check)."""
    unknown = set(data) - set(FIELDS) - {"scope", "record_types", "actor"}
    if unknown:
        raise ValidationError(f"cannot change {', '.join(sorted(unknown))}")
    edit = {f: read_strings(data, f) for f in FIELDS if data.get(f)}
    if data.get("scope"):
        edit["scope"] = read_text(data, "scope")
    if "record_types" in data:
        edit["record_types"] = read_strings(data, "record_types")
    return edit
