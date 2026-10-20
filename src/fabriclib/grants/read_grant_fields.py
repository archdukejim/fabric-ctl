from fabriclib.common.errors import ValidationError

LISTS = ("who", "where", "people", "machines", "signin", "sudo")


def read_grant_fields(data):
    """Purpose: a grant's fields from a request body or the CLI's options (manual 1.6.13.7), their types checked; what
             each may hold is the DC's check (check_grant), so the console and the CLI are refused alike.
    Inputs:  data — dict: any of kind ("allow" | "restrict"), description (str), who, where, people, machines, signin,
             sudo (lists of str), local_admin (bool); other keys ignored.
    Returns: dict with the fields given.
    Fails:   ValidationError "<field> must be a list of names", "kind: allow or restrict", "description: text",
             "local_admin: true or false", "a grant's fields: an object".
    Feeds:   add_grant, set_grant, run_grant_command, agent/post_grants."""
    if not isinstance(data, dict):
        raise ValidationError("a grant's fields: an object")
    out = {}
    for key in LISTS:
        if key in data:
            value = data[key]
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ValidationError(f"{key} must be a list of names")
            out[key] = [x.strip() for x in value if x.strip()]
    if "kind" in data:
        if data["kind"] not in ("allow", "restrict"):
            raise ValidationError("kind: allow or restrict")
        out["kind"] = data["kind"]
    if "description" in data:
        if not isinstance(data["description"], str):
            raise ValidationError("description: text")
        out["description"] = data["description"]
    if "local_admin" in data:
        if not isinstance(data["local_admin"], bool):
            raise ValidationError("local_admin: true or false")
        out["local_admin"] = data["local_admin"]
    return out
