from fabriclib.common.errors import ValidationError
from fabriclib.samba.check_password_policy import POLICY_KEYS


def read_policy_changes(data):
    """Purpose: the password-policy values a request carries (the console's form, 2.1.2.22 item 2), typed as
             `fabricctl domain password-policy` types its options: the numbers whole numbers, complexity on or off.
             Only the keys given are changed; set_domain_password_policy then checks the whole policy again.
    Inputs:  data — dict: any of POLICY_KEYS (a whole number, as an int or its digits) and complexity (true/false, or
             "on"/"off" as a form sends it).
    Returns: dict {policy key: value} of the keys given.
    Fails:   ValidationError "<key> takes a whole number", "complexity takes on or off", "unknown policy setting
             <key>", "no policy value given", or, for a request naming a tier, that the tiers' policies are set only
             on the host (2.1.6.71).
    Feeds:   agent/post_domain (POST /v1/domain/password-policy)."""
    if "tier" in data:                  # the tiers' own policies are the host's alone (2.1.6.71)
        raise ValidationError("the tiers' password policies (fabric-admin's, the Directory Administrators') are set "
                              "only on the host: sudo fabricctl domain password-policy --tier (2.1.6.71)")
    known = set(POLICY_KEYS) | {"complexity"}
    unknown = sorted(k for k in data if k not in known and k != "actor")
    if unknown:
        raise ValidationError(f"unknown policy setting {', '.join(unknown)}")
    out = {}
    for key in POLICY_KEYS:
        if key in data:
            value = data[key]
            if isinstance(value, bool) or not (isinstance(value, int) or str(value).strip().isdigit()):
                raise ValidationError(f"{key.replace('_', ' ')} takes a whole number")
            out[key] = int(value)
    if "complexity" in data:
        value = data["complexity"]
        if value not in (True, False, "on", "off"):
            raise ValidationError("complexity takes on or off")
        out["complexity"] = value in (True, "on")
    if not out:
        raise ValidationError("no policy value given")
    return out
