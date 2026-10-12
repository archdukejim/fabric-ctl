from fabriclib.common.errors import ValidationError


def read_strings(data, field):
    """Purpose: read one list-of-text field from a request body.
    Inputs:  data — the request body; field — str, the key.
    Returns: list of str (at most 100); [] when absent or empty.
    Fails:   ValidationError("<field> must be a list of text") for anything else (-> 400).
    Feeds:   post_dns (TSIG hosts and types), post_pki (sans), post_domain (log-on groups)."""
    value = data.get(field) or []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value) or len(value) > 100:
        raise ValidationError(f"{field} must be a list of text")
    return value
