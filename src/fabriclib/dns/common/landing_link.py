from fabriclib.common.errors import ValidationError


def landing_link(form):
    """Purpose: a record's landing-page link (manual 1.4.2.2, 1.4.2.4, 2.1.4.2), from a form's link fields.
    Inputs:  form — dict: link ("on"/"true"/"1"/"yes" to link the record from the landing page), link_label (≤ 60
             printable characters without <, >, " or a backslash; default: the record's name), link_port (1-65535,
             optional), link_path (starting with "/", without spaces, quotes, backslashes or <>; optional).
    Returns: {"label", "port", "path"} (None for each one not given), or None when the record is not linked.
    Fails:   ValidationError "invalid link label", "invalid link path", "link port must be a number" or "link port
             must be between 1 and 65535".
    Feeds:   validate_record (A, AAAA, CNAME at add), set_record_link (the landing page's own section)."""
    if str(form.get("link") or "").strip().lower() not in ("on", "true", "1", "yes"):
        return None
    label = str(form.get("link_label") or "").strip()
    if len(label) > 60 or any(c in label for c in '<>"\\') or not all(c.isprintable() for c in label):
        raise ValidationError("invalid link label")
    port = str(form.get("link_port") or "").strip()
    if port:
        if not port.isdigit():
            raise ValidationError("link port must be a number")
        if not 1 <= int(port) <= 65535:
            raise ValidationError("link port must be between 1 and 65535")
    path = str(form.get("link_path") or "").strip()
    if path and (not path.startswith("/") or any(c in path for c in ' "\'<>\\') or not path.isprintable()):
        raise ValidationError("invalid link path")
    return {"label": label or None, "port": int(port) if port else None, "path": path or None}
