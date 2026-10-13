import ipaddress
import re

from fabriclib.common.errors import ValidationError
from fabriclib.dns.common.landing_link import landing_link

LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?"
NAME_RE = re.compile(rf"^(?:@|\*|(?:\*\.)?{LABEL}(?:\.{LABEL})*)$")
HOST_RE = re.compile(rf"^{LABEL}(?:\.{LABEL})*\.?$")
# the field a record's one "value" fills (2.1.2.22 item 3: the console asks type, name, value)
VALUE_FIELD = {"A": "ip", "AAAA": "ip", "CNAME": "target", "MX": "target", "TXT": "text", "SRV": "target"}


def _int(value, lo, hi, field):
    """Purpose: Parse a numeric record field and check its range.
    Inputs:  value — any; lo, hi — int bounds (inclusive); field — name used in the message.
    Returns: the int.
    Fails:   ValidationError "<field> must be a number" or "<field> must be between <lo> and <hi>".
    Feeds:   validate_record (MX, SRV).
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{field} must be a number")
    if not lo <= n <= hi:
        raise ValidationError(f"{field} must be between {lo} and {hi}")
    return n


def _host(value, field):
    """Purpose: Check a host name field (CNAME, MX or SRV target).
    Inputs:  value — str or None (stripped); field — name used in the message.
    Returns: the stripped host name (a trailing dot is allowed).
    Fails:   ValidationError "invalid <field>".
    Feeds:   validate_record.
    """
    value = (value or "").strip()
    if not HOST_RE.match(value):
        raise ValidationError(f"invalid {field}")
    return value


def validate_record(rtype, form):
    """Purpose: Build a vars.yaml record from user input, rejecting anything that could inject zone-file syntax (quotes,
             newlines, `$INCLUDE`, bad labels).
    Inputs:  rtype — "A", "AAAA", "CNAME", "MX", "TXT" or "SRV".
             form — dict of str: name (@, *, *.label or labels), plus ip (A/AAAA), target (CNAME, MX, SRV), priority
             (MX/SRV, 0-65535), weight (0-65535), port (1-65535), text (TXT: 1-255 characters without quotes,
             backslashes or newlines) — or value, which fills the type's field (VALUE_FIELD) when that is empty (the
             console's form, 2.1.2.22); for A, AAAA and CNAME, link (on: listed on the landing page) with
             link_label, link_port, link_path (common/landing_link).
    Returns: {"name", "ip"} | {"name", "canonical"} | {"name", "priority", "exchange"} | {"name", "text"} | {"name",
             "priority", "weight", "port", "target"}; an A, AAAA or CNAME record marked for the landing page also has
             "link": {"label", "port", "path"}.
    Fails:   ValidationError "invalid record name", "invalid IPv4 address", "invalid IPv6 address", "invalid CNAME
             target", "invalid mail exchange", "invalid SRV target", "TXT must be 1-255 chars …", the range messages of
             _int, "unsupported record type", landing_link's; AttributeError if a field is not a str.
    Feeds:   add_record; HOST_RE is reused by menu/edit_dns.
    """
    field = VALUE_FIELD.get(rtype)
    if field and not str(form.get(field) or "").strip() and form.get("value"):
        form = {**form, field: form["value"]}
    name = (form.get("name") or "").strip()
    if not NAME_RE.match(name):
        raise ValidationError("invalid record name")
    link = landing_link(form) if rtype in ("A", "AAAA", "CNAME") else None
    extra = {"link": link} if link else {}
    if rtype == "A":
        try:
            return {"name": name, "ip": str(ipaddress.IPv4Address((form.get("ip") or "").strip())), **extra}
        except ValueError:
            raise ValidationError("invalid IPv4 address")
    if rtype == "AAAA":
        try:
            return {"name": name, "ip": str(ipaddress.IPv6Address((form.get("ip") or "").strip())), **extra}
        except ValueError:
            raise ValidationError("invalid IPv6 address")
    if rtype == "CNAME":
        return {"name": name, "canonical": _host(form.get("target"), "CNAME target"), **extra}
    if rtype == "MX":
        return {"name": name, "priority": _int(form.get("priority"), 0, 65535, "priority"),
                "exchange": _host(form.get("target"), "mail exchange")}
    if rtype == "TXT":
        text = form.get("text") or ""
        if not text or len(text) > 255 or any(c in text for c in '"\\\r\n'):
            raise ValidationError("TXT must be 1-255 chars without quotes, backslashes or newlines")
        return {"name": name, "text": text}
    if rtype == "SRV":
        return {"name": name, "priority": _int(form.get("priority"), 0, 65535, "priority"),
                "weight": _int(form.get("weight"), 0, 65535, "weight"),
                "port": _int(form.get("port"), 1, 65535, "port"),
                "target": _host(form.get("target"), "SRV target")}
    raise ValidationError("unsupported record type")
