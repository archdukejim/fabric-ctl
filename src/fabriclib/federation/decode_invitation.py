import base64
import binascii
import ipaddress
import json
import re

from fabriclib.common.errors import ValidationError
from fabriclib.federation.constants import BASE_DN_RE, DOMAIN_RE, INVITE_PREFIX, SITE_NAME_RE

_FP_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){31}$")


def decode_invitation(text):
    """Purpose: On a joining node: read and check an invitation made by create_invitation (no network).
    Inputs:  text — the invitation string ("fabric-join-1.<base64url JSON>"); surrounding whitespace ignored.
    Returns: {"id", "secret", "site", "upstream", "org_domain", "ldap_base_dn", "host", "address", "root_sha256",
             "expires", "via" ("" unless the invitation names a relay), "dc", "ad_domain", "ad_password_policy" (the
             domain the site's DC joins; "", "" and {} in an invitation made on a site), "version" (the upstream's
             fabric version; "" in an invitation from an upstream before 0.8.0)} with every field checked:
             site SITE_NAME_RE, host and org_domain DNS names, ldap_base_dn BASE_DN_RE, address an IP,
             root_sha256 an upper-case colon-separated SHA-256 fingerprint.
    Fails:   ValidationError "not a fabric invitation"; "the invitation is damaged (...)"; "the invitation has
             a bad <field>".
    Feeds:   setup collect_vars (--join: the site's defaults), setup step `join` (join_upstream).
    Notes:   expiry is checked by the upstream, whose clock decides."""
    text = str(text or "").strip()
    if not text.startswith(INVITE_PREFIX):
        raise ValidationError("not a fabric invitation (it starts with fabric-join-1.)")
    raw = text[len(INVITE_PREFIX):]
    try:
        body = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (binascii.Error, ValueError, UnicodeDecodeError) as e:
        raise ValidationError(f"the invitation is damaged ({e.__class__.__name__}): copy it again") from None
    if not isinstance(body, dict) or body.get("v") != 1:
        raise ValidationError("the invitation is damaged (unknown version): copy it again")
    checks = {"id": lambda x: re.fullmatch(r"[0-9a-f]{12}", x), "secret": lambda x: re.fullmatch(r"[A-Za-z0-9_-]{40,}",
                                                                                                 x),
              "site": SITE_NAME_RE.match, "upstream": SITE_NAME_RE.match, "org_domain": DOMAIN_RE.match,
              "host": DOMAIN_RE.match, "root_sha256": _FP_RE.match, "ldap_base_dn": BASE_DN_RE.match}
    for field, ok in checks.items():
        if not isinstance(body.get(field), str) or not ok(body[field]):
            raise ValidationError(f"the invitation has a bad {field}")
    try:
        ipaddress.ip_address(body.get("address", ""))
    except ValueError:
        raise ValidationError("the invitation has a bad address") from None
    if body.get("version") is not None and not isinstance(body["version"], str):
        raise ValidationError("the invitation has a bad version")
    if not isinstance(body.get("expires"), int):
        raise ValidationError("the invitation has a bad expires")
    if body.get("via") is not None and not (isinstance(body["via"], str) and SITE_NAME_RE.match(body["via"])):
        raise ValidationError("the invitation has a bad via")
    dc = body.get("dc")
    if dc is not None:                       # the domain the site's DC joins (manual 1.9.8.4)
        if dc not in ("writable", "rodc"):
            raise ValidationError("the invitation has a bad dc")
        if not (isinstance(body.get("ad_domain"), str) and DOMAIN_RE.match(body["ad_domain"])):
            raise ValidationError("the invitation has a bad ad_domain")
        if not isinstance(body.get("ad_password_policy"), dict):
            raise ValidationError("the invitation has a bad ad_password_policy")
    return {**{k: body[k] for k in ("id", "secret", "site", "upstream", "org_domain", "ldap_base_dn", "host",
                                    "address", "root_sha256", "expires")}, "via": body.get("via") or "",
            "dc": dc or "", "ad_domain": body.get("ad_domain") or "",
            "ad_password_policy": body.get("ad_password_policy") or {}, "version": body.get("version") or ""}
