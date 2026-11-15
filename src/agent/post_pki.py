from agent.read_strings import read_strings
from agent.read_text import read_text
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.pki.certs_overview import certs_overview
from fabriclib.pki.convert_cert import convert_cert
from fabriclib.pki.describe_csr import describe_csr
from fabriclib.pki.find_cert import find_cert
from fabriclib.pki.inspect_pem import inspect_pem
from fabriclib.pki.issue_key_pair import issue_key_pair
from fabriclib.pki.revoke_cert import revoke_cert
from fabriclib.pki.set_lifetimes import set_lifetimes
from fabriclib.pki.sign_csr import sign_csr


def post_pki(op, actor, data):
    """Purpose: the manual PKI operations of POST /v1/pki/<op> (one fabriclib.pki file each).
    Inputs:  op — "describe-csr" | "sign" | "issue" | "inspect" | "convert" | "revoke" | "lookup" | "lifetimes";
             actor — str; data — body with csr, days, device, cn, sans, key_type, data, cert, key, target, pem,
             confirm, reason, serial, and the Lifetimes fields as each operation needs (text fields must be strings).
    Returns: the fabriclib result: describe_csr, sign_csr, issue_key_pair, inspect_pem, convert_cert, revoke_cert,
             find_cert (lookup: the certificate a revocation names, by serial or file, 2.1.5.13) or set_lifetimes
             (held for PKI's Apply, 2.1.5.14).
    Fails:   ValidationError("unknown operation") for another op, or from the readers and fabriclib (-> 400).
    Feeds:   agent/post_route.py (POST pki/<op>)."""
    if op == "describe-csr":
        return describe_csr(read_text(data, "csr"))
    if op == "sign":
        return sign_csr(load_vars(), actor, read_text(data, "csr"), data.get("days"), read_text(data, "device"))
    if op == "issue":
        return issue_key_pair(load_vars(), actor, read_text(data, "cn"), read_strings(data, "sans"),
                              read_text(data, "key_type"), data.get("days"), read_text(data, "device"))
    if op == "inspect":
        return inspect_pem(load_vars(), read_text(data, "data"))
    if op == "convert":
        return convert_cert(load_vars(), actor, read_text(data, "cert"), read_text(data, "key"))
    if op == "revoke":                          # the console's confirmation: the name typed again (1.5.1.9.3)
        return revoke_cert(load_vars(), actor, read_text(data, "target"), read_text(data, "reason") or "unspecified",
                           source="web", pem=read_text(data, "pem"),
                           confirm=read_text(data, "confirm") if "confirm" in data else None)
    if op == "lookup":
        v = load_vars()
        return find_cert(v, certs_overview(v), serial=read_text(data, "serial"), pem=read_text(data, "pem"))
    if op == "lifetimes":
        fields = data.get("fields")
        if not isinstance(fields, dict):
            raise ValidationError("fields: the lifetimes to set")
        return set_lifetimes(actor, {str(k): str(val) for k, val in fields.items()}, source="web")
    raise ValidationError("unknown operation")
